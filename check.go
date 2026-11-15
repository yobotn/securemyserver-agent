package main

// `securemyserver check` (send one report now and print a short summary) and `securemyserver status` (the local
// state, without contacting the platform). Plus what both read: the result of the last report, and the one-time
// enrollment (D-054).
//
// Enrollment: a token that starts with sms_enroll_ works for one report only. That first report must be signed
// (D-043): it registers this server's report key and the platform marks the token used. The agent then records the
// enrollment in /var/lib/securemyserver/enrollment.json and from then on names the server with X-SMS-Server and
// proves who it is with the request signature alone; the dead token in agent.conf is never sent again. Older
// sms_ tokens keep working as bearer tokens.

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	lastReportFile = stateDir + "/last_report.json"
	enrollmentFile = stateDir + "/enrollment.json"
	enrollPrefix   = "sms_enroll_"
	serviceName    = "securemyserver"
)

// replySummary is display-only: numbers the platform adds to its reply for `check`. The agent never acts on them.
type replySummary struct {
	Open            int `json:"open"`
	Critical        int `json:"critical"`
	Verified        int `json:"verified"`
	SwitchesWaiting int `json:"switches_waiting"`
}

// lastReport is what the last report attempt did (the agent loop and `check` both write it).
type lastReport struct {
	At        string        `json:"at"`
	OK        bool          `json:"ok"`
	Error     string        `json:"error,omitempty"`
	Summary   *replySummary `json:"summary,omitempty"`
	Envelopes int           `json:"envelopes"`
}

func saveLastReport(lr lastReport) {
	if err := writeJSON(rp(lastReportFile), lr); err != nil {
		log.Printf("last report state: %v", err)
	}
}

func loadLastReport() *lastReport {
	var lr lastReport
	if readJSON(rp(lastReportFile), &lr) != nil || lr.At == "" {
		return nil
	}
	return &lr
}

// enrollment records that this agent.conf's enrollment token was used (by its first report).
type enrollment struct {
	TokenSHA256 string `json:"token_sha256"`
	ServerID    string `json:"server_id"`
	At          string `json:"at"`
}

func tokenSum(token string) string {
	s := sha256.Sum256([]byte(token))
	return hex.EncodeToString(s[:])
}

func isEnrollToken(token string) bool { return strings.HasPrefix(token, enrollPrefix) }

// enrolledServer is the server id to send as X-SMS-Server, once this config's enrollment token was used. "" while
// the token still has to be sent (or for an old sms_ token, which stays a bearer token).
func enrolledServer(cfg Config) string {
	if !isEnrollToken(cfg.Token) {
		return ""
	}
	var e enrollment
	if readJSON(rp(enrollmentFile), &e) != nil || e.TokenSHA256 != tokenSum(cfg.Token) || !uuidRE.MatchString(e.ServerID) {
		return ""
	}
	return e.ServerID
}

func saveEnrollment(cfg Config, serverID string, now time.Time) {
	if !uuidRE.MatchString(serverID) {
		return
	}
	if err := writeJSON(rp(enrollmentFile), enrollment{TokenSHA256: tokenSum(cfg.Token), ServerID: serverID, At: stamp(now)}); err != nil {
		log.Printf("enrollment state: %v", err)
		return
	}
	log.Print("enrolled: the enrollment token is used up; from now on this server's signing key alone identifies it")
}

// setAuth names the server on a request: the bearer token, or after enrollment the server id (the request
// signature, added by the caller, is then the only proof).
func setAuth(req *http.Request, cfg Config, viaKey string) {
	if viaKey != "" {
		req.Header.Set("X-SMS-Server", viaKey)
		return
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
}

/* ---------- check ---------- */

func cmdCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("securemyserver check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configFlag := fs.String("config", "", "config file (default "+defaultConfigPath+")")
	verbose := fs.Bool("v", false, "also print the agent's log lines")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := requireRoot(); err != nil {
		fmt.Fprintln(stderr, "securemyserver check:", err)
		return 1
	}
	configPath, note := resolveConfigPath(*configFlag, fileExists)
	if note != "" {
		fmt.Fprintln(stderr, note)
	}
	cfg, warnings, err := loadConfig(configPath)
	for _, w := range warnings {
		fmt.Fprintln(stderr, "warning:", w)
	}
	if err != nil {
		fmt.Fprintf(stderr, "securemyserver check: config %s: %v\n", configPath, err)
		return 1
	}
	if !*verbose {
		prev := log.Writer()
		log.SetOutput(io.Discard)
		defer log.SetOutput(prev)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	sendErr := sendOnce(client, cfg, nowFn().Add(-15*time.Minute))
	fmt.Fprint(stdout, checkSummary(cfg, loadLastReport(), sendErr))
	if sendErr != nil {
		return 1
	}
	return 0
}

// checkSummary is what `check` prints: a few lines a person can read at a glance.
func checkSummary(cfg Config, lr *lastReport, sendErr error) string {
	var b strings.Builder
	if sendErr != nil {
		fmt.Fprintf(&b, "Report NOT sent: %s\n", sendErr)
		if hint := sendHint(cfg, sendErr.Error()); hint != "" {
			fmt.Fprintln(&b, hint)
		}
		return b.String()
	}
	fmt.Fprintf(&b, "Report sent to %s.\n", hostOf(cfg.Endpoint))
	if lr != nil && lr.Summary != nil {
		s := lr.Summary
		fmt.Fprintf(&b, "Checklist: %d open (%d critical), %d verified.\n", s.Open, s.Critical, s.Verified)
	} else {
		fmt.Fprintln(&b, "Checklist: see the dashboard (this platform sent no summary).")
	}
	fmt.Fprintln(&b, "Switches:", switchesLine(lr))
	fmt.Fprintln(&b, blocklistStatus())
	if cfg.ServerID != "" && cfg.Origin != "" {
		fmt.Fprintf(&b, "Dashboard: %s/app/servers/%s\n", cfg.Origin, cfg.ServerID)
	}
	return b.String()
}

func sendHint(cfg Config, msg string) string {
	switch {
	case strings.Contains(msg, "already used"), strings.Contains(msg, "expired"):
		return "Get a new enrollment token on the server's page in the dashboard, put it in " + defaultConfigPath + " as token = ..., and run sudo securemyserver check again."
	case strings.Contains(msg, "clock"):
		return "Fix the server's clock (timedatectl) and run sudo securemyserver check again."
	case strings.Contains(msg, "never registered"):
		return "This agent has a new report key. Use Forget report key on the server's page, then get a new enrollment token."
	case isEnrollToken(cfg.Token) && strings.Contains(msg, "HTTP 401"):
		return "The platform refused this server. If the token is older than 15 minutes, get a new one in the dashboard."
	}
	return ""
}

func switchesLine(lr *lastReport) string {
	var parts []string
	if lr != nil && lr.Envelopes > 0 {
		parts = append(parts, fmt.Sprintf("%d signed request(s) ran now", lr.Envelopes))
	}
	if lr != nil && lr.Summary != nil && lr.Summary.SwitchesWaiting > 0 {
		parts = append(parts, fmt.Sprintf("%d signed in the dashboard, waiting for this server", lr.Summary.SwitchesWaiting))
	}
	if n, until := waitingSwitches(); n > 0 {
		parts = append(parts, fmt.Sprintf("%d applied, waiting for a new SSH login (rolls back at %s)", n, until))
	}
	if len(parts) == 0 {
		return "none pending."
	}
	return strings.Join(parts, "; ") + "."
}

// waitingSwitches counts applied switches that still wait for a new login or a confirm.
func waitingSwitches() (int, string) {
	n, until := 0, ""
	_ = withLock(func() error {
		st := loadEngineState()
		for _, o := range st.Ops {
			if o.State == opApplied {
				n++
				until = o.Deadline
			}
		}
		return nil
	})
	return n, until
}

func hostOf(endpoint string) string {
	if u, err := url.Parse(endpoint); err == nil && u.Host != "" {
		return u.Host
	}
	return endpoint
}

/* ---------- status ---------- */

// serviceState asks systemd whether the agent service runs. A variable for tests.
var serviceState = func() string {
	if !isSystemd() {
		return "unknown (no systemd)"
	}
	out, _, _ := run(10*time.Second, "systemctl", "is-active", serviceName)
	s := strings.TrimSpace(string(out))
	if s == "" {
		return "unknown"
	}
	return s
}

func cmdStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("securemyserver status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configFlag := fs.String("config", "", "config file (default "+defaultConfigPath+")")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := requireRoot(); err != nil {
		fmt.Fprintln(stderr, "securemyserver status:", err)
		return 1
	}
	fmt.Fprintf(stdout, "Service: %s.service %s\n", serviceName, serviceState())
	configPath, _ := resolveConfigPath(*configFlag, fileExists)
	cfg, _, cfgErr := loadConfig(configPath)
	if cfgErr != nil {
		fmt.Fprintf(stdout, "Config: %s: %v\n", configPath, cfgErr)
	} else {
		fmt.Fprintf(stdout, "Config: %s (reports to %s)\n", configPath, hostOf(cfg.Endpoint))
		fmt.Fprintln(stdout, "Enrollment:", enrollmentLine(cfg))
	}
	fmt.Fprintln(stdout, "Last report:", lastReportLine(loadLastReport()))

	allowed, err := allowedSwitches()
	if err != nil {
		fmt.Fprintf(stdout, "Allowed switches: none (%v)\n", err)
	} else {
		fmt.Fprintln(stdout, "Allowed switches:", orDefault(strings.Join(allowed, ", "), "none"))
	}
	if all, err := allowedAll(); err == nil {
		var extra []string
		for _, n := range all {
			if !knownSwitch(n) {
				extra = append(extra, n)
			}
		}
		if len(extra) > 0 {
			fmt.Fprintln(stdout, "Also allowed:", strings.Join(extra, ", "))
		}
	}
	if p := pendingCheckpoint(); p != nil {
		fmt.Fprintf(stdout, "Waiting checkpoint: %s (%s), restores at %s unless confirmed\n", p.ID, strings.Join(p.Targets, ","), p.Deadline.Format("15:04:05 UTC"))
	} else {
		fmt.Fprintln(stdout, "Waiting checkpoint: none")
	}
	fmt.Fprintln(stdout, blocklistStatus())
	fmt.Fprintln(stdout, "Report key:", reportKeyInfo())

	all := listCheckpoints()
	if len(all) > 10 {
		all = all[len(all)-10:]
	}
	if len(all) > 0 {
		fmt.Fprintln(stdout, "Checkpoints:")
	}
	for _, m := range all {
		line := fmt.Sprintf("  %s  %-14s %-10s %s", m.ID, m.Status, strings.Join(m.Targets, ","), m.Reason)
		if m.Kind == cpKindSession {
			line += fmt.Sprintf("  (AI session, last sudo %s)", m.LastActivity.Format("2006-01-02 15:04 UTC"))
		} else if m.Status == cpPending {
			line += fmt.Sprintf("  (restores at %s)", m.Deadline.Format("15:04:05 UTC"))
		} else if m.StatusNote != "" {
			line += "  (" + m.StatusNote + ")"
		}
		fmt.Fprintln(stdout, line)
	}
	return 0
}

func enrollmentLine(cfg Config) string {
	if !isEnrollToken(cfg.Token) {
		return "bearer token (an older sms_ token)"
	}
	var e enrollment
	if readJSON(rp(enrollmentFile), &e) == nil && e.TokenSHA256 == tokenSum(cfg.Token) {
		return "done " + e.At + "; the token is used up and the report key identifies this server"
	}
	return "not yet: the first report uses the one-time token (it expires 15 minutes after it was made)"
}

func lastReportLine(lr *lastReport) string {
	if lr == nil {
		return "none yet. Run: sudo securemyserver check"
	}
	if !lr.OK {
		return lr.At + " FAILED: " + lr.Error
	}
	line := lr.At + " ok"
	if s := lr.Summary; s != nil {
		line += fmt.Sprintf(" (%d open, %d critical, %d verified)", s.Open, s.Critical, s.Verified)
	}
	return line
}

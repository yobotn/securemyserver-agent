// securemyserver is the SecureMyServer binary. `securemyserver agent` reads system state and POSTs a report.
// It never listens on a port and never runs commands it receives: data flows up (D-005). The one write path is
// the signed safe switches (D-014): fixed Go code, run only for a policy the owner signed with a pinned passkey
// AND allowed on this server, with a checkpoint that restores itself unless a new login confirms it.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const agentVersion = "0.9.0"

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	os.Exit(dispatch(os.Args[1:], os.Stdout, os.Stderr))
}

const usage = `usage: securemyserver <command> [flags]

commands:
  check       send one report now and print a short summary (sudo securemyserver check)
  status      this server's local state: service, last report, switches, checkpoint, blocklist, report key
  agent       the service: read the server and send a report every 5 minutes (agent --help for flags)
  checkpoint  save ssh|ufw|nft|apt|... before a change; restores itself after --minutes (default 5) unless confirmed
  confirm     keep the change (run it from a NEW SSH session)
  undo        restore the last checkpoint now
  allow       allow signed switches on this server: allow --all-safe (every safe switch), or e.g. allow ssh.password_auth_off blocklist
  disallow    stop allowing switches
  allowed     list the allowed switches (and the blocklist)
  rotate-key  make a new report signing key, signed by the old one
  version     print the version
`

// dispatch runs a subcommand and returns the exit code.
func dispatch(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "agent":
		agent(args[1:])
		return 0
	case "version", "--version", "-version":
		fmt.Fprintln(stdout, "securemyserver", agentVersion)
		return 0
	case "checkpoint":
		return cmdCheckpoint(args[1:], stdout, stderr)
	case "confirm":
		return cmdConfirm(args[1:], stdout, stderr)
	case "undo":
		return cmdUndo(args[1:], stdout, stderr)
	case "check":
		return cmdCheck(args[1:], stdout, stderr)
	case "status":
		return cmdStatus(args[1:], stdout, stderr)
	case "allow", "disallow", "allowed":
		return cmdAllow(args[0], args[1:], stdout, stderr)
	case "rotate-key":
		return cmdRotateKey(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "securemyserver: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

func agent(args []string) {
	fs := flag.NewFlagSet("securemyserver agent", flag.ExitOnError)
	var (
		configFlag = fs.String("config", "", "config file (default "+defaultConfigPath+")")
		once       = fs.Bool("once", false, "collect and send one report, then exit")
		dryRun     = fs.Bool("dry-run", false, "with --once: print the report JSON to stdout and send nothing")
		interval   = fs.Duration("interval", 5*time.Minute, "time between reports")
		window     = fs.Duration("since", 15*time.Minute, "auth log window for the first report")
		version    = fs.Bool("version", false, "print version and exit")
	)
	_ = fs.Parse(args)
	log.SetPrefix("securemyserver agent: ")

	if *version {
		fmt.Println("securemyserver", agentVersion)
		return
	}
	if *dryRun && !*once {
		log.Fatal("--dry-run needs --once")
	}

	since := time.Now().Add(-*window)
	if *dryRun {
		sw := &Switches{Off: "no readable config", Allowed: []string{}, OwnerKeys: []string{}, Seen: []string{}, Ops: []SwitchOp{}, Refused: []Refusal{}}
		if p, _ := resolveConfigPath(*configFlag, fileExists); p != "" {
			if cfg, _, err := loadConfig(p); err == nil {
				sw = switchesReport(cfg)
			}
		}
		rep := collect(since, sw)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			log.Fatal(err)
		}
		return
	}

	configPath, note := resolveConfigPath(*configFlag, fileExists)
	if note != "" {
		log.Print(note)
	}
	cfg, warnings, err := loadConfig(configPath)
	for _, w := range warnings {
		log.Print("warning: ", w)
	}
	if err != nil {
		log.Fatalf("config %s: %v", configPath, err)
	}
	client := &http.Client{Timeout: 30 * time.Second}

	if *once {
		if err := sendOnce(client, cfg, since); err != nil {
			log.Fatal(err)
		}
		return
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	// Applied switches and checkpoints are followed every 30 seconds: a new key login confirms, a passed
	// deadline restores. Such a change is reported at once instead of with the next report.
	watch := time.NewTicker(30 * time.Second)
	defer watch.Stop()
	for {
		started := time.Now()
		if err := sendOnce(client, cfg, since); err != nil {
			log.Print(err)
		} else {
			// Only advance the auth window after a report was accepted, so failed sends are retried.
			since = started.Add(-30 * time.Second) // small overlap; the platform dedupes by event id
			gateFirstRead = false
		}
		waitNext(ticker.C, watch.C, stop)
		select {
		case <-stop:
			return
		default:
		}
	}
}

// waitNext returns at the next report time, or as soon as the 30-second watch confirmed or rolled back a
// switch (so the dashboard hears it now), or on a signal.
func waitNext(report, watch <-chan time.Time, stop chan os.Signal) {
	for {
		select {
		case <-report:
			return
		case <-watch:
			if tickSwitches() {
				return
			}
		case s := <-stop:
			stop <- s // let the caller see it
			return
		}
	}
}

func collect(since time.Time, sw *Switches) Report {
	rep := Report{
		Version:      1,
		AgentVersion: agentVersion,
		CollectedAt:  time.Now().UTC().Format(time.RFC3339),
		Ports:        []Port{},
		Users:        []User{},
		AuthEvents:   []AuthEvent{},
		Errors:       []string{},
	}
	note := func(what string, err error) {
		if err != nil && len(rep.Errors) < 20 {
			rep.Errors = append(rep.Errors, what+": "+trim(err.Error(), 200))
		}
	}
	rep.Hostname, _ = os.Hostname()
	rep.MachineIDHash = collectMachineIDHash()
	var err error
	rep.OS, err = collectOS()
	note("os", err)
	rep.Updates, err = collectUpdates()
	note("updates", err)
	rep.SSH, err = collectSSH()
	note("sshd -T", err)
	ports, err := collectPorts()
	note("ports", err)
	if ports != nil {
		rep.Ports = ports
	}
	var nft nftSummary
	rep.Firewall, nft = collectFirewall()
	rep.Docker = collectDocker(nft)
	users, err := collectUsers()
	note("users", err)
	rep.Users = users
	auth, err := collectAuth(since)
	note("auth log", err)
	rep.AuthEvents, rep.AuthSource, rep.AuthVerified, rep.AuthRejected = auth.Events, auth.Source, auth.Verified, auth.Rejected
	updateKeyUsage(auth.Events, time.Now())
	if pw, err := readCapped("/etc/passwd", 4<<20); err == nil {
		rep.SSHKeys = collectKeys(keyOwnersFrom(pw), rep.SSH.Effective["authorizedkeysfile"], keyUsage, keyUsageSource, keyUsageVerified)
	}
	rep.Gate = collectGate(since)
	rep.Switches = sw
	rep.Blocklist = blocklistReport()
	rep.AISessions = sessionsReport()
	return rep
}

// sendOnce follows applied switches, sends a report, and runs any signed envelopes in the reply. When one ran,
// a second report goes out at once so the dashboard shows the result without waiting 5 minutes. Then, when root
// allowed it, the signed blocklist is pulled and applied; its result goes into the next report.
func sendOnce(client *http.Client, cfg Config, since time.Time) error {
	tickSwitches()
	key := signingKey()
	rep := collect(since, switchesReport(cfg))
	reply, err := post(client, cfg, key, rep)
	if err != nil {
		saveLastReport(lastReport{At: stamp(nowFn()), OK: false, Error: trim(err.Error(), 300)})
		return err
	}
	markSessionsSent(rep.AISessions)
	ran := len(reply.Envelopes)
	if processEnvelopes(cfg, reply.Envelopes) {
		rep = collect(since, switchesReport(cfg))
		more, err := post(client, cfg, key, rep)
		if err != nil {
			log.Print(err)
		} else {
			markSessionsSent(rep.AISessions)
			reply.Summary = orSummary(more.Summary, reply.Summary)
			ran += len(more.Envelopes)
			if processEnvelopes(cfg, more.Envelopes) {
				log.Print("more signed requests ran; the next report carries their result")
			}
		}
	}
	saveLastReport(lastReport{At: stamp(nowFn()), OK: true, Summary: reply.Summary, Envelopes: ran})
	refreshBlocklist(cfg, key)
	return nil
}

func orSummary(a, b *replySummary) *replySummary {
	if a != nil {
		return a
	}
	return b
}

// signingKey is this server's report key, made on first use (D-043). Without one (a read-only state directory),
// reports go unsigned, which the platform only accepts until a key was registered.
func signingKey() *reportKey {
	var k *reportKey
	err := withLock(func() error {
		var err error
		k, err = loadReportKey(true)
		return err
	})
	if err != nil {
		log.Printf("report key: %v; sending unsigned", err)
		return nil
	}
	return k
}

// replyBody is all the agent reads from the platform's reply. `envelopes` are signed requests, each verified here
// against the pinned keys before anything happens. `summary` is numbers for `check` to print, never acted on.
// `enrolled` and `server_id` say the one-time enrollment token was used (D-054). Everything else is ignored.
type replyBody struct {
	Envelopes []Envelope    `json:"envelopes"`
	Summary   *replySummary `json:"summary"`
	Enrolled  bool          `json:"enrolled"`
	ServerID  string        `json:"server_id"`
}

func post(client *http.Client, cfg Config, key *reportKey, rep Report) (replyBody, error) {
	body, err := json.Marshal(rep)
	if err != nil {
		return replyBody{}, err
	}
	viaKey := ""
	if key != nil {
		viaKey = enrolledServer(cfg)
	}
	status, msg, err := postOnce(client, cfg, key, body, viaKey)
	// The enrollment state was lost (a wiped state directory) but the key was kept: the token is dead, so name the
	// server by the id in agent.conf and let the signature prove it.
	if err == nil && status == http.StatusUnauthorized && viaKey == "" && key != nil && isEnrollToken(cfg.Token) && cfg.ServerID != "" &&
		strings.Contains(string(msg), "already used") {
		status, msg, err = postOnce(client, cfg, key, body, cfg.ServerID)
		if err == nil && status/100 == 2 {
			saveEnrollment(cfg, cfg.ServerID, nowFn())
		}
	}
	if err != nil {
		return replyBody{}, fmt.Errorf("send report: %w", err)
	}
	if status/100 != 2 {
		return replyBody{}, fmt.Errorf("send report: HTTP %d: %s", status, trim(strings.TrimSpace(string(msg)), 300))
	}
	var reply replyBody
	_ = json.Unmarshal(msg, &reply)
	if viaKey == "" && isEnrollToken(cfg.Token) && reply.Enrolled {
		id := reply.ServerID
		if id == "" {
			id = cfg.ServerID
		}
		saveEnrollment(cfg, id, nowFn())
	}
	aiCmds := 0
	if rep.Gate != nil {
		aiCmds = len(rep.Gate.Commands)
	}
	log.Printf("report sent: %d bytes, %d auth events, %d AI commands, HTTP %d, %d signed requests", len(body), len(rep.AuthEvents), aiCmds, status, len(reply.Envelopes))
	return reply, nil
}

func postOnce(client *http.Client, cfg Config, key *reportKey, body []byte, viaKey string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	setAuth(req, cfg, viaKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "securemyserver/"+agentVersion)
	if key != nil {
		key.signRequest(req, body, nowFn())
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return resp.StatusCode, msg, nil
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

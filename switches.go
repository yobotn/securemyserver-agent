package main

// The six safe switches (D-014, D-030). Each name maps to fixed code here: pre-checks, the change, a check and a
// reload, then a verify of the live value. Nothing from the policy reaches a command; the only inputs are
// what this server reads about itself. Every switch only makes the server safer; there is no "off".

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	sshDropIn       = "/etc/ssh/sshd_config.d/00-securemyserver.conf"
	aptAutoUpgrades = "/etc/apt/apt.conf.d/52securemyserver-auto-upgrades"
	switchWindow    = 10 * time.Minute
	switchRate      = 10 * time.Minute
)

type directive struct{ Name, Value string }

// switchPlan is what a switch will do on this server, decided by its pre-checks.
type switchPlan struct {
	targets    []string // checkpoint targets
	needsLogin bool     // confirmed by a new key login (or the owner), else rolled back at the deadline
	summary    string   // "PasswordAuthentication no"
	apply      func(l *opLog) error
	verify     func(l *opLog) error
}

type opLog struct{ steps []SwitchStep }

func (l *opLog) add(name string, err error, detail string) error {
	s := SwitchStep{Name: name, OK: err == nil, Detail: trim(detail, 300)}
	if err != nil {
		s.Detail = trim(err.Error(), 300)
	}
	if len(l.steps) < 30 {
		l.steps = append(l.steps, s)
	}
	return err
}

// Reads and commands the switches use. Variables so tests can stand in for the system.
var (
	sshdEffective = func() (map[string]string, error) {
		out, errb, err := run(20*time.Second, "sshd", "-T")
		if err != nil {
			return nil, fmt.Errorf("sshd -T: %s", trim(strings.TrimSpace(string(errb)), 200))
		}
		return parseSSHDT(out), nil
	}
	recentKeyLogins = func(since, now time.Time) int {
		m := map[string]keyUse{}
		scanKeyUsage(m, since, now)
		return len(m)
	}
	listUsers   = collectUsers
	listPorts   = collectPorts
	sshBannerOK = checkSSHBanner
)

// planSwitch runs the pre-checks. An error is the refusal reason, shown to the owner as is.
func planSwitch(name string, now time.Time) (*switchPlan, error) {
	switch name {
	case "ssh.password_auth_off":
		return planPasswordOff(now)
	case "ssh.root_login_off":
		return planRootOff()
	case "ssh.max_auth_tries_3":
		return planMaxAuthTries()
	case "updates.security_now":
		return planSecurityNow()
	case "updates.unattended_on":
		return planUnattendedOn()
	case "firewall.on_keep_ssh":
		return planFirewallOn()
	}
	return nil, fmt.Errorf("unknown switch %q", name)
}

/* ---------- SSH ---------- */

var includeRE = regexp.MustCompile(`(?im)^[ \t]*Include[ \t]+/etc/ssh/sshd_config\.d/\*\.conf\b`)

func sshPrechecks() (map[string]string, error) {
	eff, err := sshdEffective()
	if err != nil {
		return nil, err
	}
	b, err := readCapped(rp("/etc/ssh/sshd_config"), 1<<20)
	if err != nil {
		return nil, fmt.Errorf("read /etc/ssh/sshd_config: %v", err)
	}
	if !includeRE.Match(b) {
		return nil, errors.New("sshd_config does not read /etc/ssh/sshd_config.d/*.conf, so a switch can't set it safely. Use Fix with AI")
	}
	return eff, nil
}

func planPasswordOff(now time.Time) (*switchPlan, error) {
	eff, err := sshPrechecks()
	if err != nil {
		return nil, err
	}
	kbdName := "KbdInteractiveAuthentication"
	kbd := eff["kbdinteractiveauthentication"]
	if _, ok := eff["kbdinteractiveauthentication"]; !ok {
		kbdName, kbd = "ChallengeResponseAuthentication", eff["challengeresponseauthentication"]
	}
	ds := []directive{}
	if eff["passwordauthentication"] != "no" {
		ds = append(ds, directive{"PasswordAuthentication", "no"})
	}
	// With UsePAM yes, keyboard-interactive still asks for the password: both go off together.
	if kbd == "yes" && eff["usepam"] == "yes" {
		ds = append(ds, directive{kbdName, "no"})
	}
	if len(ds) == 0 {
		return nil, errors.New("password login is already off")
	}
	if eff["pubkeyauthentication"] != "yes" {
		return nil, errors.New("PubkeyAuthentication is not yes: turning passwords off would lock everyone out")
	}
	if recentKeyLogins(now.Add(-7*24*time.Hour), now) == 0 {
		return nil, errors.New("no one logged in with an SSH key in the last 7 days. Log in with your key once, then try again")
	}
	return sshPlan(ds, true), nil
}

var rootRank = map[string]int{"yes": 0, "prohibit-password": 1, "without-password": 1, "forced-commands-only": 2, "no": 3}

// rootTarget: "no" when a named sudo user with a key exists, "prohibit-password" when only root has a key.
func rootTarget(users []User) (string, error) {
	sudoKey, rootKeys := false, false
	for _, u := range users {
		if u.UID == 0 && u.AuthorizedKeys > 0 {
			rootKeys = true
		}
		if u.UID != 0 && u.Sudo && u.AuthorizedKeys > 0 {
			sudoKey = true
		}
	}
	switch {
	case sudoKey:
		return "no", nil
	case rootKeys:
		return "prohibit-password", nil
	}
	return "", errors.New("no named sudo user has an SSH key, and root has none either: you could not log in afterwards")
}

func planRootOff() (*switchPlan, error) {
	eff, err := sshPrechecks()
	if err != nil {
		return nil, err
	}
	users, err := listUsers()
	if err != nil {
		return nil, fmt.Errorf("read users: %v", err)
	}
	target, err := rootTarget(users)
	if err != nil {
		return nil, err
	}
	cur := eff["permitrootlogin"]
	if r, ok := rootRank[cur]; ok && r >= rootRank[target] {
		return nil, fmt.Errorf("PermitRootLogin is already %s", cur)
	}
	return sshPlan([]directive{{"PermitRootLogin", target}}, true), nil
}

func planMaxAuthTries() (*switchPlan, error) {
	eff, err := sshPrechecks()
	if err != nil {
		return nil, err
	}
	if n, err := strconv.Atoi(eff["maxauthtries"]); err == nil && n <= 3 {
		return nil, fmt.Errorf("MaxAuthTries is already %d", n)
	}
	return sshPlan([]directive{{"MaxAuthTries", "3"}}, true), nil
}

func sshPlan(ds []directive, needsLogin bool) *switchPlan {
	var parts []string
	for _, d := range ds {
		parts = append(parts, d.Name+" "+d.Value)
	}
	return &switchPlan{
		targets:    []string{"ssh"},
		needsLogin: needsLogin,
		summary:    strings.Join(parts, ", "),
		apply: func(l *opLog) error {
			old, _ := readCapped(rp(sshDropIn), 1<<20)
			if err := l.add("write "+sshDropIn, writeFileAtomic(rp(sshDropIn), dropInContent(old, ds), 0o644), strings.Join(parts, ", ")); err != nil {
				return err
			}
			if err := l.add("sshd -t", sshdTest(), "config is valid"); err != nil {
				return err
			}
			return l.add("reload ssh", reloadSSHFn(), "open sessions stay connected")
		},
		verify: func(l *opLog) error {
			eff, err := sshdEffective()
			if err != nil {
				return l.add("sshd -T", err, "")
			}
			for _, d := range ds {
				if got := eff[strings.ToLower(d.Name)]; got != d.Value {
					return l.add("sshd -T", fmt.Errorf("%s is %q, not %q: an earlier setting wins", strings.ToLower(d.Name), got, d.Value), "")
				}
			}
			if err := l.add("sshd -T", nil, strings.ToLower(strings.Join(parts, ", "))); err != nil {
				return err
			}
			return l.add("ssh banner", sshBannerOK(eff), "sshd answers on its port")
		},
	}
}

// dropInContent sets each directive in the drop-in file: old lines for those names go, other lines stay.
func dropInContent(old []byte, ds []directive) []byte {
	var out []string
	header := "# Managed by SecureMyServer signed switches. `sudo securemyserver undo` restores the previous files."
	hasHeader := false
	sc := bufio.NewScanner(bytes.NewReader(old))
	for sc.Scan() {
		line := sc.Text()
		if line == header {
			hasHeader = true
		}
		f := strings.Fields(line)
		drop := false
		if len(f) > 0 && !strings.HasPrefix(f[0], "#") {
			for _, d := range ds {
				if strings.EqualFold(f[0], d.Name) {
					drop = true
				}
			}
		}
		if !drop {
			out = append(out, line)
		}
	}
	if !hasHeader {
		out = append([]string{header}, out...)
	}
	for _, d := range ds {
		out = append(out, d.Name+" "+d.Value)
	}
	return []byte(strings.Join(out, "\n") + "\n")
}

// sshEndpoints are the addresses to try for the banner check, from sshd -T port and listenaddress.
func sshEndpoints(eff map[string]string) []string {
	var ports []string
	for _, p := range strings.Split(eff["port"], ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil && n > 0 && n < 65536 {
			ports = append(ports, strconv.Itoa(n))
		}
	}
	if len(ports) == 0 {
		ports = []string{"22"}
	}
	var out []string
	for _, la := range strings.Split(eff["listenaddress"], ",") {
		la = strings.TrimSpace(la)
		host, port, err := net.SplitHostPort(la)
		if err != nil {
			continue
		}
		switch host {
		case "0.0.0.0", "":
			host = "127.0.0.1"
		case "::":
			host = "::1"
		}
		if net.ParseIP(host) != nil {
			out = append(out, net.JoinHostPort(host, port))
		}
	}
	for _, p := range ports {
		out = append(out, net.JoinHostPort("127.0.0.1", p))
	}
	return out
}

func checkSSHBanner(eff map[string]string) error {
	var last error
	for _, addr := range sshEndpoints(eff) {
		c, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			last = err
			continue
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 255)
		n, _ := c.Read(buf)
		c.Close()
		if strings.HasPrefix(string(buf[:n]), "SSH-") {
			return nil
		}
		last = fmt.Errorf("%s answered without an SSH banner", addr)
	}
	if last == nil {
		last = errors.New("no SSH port to check")
	}
	return fmt.Errorf("sshd does not answer: %v", last)
}

/* ---------- Updates ---------- */

var debPackageRE = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,100}$`)

// runApt runs a package command with a non-interactive environment. Under systemd it runs as its own transient
// unit, outside the agent's sandbox, the way Ubuntu's apt-daily-upgrade.service does.
var runApt = func(timeout time.Duration, name string, args ...string) error {
	path, err := lookPath(name)
	if err != nil {
		return err
	}
	env := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=l"}
	argv := append([]string{path}, args...)
	if isSystemd() {
		sr, err := lookPath("systemd-run")
		if err == nil {
			pre := []string{sr, "--wait", "--collect", "--quiet", "--unit=securemyserver-apt-" + strconv.FormatInt(time.Now().Unix(), 10)}
			for _, e := range env[3:] {
				pre = append(pre, "--setenv="+e)
			}
			argv = append(pre, argv...)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env, cmd.Dir = env, "/"
	var out capped
	out.max = 64 << 10
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		tail := out.String()
		if len(tail) > 300 {
			tail = tail[len(tail)-300:]
		}
		return fmt.Errorf("%s: %v: %s", name, err, strings.TrimSpace(tail))
	}
	return nil
}

var simulateUpgrades = collectUpdates

func planSecurityNow() (*switchPlan, error) {
	u, err := simulateUpgrades()
	if err != nil {
		return nil, fmt.Errorf("apt-get -s upgrade: %v", err)
	}
	if u.Source != "apt-get" {
		return nil, errors.New("only apt (Ubuntu, Debian) is supported. Use Fix with AI")
	}
	if u.Security == 0 {
		return nil, errors.New("no security updates are waiting")
	}
	if err := sshdTest(); err != nil {
		return nil, fmt.Errorf("the SSH config is not valid now, so an openssh upgrade could fail to restart it: %v", err)
	}
	before := u.Security
	_, uuErr := lookPath("unattended-upgrade")
	return &switchPlan{
		targets: []string{"ssh"},
		summary: fmt.Sprintf("install %d security update(s)", before),
		apply: func(l *opLog) error {
			if uuErr == nil {
				// unattended-upgrade only takes the security origins by default, and keeps changed config files.
				return l.add("unattended-upgrade", runApt(45*time.Minute, "unattended-upgrade"), "security origins only")
			}
			if err := l.add("apt-get update", runApt(10*time.Minute, "apt-get", "update"), ""); err != nil {
				return err
			}
			u, err := simulateUpgrades()
			if err != nil {
				return l.add("apt-get -s upgrade", err, "")
			}
			var pkgs []string
			for _, p := range u.SecurityPackages {
				if debPackageRE.MatchString(p) {
					pkgs = append(pkgs, p)
				}
			}
			if len(pkgs) == 0 {
				return l.add("security packages", nil, "nothing left to install")
			}
			args := append([]string{"-o", "Dpkg::Options::=--force-confold", "-y", "install", "--only-upgrade"}, pkgs...)
			return l.add("apt-get install --only-upgrade", runApt(45*time.Minute, "apt-get", args...), strings.Join(pkgs, " "))
		},
		verify: func(l *opLog) error {
			if err := l.add("sshd -t", sshdTest(), "config is valid"); err != nil {
				return err
			}
			eff, err := sshdEffective()
			if err != nil {
				return l.add("sshd -T", err, "")
			}
			if err := l.add("ssh banner", sshBannerOK(eff), "sshd answers on its port"); err != nil {
				return err
			}
			after, err := simulateUpgrades()
			if err != nil {
				return l.add("apt-get -s upgrade", err, "")
			}
			return l.add("security updates left", nil, fmt.Sprintf("%d before, %d now", before, after.Security))
		},
	}, nil
}

var unattended = unattendedState

func planUnattendedOn() (*switchPlan, error) {
	switch unattended() {
	case "absent":
		return nil, errors.New("unattended-upgrades is not installed, and switches never install software. Use Fix with AI")
	case "on":
		return nil, errors.New("automatic security updates are already on")
	case "unknown":
		return nil, errors.New("could not read the apt configuration (apt-config dump)")
	}
	content := "// Managed by SecureMyServer (updates.unattended_on). `sudo securemyserver undo` removes it.\n" +
		"APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"
	return &switchPlan{
		targets: []string{"apt"},
		summary: `APT::Periodic::Unattended-Upgrade "1"`,
		apply: func(l *opLog) error {
			return l.add("write "+aptAutoUpgrades, writeFileAtomic(rp(aptAutoUpgrades), []byte(content), 0o644), "")
		},
		verify: func(l *opLog) error {
			if s := unattended(); s != "on" {
				return l.add("apt-config dump", fmt.Errorf("unattended upgrades still read as %s", s), "")
			}
			return l.add("apt-config dump", nil, "APT::Periodic::Unattended-Upgrade 1")
		},
	}, nil
}

/* ---------- Firewall ---------- */

func planFirewallOn() (*switchPlan, error) {
	if _, err := lookPath("ufw"); err != nil {
		return nil, errors.New("ufw is not installed, and switches never install software. Use Fix with AI")
	}
	if ufwIsActive() {
		return nil, errors.New("ufw is already active")
	}
	eff, err := sshdEffective()
	if err != nil {
		return nil, err
	}
	var sshPorts []int
	for _, p := range strings.Split(eff["port"], ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil && n > 0 && n < 65536 {
			sshPorts = append(sshPorts, n)
		}
	}
	if len(sshPorts) == 0 {
		return nil, errors.New("could not read the SSH port from sshd -T")
	}
	ports, err := listPorts()
	if err != nil {
		return nil, fmt.Errorf("read listening ports: %v", err)
	}
	allow := map[int]bool{}
	for _, p := range sshPorts {
		allow[p] = true
	}
	var web, others []int
	for _, p := range ports {
		if (p.Addr != "0.0.0.0" && p.Addr != "::") || allow[p.Port] {
			continue
		}
		if p.Port == 80 || p.Port == 443 {
			web = append(web, p.Port)
		} else {
			others = append(others, p.Port)
		}
		allow[p.Port] = true
	}
	if len(others) > 0 {
		sort.Ints(others)
		return nil, fmt.Errorf("other ports listen on every interface (%s): choose which stay open with Fix with AI", joinInts(others))
	}
	sort.Ints(web)
	open := append(append([]int{}, sshPorts...), web...)
	return &switchPlan{
		targets:    []string{"ufw"},
		needsLogin: true,
		summary:    "ufw on, allowing " + joinInts(open),
		apply: func(l *opLog) error {
			for _, p := range open { // SSH first, before anything is switched on
				if err := l.add(fmt.Sprintf("ufw allow %d/tcp", p), runUFW("allow", strconv.Itoa(p)+"/tcp"), ""); err != nil {
					return err
				}
			}
			if err := l.add("ufw default deny incoming", runUFW("default", "deny", "incoming"), ""); err != nil {
				return err
			}
			if err := l.add("ufw default allow outgoing", runUFW("default", "allow", "outgoing"), ""); err != nil {
				return err
			}
			return l.add("ufw enable", runUFW("--force", "enable"), "open sessions stay connected")
		},
		verify: func(l *opLog) error {
			out, _, err := run(15*time.Second, "ufw", "status")
			if err != nil || parseUFWStatus(out) != "active" {
				return l.add("ufw status", errors.New("ufw is not active"), "")
			}
			for _, p := range sshPorts {
				if !ufwAllows(out, p) {
					return l.add("ufw status", fmt.Errorf("port %d/tcp is not allowed", p), "")
				}
			}
			if err := l.add("ufw status", nil, "active, SSH allowed"); err != nil {
				return err
			}
			return l.add("ssh banner", sshBannerOK(eff), "sshd answers on its port")
		},
	}, nil
}

func ufwAllows(status []byte, port int) bool {
	want := strconv.Itoa(port) + "/tcp"
	for _, l := range strings.Split(string(status), "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && (f[0] == want || f[0] == strconv.Itoa(port)) && strings.EqualFold(f[1], "ALLOW") {
			return true
		}
	}
	return false
}

func joinInts(ns []int) string {
	s := make([]string, len(ns))
	for i, n := range ns {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ", ")
}

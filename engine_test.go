package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// switchSandbox is a server with sshd_config, a pinned ES256 key and fake sshd/journal behind it.
type switchSandbox struct {
	*sandbox
	signer *testSigner
	cfg    Config
	eff    map[string]string
	logins []AuthEvent
	// unverified: the logins come from auth.log, not the journal (D-069).
	unverified bool
}

func newSwitchSandbox(t *testing.T) *switchSandbox {
	s := &switchSandbox{sandbox: newSandbox(t), signer: newSigner(t, "ES256")}
	s.sshConfig()
	s.cfg = Config{ServerID: testServer, Origin: testOrigin, RPID: testRPID, OwnerKeys: []OwnerKey{s.signer.key}}
	s.eff = map[string]string{"passwordauthentication": "yes", "pubkeyauthentication": "yes", "kbdinteractiveauthentication": "no",
		"usepam": "yes", "permitrootlogin": "yes", "maxauthtries": "6", "port": "22"}
	oldEff, oldRecent, oldUsers, oldBanner, oldAuth, oldVerifiable := sshdEffective, recentKeyLogins, listUsers, sshBannerOK, authSince, loginsVerifiable
	t.Cleanup(func() {
		sshdEffective, recentKeyLogins, listUsers, sshBannerOK, authSince, loginsVerifiable = oldEff, oldRecent, oldUsers, oldBanner, oldAuth, oldVerifiable
	})
	loginsVerifiable = func() bool { return !s.unverified }
	// sshd -T reflects the drop-in, the way the real sshd reads 00-securemyserver.conf first.
	sshdEffective = func() (map[string]string, error) {
		out := map[string]string{}
		for k, v := range s.eff {
			out[k] = v
		}
		for k, v := range parseSSHDT([]byte(s.read(sshDropIn))) {
			if !strings.HasPrefix(k, "#") && k != "<missing>" {
				out[k] = v
			}
		}
		return out, nil
	}
	recentKeyLogins = func(_, _ time.Time) int { return 1 }
	listUsers = func() ([]User, error) {
		return []User{{Name: "root", UID: 0, Sudo: true, AuthorizedKeys: 1}, {Name: "deploy", UID: 1000, Sudo: true, AuthorizedKeys: 1}}, nil
	}
	sshBannerOK = func(map[string]string) error { return nil }
	authSince = func(time.Time) ([]AuthEvent, bool) { return s.logins, !s.unverified }
	return s
}

func (s *switchSandbox) send(t *testing.T, policies ...string) {
	t.Helper()
	var envs []Envelope
	for _, p := range policies {
		envs = append(envs, s.signer.sign(t, p, nil))
	}
	processEnvelopes(s.cfg, envs)
}

func (s *switchSandbox) lastOp() SwitchOp {
	st := loadEngineState()
	if len(st.Ops) == 0 {
		return SwitchOp{}
	}
	return st.Ops[len(st.Ops)-1]
}

func TestSwitchAppliesAndConfirmsOnLogin(t *testing.T) {
	s := newSwitchSandbox(t)
	pol := testPolicy(t, "switch", "ssh.password_auth_off", s.now, nil)

	// Not allowed on the server yet: refused, nothing written.
	s.send(t, pol)
	if op := s.lastOp(); op.State != opRefused || !strings.Contains(op.Reason, "sudo securemyserver allow ssh.password_auth_off") {
		t.Fatalf("not allowed: %+v", op)
	}
	if s.read(sshDropIn) != "<missing>" {
		t.Fatal("wrote without allow")
	}
	// The same signed policy now replays: refused, even after allowing.
	_ = allowSwitch("ssh.password_auth_off")
	s.send(t, pol)
	if st := loadEngineState(); !strings.Contains(st.Refused[len(st.Refused)-1].Reason, "replayed") {
		t.Fatalf("replay: %+v", st.Refused)
	}

	pol = testPolicy(t, "switch", "ssh.password_auth_off", s.now, nil)
	s.send(t, pol)
	op := s.lastOp()
	if op.State != opApplied || op.Checkpoint == "" || !op.NeedsLogin {
		t.Fatalf("apply: %+v", op)
	}
	if got := s.read(sshDropIn); !strings.Contains(got, "PasswordAuthentication no") {
		t.Fatalf("drop-in %q", got)
	}
	if s.reloads != 1 {
		t.Fatalf("reloads %d", s.reloads)
	}
	// A rate limit holds the next switch.
	_ = allowSwitch("ssh.max_auth_tries_3")
	s.send(t, testPolicy(t, "switch", "ssh.max_auth_tries_3", s.now, nil))
	if op := s.lastOp(); op.State != opRefused || !strings.Contains(op.Reason, "10 minutes") && !strings.Contains(op.Reason, "still waiting") {
		t.Fatalf("rate limit: %+v", op)
	}

	// A login from before the change does not confirm; a new key login does.
	s.logins = []AuthEvent{{TS: s.now.Add(-time.Minute).Format(time.RFC3339Nano), Result: "ok", Method: "publickey", User: "deploy", IP: "203.0.113.5"}}
	s.now = s.now.Add(time.Minute)
	tickSwitches()
	if st := loadEngineState(); st.op(nonceOf(t, pol)).State != opApplied {
		t.Fatal("an old login confirmed")
	}
	s.logins = append(s.logins, AuthEvent{TS: s.now.Add(time.Second).Format(time.RFC3339Nano), Result: "ok", Method: "publickey", User: "deploy", IP: "203.0.113.5"})
	s.now = s.now.Add(2 * time.Second)
	tickSwitches()
	got := loadEngineState().op(nonceOf(t, pol))
	if got.State != opConfirmed || !strings.Contains(got.Reason, "deploy from 203.0.113.5") {
		t.Fatalf("confirm: %+v", got)
	}
	s.now = s.now.Add(time.Hour)
	tickSwitches()
	if !strings.Contains(s.read(sshDropIn), "PasswordAuthentication no") {
		t.Fatal("a confirmed switch was rolled back")
	}
	// Undo still works by hand.
	_ = withLock(func() error { m, _ := loadManifest(got.Checkpoint); return restoreCheckpoint(m, "undo") })
	if s.read(sshDropIn) != "<missing>" {
		t.Fatal("undo")
	}
}

func nonceOf(t *testing.T, pol string) string {
	p, err := parsePolicy(pol)
	if err != nil {
		t.Fatal(err)
	}
	return p.Nonce
}

func TestSwitchRollsBackAtDeadline(t *testing.T) {
	s := newSwitchSandbox(t)
	_ = allowSwitch("ssh.root_login_off")
	pol := testPolicy(t, "switch", "ssh.root_login_off", s.now, nil)
	s.send(t, pol)
	if op := s.lastOp(); op.State != opApplied || !strings.Contains(s.read(sshDropIn), "PermitRootLogin no") {
		t.Fatalf("apply: %+v %q", op, s.read(sshDropIn))
	}
	s.now = s.now.Add(9 * time.Minute)
	tickSwitches()
	if s.lastOp().State != opApplied {
		t.Fatal("rolled back early")
	}
	s.now = s.now.Add(time.Minute)
	tickSwitches()
	op := s.lastOp()
	if op.State != opRolledBack || !strings.Contains(op.Reason, "no new SSH key login") || s.read(sshDropIn) != "<missing>" {
		t.Fatalf("deadline: %+v", op)
	}
}

func TestSwitchConfirmPolicyAndPrechecks(t *testing.T) {
	s := newSwitchSandbox(t)
	_ = allowSwitch("ssh.max_auth_tries_3")
	pol := testPolicy(t, "switch", "ssh.max_auth_tries_3", s.now, nil)
	s.send(t, pol)
	nonce := nonceOf(t, pol)
	confirm := testPolicy(t, "confirm", "ssh.max_auth_tries_3", s.now, func(p *Policy) { p.Confirms = nonce })
	s.send(t, confirm)
	if op := loadEngineState().op(nonce); op.State != opConfirmed || !strings.Contains(op.Reason, "dashboard") {
		t.Fatalf("owner confirm: %+v", op)
	}
	// Pre-checks: already 3 is refused; no key login in 7 days refuses password off.
	s.now = s.now.Add(11 * time.Minute)
	s.eff["maxauthtries"] = "3"
	_ = withLock(func() error { return writeFileAtomic(rp(sshDropIn), nil, 0o644) })
	s.send(t, testPolicy(t, "switch", "ssh.max_auth_tries_3", s.now, nil))
	if op := s.lastOp(); op.State != opRefused || !strings.Contains(op.Reason, "already 3") {
		t.Fatalf("already: %+v", op)
	}
	recentKeyLogins = func(_, _ time.Time) int { return 0 }
	_ = allowSwitch("ssh.password_auth_off")
	s.send(t, testPolicy(t, "switch", "ssh.password_auth_off", s.now, nil))
	if op := s.lastOp(); op.State != opRefused || !strings.Contains(op.Reason, "last 7 days") {
		t.Fatalf("no key login: %+v", op)
	}
}

func TestSwitchVerifyFailureRollsBack(t *testing.T) {
	s := newSwitchSandbox(t)
	_ = allowSwitch("ssh.password_auth_off")
	sshBannerOK = func(map[string]string) error { return errors.New("sshd does not answer") }
	s.send(t, testPolicy(t, "switch", "ssh.password_auth_off", s.now, nil))
	op := s.lastOp()
	if op.State != opRolledBack || !strings.Contains(op.Reason, "sshd does not answer") || s.read(sshDropIn) != "<missing>" {
		t.Fatalf("%+v", op)
	}
}

func TestSwitchRefusesForgedAndKeyUpdate(t *testing.T) {
	s := newSwitchSandbox(t)
	_ = allowSwitch("ssh.password_auth_off")
	stranger := newSigner(t, "ES256")
	processEnvelopes(s.cfg, []Envelope{stranger.sign(t, testPolicy(t, "switch", "ssh.password_auth_off", s.now, nil), nil)})
	if op := s.lastOp(); op.State != opRefused || !strings.Contains(op.Reason, "does not trust") {
		t.Fatalf("stranger: %+v", op)
	}
	// A key update signed by a pinned key adds the stranger; then the stranger's switch runs.
	keys := testPolicy(t, "keys", "", s.now, func(p *Policy) {
		p.Keys = []PolicyKey{{ID: s.signer.id, SPKI: s.signer.key.SPKI}, {ID: stranger.id, SPKI: stranger.key.SPKI}}
	})
	// ...but not when the stranger signs it itself.
	processEnvelopes(s.cfg, []Envelope{stranger.sign(t, keys, nil)})
	if st := loadEngineState(); st.Keys != nil {
		t.Fatal("a non-pinned key updated the key set")
	}
	s.send(t, keys)
	st := loadEngineState()
	if len(st.pinnedKeys(s.cfg)) != 2 {
		t.Fatalf("pinned %d", len(st.pinnedKeys(s.cfg)))
	}
	processEnvelopes(s.cfg, []Envelope{stranger.sign(t, testPolicy(t, "switch", "ssh.password_auth_off", s.now, nil), nil)})
	if op := s.lastOp(); op.State != opApplied {
		t.Fatalf("after key update: %+v", op)
	}
	// Editing agent.conf by hand wins over the signed set.
	other := newSigner(t, "EdDSA")
	s.cfg.OwnerKeys = []OwnerKey{other.key}
	if ks := loadEngineState().pinnedKeys(s.cfg); len(ks) != 1 || ks[0].ID != other.id {
		t.Fatalf("conf did not win: %+v", ks)
	}
	rep := switchesReport(s.cfg)
	if !rep.Enabled || len(rep.Allowed) != 1 || rep.Checkpoint == nil || len(rep.Seen) == 0 {
		t.Fatalf("report %+v", rep)
	}
}

func TestDropInContent(t *testing.T) {
	old := []byte("# Managed by SecureMyServer signed switches. `sudo securemyserver undo` restores the previous files.\nMaxAuthTries 3\npasswordauthentication yes\n")
	got := string(dropInContent(old, []directive{{"PasswordAuthentication", "no"}}))
	if strings.Count(got, "Managed by") != 1 || !strings.Contains(got, "MaxAuthTries 3\n") || strings.Contains(got, "passwordauthentication yes") ||
		!strings.HasSuffix(got, "PasswordAuthentication no\n") {
		t.Fatalf("%q", got)
	}
}

func TestRootTarget(t *testing.T) {
	if v, _ := rootTarget([]User{{UID: 0, AuthorizedKeys: 1}, {UID: 1000, Sudo: true, AuthorizedKeys: 1}}); v != "no" {
		t.Fatal(v)
	}
	if v, _ := rootTarget([]User{{UID: 0, AuthorizedKeys: 1}, {UID: 1000, Sudo: false, AuthorizedKeys: 1}}); v != "prohibit-password" {
		t.Fatal(v)
	}
	if _, err := rootTarget([]User{{UID: 0}, {UID: 1000, Sudo: true}}); err == nil {
		t.Fatal("no way in, not refused")
	}
}

func TestSSHEndpointsAndUFW(t *testing.T) {
	got := sshEndpoints(map[string]string{"port": "22,2222", "listenaddress": "0.0.0.0:22,[::]:22,192.0.2.4:2222"})
	want := "127.0.0.1:22 [::1]:22 192.0.2.4:2222 127.0.0.1:22 127.0.0.1:2222"
	if strings.Join(got, " ") != want {
		t.Fatalf("%v", got)
	}
	status := []byte("Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n")
	if !ufwAllows(status, 22) || ufwAllows(status, 2222) {
		t.Fatal("ufwAllows")
	}
	if !aptPeriodicOn([]byte("APT::Periodic::Unattended-Upgrade \"0\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"), "APT::Periodic::Unattended-Upgrade") {
		t.Fatal("apt on")
	}
	if aptPeriodicOn([]byte("APT::Periodic::Unattended-Upgrade \"1\";\nAPT::Periodic::Unattended-Upgrade \"0\";\n"), "APT::Periodic::Unattended-Upgrade") {
		t.Fatal("apt off")
	}
}

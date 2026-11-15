package main

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

const gs1, gs2 = "0123456789abcdef", "fedcba9876543210"

func newSessionSandbox(t *testing.T) (*switchSandbox, *int) {
	s := newSwitchSandbox(t)
	reloads := 0
	oldNft, oldVisudo, oldReload := haveNft, visudoCheck, daemonReload
	t.Cleanup(func() { haveNft, visudoCheck, daemonReload = oldNft, oldVisudo, oldReload })
	haveNft = func() bool { return false }
	visudoCheck = func() error { return nil }
	daemonReload = func() error { reloads++; return nil }
	s.write("/etc/ssh/ssh_host_ed25519_key", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")
	s.write("/etc/sudoers.d/securemyserver-ai", "securemyserver-ai ALL=(root) NOPASSWD: /usr/sbin/sshd -T\n")
	s.write("/etc/systemd/system/app.service", "[Service]\nExecStart=/usr/bin/app\nEnvironment=API_TOKEN=abc123\n")
	return s, &reloads
}

func touch(t *testing.T, sess string) (*Manifest, bool) {
	t.Helper()
	var m *Manifest
	var created bool
	if err := withLock(func() (err error) { m, created, err = touchSession(sess); return err }); err != nil {
		t.Fatal(err)
	}
	return m, created
}

func TestSessionCheckpointLifecycle(t *testing.T) {
	s, _ := newSessionSandbox(t)
	m, created := touch(t, gs1)
	if !created || m.Kind != cpKindSession || m.Status != cpSessionOpen || !m.Deadline.IsZero() || m.Timer != "" {
		t.Fatalf("first touch: created %v %+v", created, m)
	}
	if !has(m.Targets, "sshdir") || !has(m.Targets, "sudoers") || !has(m.Targets, "systemd") || has(m.Targets, "nft") {
		t.Fatalf("targets %v", m.Targets)
	}
	if pendingCheckpoint() != nil {
		t.Fatal("a session checkpoint must not block switches as a pending one")
	}
	// Another connection 5 minutes later joins the same session.
	s.now = s.now.Add(5 * time.Minute)
	m2, created := touch(t, gs2)
	if created || m2.ID != m.ID || len(m2.AISessions) != 2 {
		t.Fatalf("join: %v %+v", created, m2)
	}
	// The AI changes things.
	s.write("/etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication no\n")
	s.write("/etc/systemd/system/app.service", "[Service]\nExecStart=/usr/bin/app --fast\nEnvironment=API_TOKEN=zzz999\n")
	s.write("/etc/ssh/ssh_host_ed25519_key", "-----BEGIN OPENSSH PRIVATE KEY-----\nBBBB\n-----END OPENSSH PRIVATE KEY-----\n")
	s.write("/etc/sudoers.d/extra", "securemyserver-ai ALL=(root) NOPASSWD: ALL\n")

	rep := sessionsReport()
	if len(rep) != 1 || rep[0].State != cpSessionOpen || rep[0].Files == nil || rep[0].UndoUntil == "" {
		t.Fatalf("report %+v", rep)
	}
	byPath := map[string]FileChange{}
	for _, f := range *rep[0].Files {
		byPath[f.Path] = f
	}
	if d := byPath["/etc/ssh/sshd_config.d/50-cloud-init.conf"].Diff; !strings.Contains(d, "-PasswordAuthentication yes\n+PasswordAuthentication no\n") {
		t.Fatalf("sshd diff %q", d)
	}
	if f := byPath["/etc/ssh/ssh_host_ed25519_key"]; f.Skipped != "secret" || f.Diff != "" {
		t.Fatalf("host key must never be diffed: %+v", f)
	}
	if f := byPath["/etc/systemd/system/app.service"]; strings.Contains(f.Diff, "abc123") || strings.Contains(f.Diff, "zzz999") || f.Redacted == 0 || !strings.Contains(f.Diff, "+ExecStart=/usr/bin/app --fast") {
		t.Fatalf("unit diff not redacted: %+v", f)
	}
	if f := byPath["/etc/sudoers.d/extra"]; f.Change != "added" || !strings.Contains(f.Diff, "+securemyserver-ai ALL=(root) NOPASSWD: ALL") {
		t.Fatalf("sudoers added: %+v", f)
	}
	// Sent once: the next report leaves the unchanged diff out.
	markSessionsSent(rep)
	if again := sessionsReport(); again[0].Files != nil {
		t.Fatal("unchanged diff sent again")
	}

	// 15 minutes idle: the session closes and its diff is frozen.
	s.now = s.now.Add(16 * time.Minute)
	tickSwitches()
	m3, _ := loadManifest(m.ID)
	if m3.Status != cpSessionClosed || m3.AfterState == "" || m3.DiffSHA256 == "" {
		t.Fatalf("closed: %+v", m3)
	}

	// The undo is refused until root allows it locally.
	undo := testPolicy(t, "confirm", sessionUndoSwitch, s.now, func(p *Policy) { p.Confirms = m.ID })
	s.send(t, undo)
	st := loadEngineState()
	if r := st.Refused[len(st.Refused)-1]; !strings.Contains(r.Reason, "allow session-undo") {
		t.Fatalf("not allowed: %+v", r)
	}
	if err := allowSwitch(sessionUndoAllow); err != nil {
		t.Fatal(err)
	}
	// Files changed after the session ended: refused, so a later change by hand is never undone silently.
	s.write("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n# by hand\n")
	s.send(t, testPolicy(t, "confirm", sessionUndoSwitch, s.now, func(p *Policy) { p.Confirms = m.ID }))
	st = loadEngineState()
	if r := st.Refused[len(st.Refused)-1]; !strings.Contains(r.Reason, "changed again") {
		t.Fatalf("changed since: %+v", r)
	}
	s.write("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n")

	// Allowed, unchanged since: restored, validated, reported.
	s.send(t, testPolicy(t, "confirm", sessionUndoSwitch, s.now, func(p *Policy) { p.Confirms = m.ID }))
	op := s.lastOp()
	if op.Switch != sessionUndoSwitch || op.State != opConfirmed || !strings.Contains(op.Reason, "sshd -t and visudo -c passed") {
		t.Fatalf("undo op %+v", op)
	}
	if got := s.read("/etc/ssh/sshd_config.d/50-cloud-init.conf"); got != "PasswordAuthentication yes\n" {
		t.Fatalf("not restored: %q", got)
	}
	if got := s.read("/etc/sudoers.d/extra"); got != "<missing>" {
		t.Fatalf("added sudoers file left behind: %q", got)
	}
	if !strings.Contains(s.read("/etc/ssh/ssh_host_ed25519_key"), "AAAA") {
		t.Fatal("host key not restored")
	}
	rep = sessionsReport()
	m4, _ := loadManifest(m.ID)
	frozen, _ := diffOf(m4)
	if rep[0].State != cpRestored || rep[0].UndoUntil != "" || len(frozen.Files) < 4 || rep[0].DiffSHA256 != m4.DiffSHA256 {
		t.Fatalf("after undo the frozen diff stays and undo is gone: %+v %d", rep[0], len(frozen.Files))
	}
	// Twice is refused.
	s.send(t, testPolicy(t, "confirm", sessionUndoSwitch, s.now, func(p *Policy) { p.Confirms = m.ID }))
	st = loadEngineState()
	if r := st.Refused[len(st.Refused)-1]; !strings.Contains(r.Reason, "already restored") {
		t.Fatalf("twice: %+v", r)
	}
}

func TestSessionUndoWindowAndNewerSession(t *testing.T) {
	s, _ := newSessionSandbox(t)
	_ = allowSwitch(sessionUndoAllow)
	m1, _ := touch(t, gs1)
	s.now = s.now.Add(20 * time.Minute)
	m2, created := touch(t, gs2)
	if !created || m2.ID == m1.ID {
		t.Fatal("after 15 idle minutes a new session starts")
	}
	if c, _ := loadManifest(m1.ID); c.Status != cpSessionClosed {
		t.Fatalf("old one closed: %s", c.Status)
	}
	s.send(t, testPolicy(t, "confirm", sessionUndoSwitch, s.now, func(p *Policy) { p.Confirms = m1.ID }))
	st := loadEngineState()
	if r := st.Refused[len(st.Refused)-1]; !strings.Contains(r.Reason, "newer AI session") {
		t.Fatalf("superseded: %+v", r)
	}
	s.now = s.now.Add(25 * time.Hour)
	s.send(t, testPolicy(t, "confirm", sessionUndoSwitch, s.now, func(p *Policy) { p.Confirms = m2.ID }))
	st = loadEngineState()
	if r := st.Refused[len(st.Refused)-1]; !strings.Contains(r.Reason, "24-hour") {
		t.Fatalf("window: %+v", r)
	}
}

func TestSessionUndoRefusesBadSavedSudoers(t *testing.T) {
	s, _ := newSessionSandbox(t)
	_ = allowSwitch(sessionUndoAllow)
	m, _ := touch(t, gs1)
	s.write("/etc/sudoers.d/securemyserver-ai", "changed\n")
	visudoCheck = func() error { return errors.New("visudo -c: parse error") }
	s.send(t, testPolicy(t, "confirm", sessionUndoSwitch, s.now, func(p *Policy) { p.Confirms = m.ID }))
	op := s.lastOp()
	if op.State != opRefused || !strings.Contains(op.Reason, "visudo") {
		t.Fatalf("op %+v", op)
	}
	if got := s.read("/etc/sudoers.d/securemyserver-ai"); got != "changed\n" {
		t.Fatalf("current file must be left as it was: %q", got)
	}
	if c, _ := loadManifest(m.ID); c.Status != cpRestoreFailed {
		t.Fatalf("status %s", c.Status)
	}
}

func TestSessionCheckpointCLI(t *testing.T) {
	newSessionSandbox(t)
	var out, errb strings.Builder
	for _, bad := range [][]string{
		{"--session", gs1},
		{"--session", gs1, "--auto", "ssh"},
		{"--session", "../../etc", "--auto"},
		{"--session", gs1, "--minutes", "1"},
	} {
		if code := cmdCheckpoint(bad, &out, &errb); code != 2 {
			t.Fatalf("%v: code %d", bad, code)
		}
	}
	if code := cmdCheckpoint([]string{"--session", gs1, "--auto"}, &out, &errb); code != 0 || !strings.HasPrefix(out.String(), "created ") {
		t.Fatalf("code %d out %q err %q", code, out.String(), errb.String())
	}
	out.Reset()
	if code := cmdCheckpoint([]string{"--session", gs1, "--auto"}, &out, &errb); code != 0 || !strings.HasPrefix(out.String(), "open ") {
		t.Fatalf("second: %d %q", code, out.String())
	}
	// A checkpoint that can't be saved fails (the gate then refuses the command).
	s := latestSession()
	_ = withLock(func() error { closeSession(s); return nil })
	if err := os.Chmod(rp(checkpointDir), 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(rp(checkpointDir), 0o700)
	if os.Getuid() != 0 { // root ignores the mode; the e2e test fills the disk instead
		if code := cmdCheckpoint([]string{"--session", gs2, "--auto"}, &out, &errb); code != 1 {
			t.Fatalf("unwritable: code %d", code)
		}
	}
}

// The same bytes src/lib/phase2b.test.ts builds for "Undo this session".
func TestSessionUndoPolicyVector(t *testing.T) {
	raw := `{"confirms":"20261108-120000-abcd","expires_at":"2026-11-08T12:10:00Z","issued_at":"2026-11-08T12:00:00Z","nonce":"AAAAAAAAAAAAAAAAAAAAAA","server_id":"0b6c1f7e-1234-4abc-8def-0123456789ab","switch":"session.undo","type":"confirm","v":1}`
	p, err := parsePolicy(raw)
	if err != nil || p.Switch != sessionUndoSwitch || p.Confirms != "20261108-120000-abcd" {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := parsePolicy(strings.Replace(raw, "20261108-120000-abcd", "AAAAAAAAAAAAAAAAAAAAAA", 1)); err == nil {
		t.Fatal("session.undo must name a checkpoint id")
	}
	if _, err := parsePolicy(strings.Replace(raw, `"type":"confirm"`, `"type":"switch"`, 1)); err == nil {
		t.Fatal("session.undo is not a switch")
	}
}

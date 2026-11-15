package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// sandbox points every path at a temp dir and replaces the system commands, for one test.
type sandbox struct {
	t        *testing.T
	root     string
	now      time.Time
	sshdOK   bool
	reloads  int
	timers   []string
	stopped  []string
	session  string
	ufwState bool
}

func newSandbox(t *testing.T) *sandbox {
	t.Helper()
	s := &sandbox{t: t, root: t.TempDir(), now: time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC), sshdOK: true, session: "7"}
	saved := []func(){}
	keep := func(restore func()) { saved = append(saved, restore) }
	oldRoot, oldNow, oldTest, oldReload, oldSys, oldStart, oldStop, oldSess, oldRootCheck := fsRoot, nowFn, sshdTest, reloadSSHFn, isSystemd, startTimer, stopTimer, auditSession, requireRoot
	oldUfwActive, oldRunUFW := ufwIsActive, runUFW
	keep(func() {
		fsRoot, nowFn, sshdTest, reloadSSHFn, isSystemd, startTimer, stopTimer, auditSession, requireRoot = oldRoot, oldNow, oldTest, oldReload, oldSys, oldStart, oldStop, oldSess, oldRootCheck
		ufwIsActive, runUFW = oldUfwActive, oldRunUFW
	})
	fsRoot = s.root
	nowFn = func() time.Time { return s.now }
	sshdTest = func() error {
		if !s.sshdOK {
			return errors.New("sshd -t: line 1: Bad configuration option")
		}
		return nil
	}
	reloadSSHFn = func() error { s.reloads++; return nil }
	isSystemd = func() bool { return true }
	startTimer = func(id string, _ time.Duration) (string, error) {
		s.timers = append(s.timers, id)
		return "securemyserver-undo-" + id, nil
	}
	stopTimer = func(unit string) { s.stopped = append(s.stopped, unit) }
	auditSession = func() string { return s.session }
	requireRoot = func() error { return nil }
	ufwIsActive = func() bool { return s.ufwState }
	runUFW = func(args ...string) error {
		switch strings.Join(args, " ") {
		case "--force enable":
			s.ufwState = true
		case "disable":
			s.ufwState = false
		}
		return nil
	}
	t.Cleanup(func() {
		for i := len(saved) - 1; i >= 0; i-- {
			saved[i]()
		}
	})
	return s
}

func (s *sandbox) write(path, content string) {
	s.t.Helper()
	if err := os.MkdirAll(filepath.Dir(rp(path)), 0o755); err != nil {
		s.t.Fatal(err)
	}
	if err := os.WriteFile(rp(path), []byte(content), 0o644); err != nil {
		s.t.Fatal(err)
	}
}

func (s *sandbox) read(path string) string {
	b, err := os.ReadFile(rp(path))
	if err != nil {
		return "<missing>"
	}
	return string(b)
}

func (s *sandbox) sshConfig() {
	s.write("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n")
	s.write("/etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n")
}

func cp(t *testing.T, targets []string, window time.Duration) *Manifest {
	t.Helper()
	var m *Manifest
	if err := withLock(func() (err error) { m, err = createCheckpoint(targets, window, "test"); return err }); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestCheckpointRestoresExactly(t *testing.T) {
	s := newSandbox(t)
	s.sshConfig()
	m := cp(t, []string{"ssh"}, 5*time.Minute)
	if len(s.timers) != 1 || m.Timer == "" {
		t.Fatalf("no backup timer: %v", s.timers)
	}
	if st, _ := os.Stat(cpPath(m.ID)); st.Mode().Perm() != 0o700 {
		t.Fatalf("checkpoint dir mode %v", st.Mode())
	}
	// Change, add and remove files, then undo.
	s.write("/etc/ssh/sshd_config", "garbage\n")
	s.write(sshDropIn, "PasswordAuthentication no\n")
	os.Remove(rp("/etc/ssh/sshd_config.d/50-cloud-init.conf"))
	if err := withLock(func() error { return restoreCheckpoint(m, "test undo") }); err != nil {
		t.Fatal(err)
	}
	if got := s.read("/etc/ssh/sshd_config"); !strings.HasPrefix(got, "Include") {
		t.Fatalf("sshd_config %q", got)
	}
	if got := s.read(sshDropIn); got != "<missing>" {
		t.Fatalf("drop-in left behind: %q", got)
	}
	if got := s.read("/etc/ssh/sshd_config.d/50-cloud-init.conf"); got != "PasswordAuthentication yes\n" {
		t.Fatalf("removed file not restored: %q", got)
	}
	if s.reloads != 1 {
		t.Fatalf("reloads %d", s.reloads)
	}
	m2, _ := loadManifest(m.ID)
	if m2.Status != cpRestored || len(s.stopped) != 1 {
		t.Fatalf("status %s stopped %v", m2.Status, s.stopped)
	}
	if err := withLock(func() error { return restoreCheckpoint(m2, "again") }); err == nil {
		t.Fatal("restored twice")
	}
}

func TestCheckpointBackupFailsValidation(t *testing.T) {
	s := newSandbox(t)
	s.sshConfig()
	m := cp(t, []string{"ssh"}, 5*time.Minute)
	s.write(sshDropIn, "PasswordAuthentication no\n")
	s.sshdOK = false // the saved config does not pass sshd -t (e.g. a newer sshd since)
	err := withLock(func() error { return restoreCheckpoint(m, "undo") })
	if err == nil || !strings.Contains(err.Error(), "FAILS sshd -t") {
		t.Fatalf("err %v", err)
	}
	if got := s.read(sshDropIn); got != "PasswordAuthentication no\n" {
		t.Fatalf("the current config was not left as it was: %q", got)
	}
	if s.reloads != 0 {
		t.Fatal("reloaded after a failed validation")
	}
	m2, _ := loadManifest(m.ID)
	if m2.Status != cpRestoreFailed {
		t.Fatalf("status %s", m2.Status)
	}
}

func TestCheckpointDamagedCopyIsNotRestored(t *testing.T) {
	s := newSandbox(t)
	s.sshConfig()
	m := cp(t, []string{"ssh"}, 5*time.Minute)
	if err := os.WriteFile(filepath.Join(cpPath(m.ID), "files", "etc/ssh/sshd_config"), []byte("PermitRootLogin yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.write("/etc/ssh/sshd_config", "current\n")
	if err := withLock(func() error { return restoreCheckpoint(m, "undo") }); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("err %v", err)
	}
	if s.read("/etc/ssh/sshd_config") != "current\n" {
		t.Fatal("a damaged copy was written")
	}
}

func TestCheckpointDeadlineAndConfirm(t *testing.T) {
	s := newSandbox(t)
	s.sshConfig()
	m := cp(t, []string{"ssh"}, 5*time.Minute)
	if err := withLock(func() error { _, err := createCheckpoint([]string{"ssh"}, time.Minute, "second"); return err }); err == nil {
		t.Fatal("two pending checkpoints")
	}
	s.write(sshDropIn, "x\n")
	s.now = s.now.Add(4 * time.Minute)
	_ = withLock(func() error { enforceDeadlines(s.now); return nil })
	if s.read(sshDropIn) != "x\n" {
		t.Fatal("restored before the deadline")
	}
	s.now = s.now.Add(time.Minute)
	_ = withLock(func() error { enforceDeadlines(s.now); return nil })
	if s.read(sshDropIn) != "<missing>" {
		t.Fatal("not restored at the deadline")
	}

	// A confirmed checkpoint is never restored by the deadline.
	m = cp(t, []string{"ssh"}, 5*time.Minute)
	s.write(sshDropIn, "kept\n")
	var out, errb bytes.Buffer
	if code := dispatch([]string{"confirm"}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "NEW SSH login") {
		t.Fatalf("same session confirmed: %d %s", code, errb.String())
	}
	s.session = "8" // a new login
	out.Reset()
	if code := dispatch([]string{"confirm"}, &out, &errb); code != 0 || !strings.Contains(out.String(), m.ID) {
		t.Fatalf("confirm: %d %s %s", code, out.String(), errb.String())
	}
	s.now = s.now.Add(time.Hour)
	_ = withLock(func() error { enforceDeadlines(s.now); return nil })
	if s.read(sshDropIn) != "kept\n" {
		t.Fatal("a confirmed checkpoint was restored")
	}
	// undo still restores the confirmed one on request.
	out.Reset()
	if code := dispatch([]string{"undo"}, &out, &errb); code != 0 || s.read(sshDropIn) != "<missing>" {
		t.Fatalf("undo: %d %s %s", code, out.String(), errb.String())
	}
}

func TestCheckpointCLI(t *testing.T) {
	s := newSandbox(t)
	s.sshConfig()
	var out, errb bytes.Buffer
	if code := dispatch([]string{"checkpoint", "bogus"}, &out, &errb); code != 2 {
		t.Fatalf("bogus target: %d", code)
	}
	if code := dispatch([]string{"checkpoint", "ssh", "--minutes", "0"}, &out, &errb); code != 2 {
		t.Fatalf("0 minutes: %d", code)
	}
	errb.Reset()
	if code := dispatch([]string{"checkpoint", "ssh", "--minutes", "10"}, &out, &errb); code != 0 {
		t.Fatalf("checkpoint: %d %s", code, errb.String())
	}
	dir := strings.TrimSpace(out.String())
	if !strings.HasPrefix(dir, rp(checkpointDir)+"/") || !strings.Contains(errb.String(), "sudo securemyserver confirm") {
		t.Fatalf("out %q err %q", dir, errb.String())
	}
	m, err := loadManifest(filepath.Base(dir))
	if err != nil || m.Deadline.Sub(m.CreatedAt) != 10*time.Minute {
		t.Fatalf("%v %+v", err, m)
	}
	// The timer's own call does nothing before the deadline, and restores after it.
	out.Reset()
	if code := dispatch([]string{"undo", "--if-pending", m.ID}, &out, &errb); code != 0 || !strings.Contains(out.String(), "nothing to do") {
		t.Fatalf("early timer: %d %s", code, out.String())
	}
	s.write(sshDropIn, "x\n")
	s.now = s.now.Add(10 * time.Minute)
	out.Reset()
	if code := dispatch([]string{"undo", "--if-pending", m.ID}, &out, &errb); code != 0 || s.read(sshDropIn) != "<missing>" {
		t.Fatalf("timer restore: %d %s %s", code, out.String(), errb.String())
	}
	out.Reset()
	if code := dispatch([]string{"status"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "restored") {
		t.Fatalf("status: %s", out.String())
	}
	requireRoot = func() error { return errNotRoot }
	if code := dispatch([]string{"undo"}, &out, &errb); code != 1 {
		t.Fatal("undo without root")
	}
}

func TestCheckpointUFWState(t *testing.T) {
	s := newSandbox(t)
	s.write("/etc/ufw/ufw.conf", "ENABLED=no\n")
	s.write("/etc/default/ufw", "IPV6=yes\n")
	m := cp(t, []string{"ufw"}, 10*time.Minute)
	if m.UFWActive == nil || *m.UFWActive {
		t.Fatal("ufw state not saved")
	}
	s.ufwState = true
	s.write("/etc/ufw/ufw.conf", "ENABLED=yes\n")
	s.write("/etc/ufw/user.rules", "-A ufw-user-input -p tcp --dport 22 -j ACCEPT\n")
	if err := withLock(func() error { return restoreCheckpoint(m, "undo") }); err != nil {
		t.Fatal(err)
	}
	if s.ufwState || s.read("/etc/ufw/ufw.conf") != "ENABLED=no\n" || s.read("/etc/ufw/user.rules") != "<missing>" {
		t.Fatalf("ufw not put back: active=%v", s.ufwState)
	}
}

func TestAllow(t *testing.T) {
	newSandbox(t)
	if l, _ := allowedSwitches(); len(l) != 0 {
		t.Fatal("allowed without allow.d")
	}
	var out, errb bytes.Buffer
	if code := dispatch([]string{"allow", "ssh.password_auth_on"}, &out, &errb); code != 1 {
		t.Fatal("allowed an unknown switch")
	}
	if code := dispatch([]string{"allow", "ssh.password_auth_off"}, &out, &errb); code != 0 {
		t.Fatalf("allow: %s", errb.String())
	}
	if !switchAllowed("ssh.password_auth_off") || switchAllowed("firewall.on_keep_ssh") {
		t.Fatal("allow list")
	}
	st, _ := os.Stat(rp(allowDir))
	if st.Mode().Perm() != 0o700 {
		t.Fatalf("allow.d mode %v", st.Mode())
	}
	// A directory others can write to counts for nothing.
	os.Chmod(rp(allowDir), 0o777)
	if switchAllowed("ssh.password_auth_off") {
		t.Fatal("world-writable allow.d counted")
	}
	os.Chmod(rp(allowDir), 0o700)
	out.Reset()
	dispatch([]string{"allowed"}, &out, &errb)
	if strings.TrimSpace(out.String()) != "ssh.password_auth_off" {
		t.Fatalf("allowed: %q", out.String())
	}
	dispatch([]string{"disallow", "ssh.password_auth_off"}, &out, &errb)
	if switchAllowed("ssh.password_auth_off") {
		t.Fatal("still allowed")
	}
}

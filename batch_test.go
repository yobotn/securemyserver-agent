package main

// One passkey tap for several switches (D-090), auto-confirm by a journal-attested login, and allow --all-safe.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// The same batch vector is checked in src/lib/switches/switches.test.ts.
const (
	batchVectorCanonical = `{"expires_at":"2026-11-08T10:10:00Z","issued_at":"2026-11-08T10:00:00Z","nonce":"AAAAAAAAAAAAAAAAAAAAAA","server_id":"00000000-0000-4000-8000-000000000001","switches":["ssh.max_auth_tries_3","ssh.password_auth_off"],"type":"switches","v":1}`
	batchVectorChallenge = "Zdy9vwiMxqFEXsnfHWPmqTw2bhS_O0Js_xFd3Dfw6Hs"
)

func TestBatchPolicyVector(t *testing.T) {
	p := Policy{V: 1, Type: "switches", ServerID: "00000000-0000-4000-8000-000000000001", Switches: []string{"ssh.max_auth_tries_3", "ssh.password_auth_off"},
		Nonce: "AAAAAAAAAAAAAAAAAAAAAA", IssuedAt: "2026-11-08T10:00:00Z", ExpiresAt: "2026-11-08T10:10:00Z"}
	c, err := canonicalPolicy(p)
	if err != nil || string(c) != batchVectorCanonical {
		t.Fatalf("canonical: %v\n%s", err, c)
	}
	sum := sha256.Sum256(c)
	if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != batchVectorChallenge {
		t.Fatalf("challenge %s", got)
	}
	if _, err := parsePolicy(batchVectorCanonical); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		strings.Replace(batchVectorCanonical, `"ssh.max_auth_tries_3","ssh.password_auth_off"`, `"ssh.password_auth_off","ssh.max_auth_tries_3"`, 1),  // not sorted
		strings.Replace(batchVectorCanonical, `"ssh.max_auth_tries_3","ssh.password_auth_off"`, `"ssh.password_auth_off","ssh.password_auth_off"`, 1), // twice
		strings.Replace(batchVectorCanonical, `"ssh.max_auth_tries_3","ssh.password_auth_off"`, `"ssh.password_auth_off"`, 1),                         // one is a switch policy
		strings.Replace(batchVectorCanonical, `"ssh.max_auth_tries_3"`, `"ssh.password_auth_on"`, 1),                                                  // unknown
		strings.Replace(batchVectorCanonical, `"switches":[`, `"switch":"ssh.root_login_off","switches":[`, 1),                                        // both
		strings.Replace(batchVectorCanonical, `"type":"switches"`, `"type":"switch"`, 1),                                                              // a switch policy with a list
		strings.Replace(batchVectorCanonical, `"switches":["ssh.max_auth_tries_3","ssh.password_auth_off"],`, `"switches":[],`, 1),                    // empty
		strings.Replace(batchVectorCanonical, `"ssh.max_auth_tries_3"`, `"x;rm -rf /"`, 1),                                                            // not canonical-safe
	} {
		if _, err := parsePolicy(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func batchPolicy(t *testing.T, now time.Time, names ...string) string {
	return testPolicy(t, "switches", "", now, func(p *Policy) { p.Switches = names })
}

func (s *switchSandbox) ops(t *testing.T, pol string) map[string]SwitchOp {
	t.Helper()
	n := nonceOf(t, pol)
	out := map[string]SwitchOp{}
	for _, o := range loadEngineState().Ops {
		if o.Nonce == n {
			out[o.Switch] = o
		}
	}
	return out
}

var sshBatch = []string{"ssh.max_auth_tries_3", "ssh.password_auth_off", "ssh.root_login_off"}

func TestBatchAppliesEachWithItsOwnCheckpointAndOneLoginKeepsAll(t *testing.T) {
	s := newSwitchSandbox(t)
	for _, n := range sshBatch {
		_ = allowSwitch(n)
	}
	pol := batchPolicy(t, s.now, sshBatch...)
	s.send(t, pol)
	ops := s.ops(t, pol)
	if len(ops) != 3 {
		t.Fatalf("ops %+v", ops)
	}
	seen := map[string]bool{}
	for _, n := range sshBatch {
		o := ops[n]
		if o.State != opApplied || o.Checkpoint == "" || o.Batch != 3 || seen[o.Checkpoint] || o.Deadline != ops[sshBatch[0]].Deadline {
			t.Fatalf("%s: %+v", n, o)
		}
		seen[o.Checkpoint] = true
		if len(o.Steps) == 0 || o.Steps[0].Name != "pre-checks" || !o.Steps[0].OK {
			t.Fatalf("%s ran no pre-checks of its own: %+v", n, o.Steps)
		}
	}
	got := s.read(sshDropIn)
	for _, want := range []string{"MaxAuthTries 3", "PasswordAuthentication no", "PermitRootLogin no"} {
		if !strings.Contains(got, want) {
			t.Fatalf("drop-in %q lacks %s", got, want)
		}
	}
	if s.reloads != 3 {
		t.Fatalf("reloads %d", s.reloads)
	}
	// The batch is one signed change: the next one waits.
	_ = allowSwitch("updates.unattended_on")
	next := testPolicy(t, "switch", "updates.unattended_on", s.now, nil)
	s.send(t, next)
	if o := s.ops(t, next)["updates.unattended_on"]; o.State != opRefused || !strings.Contains(o.Reason, "10 minutes") {
		t.Fatalf("rate limit: %+v", o)
	}

	// A login auth.log reports (unverified) does not confirm; the journal-attested one keeps all three.
	s.unverified = true
	s.logins = []AuthEvent{{TS: s.now.Add(time.Second).Format(time.RFC3339Nano), Result: "ok", Method: "publickey", User: "deploy", IP: "203.0.113.5"}}
	s.now = s.now.Add(2 * time.Second)
	tickSwitches()
	if o := s.ops(t, pol)["ssh.root_login_off"]; o.State != opApplied {
		t.Fatalf("an unverified login confirmed: %+v", o)
	}
	s.unverified = false
	tickSwitches()
	for n, o := range s.ops(t, pol) {
		if o.State != opConfirmed || o.Proof != proofLogin || !strings.Contains(o.Reason, "deploy from 203.0.113.5") {
			t.Fatalf("%s: %+v", n, o)
		}
	}
	s.now = s.now.Add(time.Hour)
	tickSwitches()
	if !strings.Contains(s.read(sshDropIn), "PermitRootLogin no") {
		t.Fatal("a confirmed batch was rolled back")
	}
}

func TestBatchFailureRollsBackOnlyThatSwitch(t *testing.T) {
	s := newSwitchSandbox(t)
	for _, n := range sshBatch {
		_ = allowSwitch(n)
	}
	// root_login_off runs second (batchOrder); its verify fails, the ones before and after it stay.
	sshBannerOK = func(map[string]string) error {
		if strings.Contains(s.read(sshDropIn), "PermitRootLogin") {
			return errors.New("sshd does not answer")
		}
		return nil
	}
	pol := batchPolicy(t, s.now, sshBatch...)
	s.send(t, pol)
	ops := s.ops(t, pol)
	if o := ops["ssh.root_login_off"]; o.State != opRolledBack || !strings.Contains(o.Reason, "sshd does not answer") {
		t.Fatalf("root: %+v", o)
	}
	for _, n := range []string{"ssh.max_auth_tries_3", "ssh.password_auth_off"} {
		if ops[n].State != opApplied {
			t.Fatalf("%s: %+v", n, ops[n])
		}
	}
	got := s.read(sshDropIn)
	if !strings.Contains(got, "MaxAuthTries 3") || !strings.Contains(got, "PasswordAuthentication no") || strings.Contains(got, "PermitRootLogin") {
		t.Fatalf("drop-in %q", got)
	}
	// Your signed confirm for one switch keeps the whole batch.
	confirm := testPolicy(t, "confirm", "ssh.password_auth_off", s.now, func(p *Policy) { p.Confirms = nonceOf(t, pol) })
	s.send(t, confirm)
	ops = s.ops(t, pol)
	for _, n := range []string{"ssh.max_auth_tries_3", "ssh.password_auth_off"} {
		if ops[n].State != opConfirmed || ops[n].Proof != proofOwner {
			t.Fatalf("%s: %+v", n, ops[n])
		}
	}
	if ops["ssh.root_login_off"].State != opRolledBack {
		t.Fatal("the confirm touched the rolled back switch")
	}
	if pendingCheckpoint() != nil {
		t.Fatal("a batch checkpoint still waits after the confirm")
	}
}

func TestBatchRollsBackEverythingAtTheDeadline(t *testing.T) {
	s := newSwitchSandbox(t)
	for _, n := range sshBatch {
		_ = allowSwitch(n)
	}
	// Not allowed: refused on its own, the others run.
	pol := batchPolicy(t, s.now, append([]string{"firewall.on_keep_ssh"}, sshBatch...)...)
	s.send(t, pol)
	ops := s.ops(t, pol)
	if o := ops["firewall.on_keep_ssh"]; o.State != opRefused || !strings.Contains(o.Reason, "allow firewall.on_keep_ssh") {
		t.Fatalf("firewall: %+v", o)
	}
	if ops["ssh.root_login_off"].State != opApplied {
		t.Fatalf("%+v", ops)
	}
	s.now = s.now.Add(switchWindow)
	tickSwitches()
	for _, n := range sshBatch {
		if o := s.ops(t, pol)[n]; o.State != opRolledBack {
			t.Fatalf("%s: %+v", n, o)
		}
	}
	if got := s.read(sshDropIn); got != "<missing>" {
		t.Fatalf("not everything was put back: %q", got)
	}
	for _, m := range listCheckpoints() {
		if m.Status != cpRestored {
			t.Fatalf("checkpoint %s is %s", m.ID, m.Status)
		}
	}
}

func TestBatchCheckpointsRestoreInOrderByHand(t *testing.T) {
	s := newSwitchSandbox(t)
	for _, n := range sshBatch {
		_ = allowSwitch(n)
	}
	s.send(t, batchPolicy(t, s.now, sshBatch...))
	all := listCheckpoints()
	if len(all) != 3 || all[0].Seq != 0 || all[2].Seq != 2 || all[0].Batch == "" {
		t.Fatalf("checkpoints %+v", all)
	}
	// Restoring the first one restores the two stacked on it first, so nothing from the batch is left.
	_ = withLock(func() error { return restoreCheckpoint(all[0], "undo") })
	if got := s.read(sshDropIn); got != "<missing>" {
		t.Fatalf("drop-in %q", got)
	}
	// The deadline timer of the last one then finds nothing to do and changes nothing.
	s.now = s.now.Add(switchWindow)
	_ = withLock(func() error { enforceDeadlines(s.now); return nil })
	if got := s.read(sshDropIn); got != "<missing>" {
		t.Fatalf("a later restore put a batch change back: %q", got)
	}
}

func TestNoJournalWaitsForYourConfirm(t *testing.T) {
	s := newSwitchSandbox(t)
	s.unverified = true
	_ = allowSwitch("ssh.max_auth_tries_3")
	pol := testPolicy(t, "switch", "ssh.max_auth_tries_3", s.now, nil)
	s.send(t, pol)
	if o := s.lastOp(); o.State != opApplied || !strings.Contains(o.Reason, "no systemd journal") {
		t.Fatalf("%+v", o)
	}
	s.logins = []AuthEvent{{TS: s.now.Add(time.Second).Format(time.RFC3339Nano), Result: "ok", Method: "publickey", User: "deploy", IP: "203.0.113.5"}}
	s.now = s.now.Add(switchWindow)
	tickSwitches()
	if o := s.lastOp(); o.State != opRolledBack {
		t.Fatalf("an auth.log line kept the change: %+v", o)
	}
}

func TestAllowAllSafe(t *testing.T) {
	newSandbox(t)
	var out, errb bytes.Buffer
	if code := cmdAllow("allow", []string{"--all-safe"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	got, err := allowedSwitches()
	if err != nil || strings.Join(got, " ") != strings.Join(sortedCopy(switchNames), " ") {
		t.Fatalf("allowed %v %v", got, err)
	}
	if blocklistAllowed() || allowedName(sessionUndoAllow) {
		t.Fatal("--all-safe allowed more than the switches")
	}
	if !strings.Contains(out.String(), "still needs your passkey") {
		t.Fatalf("output %q", out.String())
	}
	// With the blocklist in the same line; a typo changes nothing.
	if code := cmdAllow("allow", []string{"--all-safe", "blocklist"}, &out, &errb); code != 0 || !blocklistAllowed() {
		t.Fatalf("blocklist: %d", code)
	}
	if code := cmdAllow("disallow", []string{"--all-safe", "typo"}, &out, &errb); code != 1 {
		t.Fatalf("typo: %d", code)
	}
	if got, _ := allowedSwitches(); len(got) != len(switchNames) {
		t.Fatal("a typo disallowed some")
	}
	if code := cmdAllow("disallow", []string{"--all-safe"}, &out, &errb); code != 0 {
		t.Fatalf("disallow: %d", code)
	}
	if got, _ := allowedSwitches(); len(got) != 0 || !blocklistAllowed() {
		t.Fatalf("after disallow: %v", got)
	}
}

func sortedCopy(in []string) []string {
	out := append([]string{}, in...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

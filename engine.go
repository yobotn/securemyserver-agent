package main

// The switch engine: takes signed envelopes from the report reply, verifies them itself, and runs a switch with
// its checkpoint, or confirms one, or updates the pinned keys. Every result goes into the next report.
// State (used nonces, sign counters, the rate limit, recent ops) is kept in /var/lib/securemyserver/switches.json.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
)

const (
	opApplied    = "applied"
	opConfirmed  = "confirmed"
	opRolledBack = "rolled_back"
	opRefused    = "refused"

	proofLogin    = "login"
	proofOwner    = "owner"
	proofServer   = "server"
	proofVerified = "verified"

	keepOps        = 20
	keepRefusals   = 20
	keepNonces     = 24 * time.Hour
	maxEnvelopes   = 5
	keysUpdateName = "keys.update"
)

type engineState struct {
	Nonces       map[string]time.Time `json:"nonces"`   // policy nonce -> when it was used
	Counters     map[string]uint32    `json:"counters"` // credential id -> highest sign counter seen
	LastSwitchAt time.Time            `json:"last_switch_at"`
	Ops          []SwitchOp           `json:"ops"`
	Refused      []Refusal            `json:"refused"`
	Keys         *pinnedSet           `json:"keys,omitempty"`
}

// pinnedSet is a key set installed by a signed keys policy. It only counts while agent.conf still has the
// owner_key lines it was derived from: root editing agent.conf by hand always wins.
type pinnedSet struct {
	BaseHash  string      `json:"base_hash"`
	Keys      []PolicyKey `json:"keys"`
	UpdatedAt time.Time   `json:"updated_at"`
}

func confKeysHash(keys []OwnerKey) string {
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k.ID + " " + k.SPKI + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func loadEngineState() *engineState {
	st := &engineState{}
	_ = readJSON(rp(switchState), st)
	if st.Nonces == nil {
		st.Nonces = map[string]time.Time{}
	}
	if st.Counters == nil {
		st.Counters = map[string]uint32{}
	}
	return st
}

func (st *engineState) save() {
	if err := writeJSON(rp(switchState), st); err != nil {
		log.Printf("switches: save state: %v", err)
	}
}

// pinnedKeys is the key set policies are checked against.
func (st *engineState) pinnedKeys(cfg Config) []OwnerKey {
	if st.Keys == nil || st.Keys.BaseHash != confKeysHash(cfg.OwnerKeys) {
		return cfg.OwnerKeys
	}
	var out []OwnerKey
	for _, k := range st.Keys.Keys {
		if ok, err := parseOwnerKey(k.ID, k.SPKI); err == nil {
			out = append(out, ok)
		}
	}
	return out
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func (st *engineState) refuse(nonce, reason string, now time.Time) {
	if nonce != "" {
		log.Printf("switches: refused %s: %s", nonce, reason)
	} else {
		log.Printf("switches: refused: %s", reason)
	}
	st.Refused = append(st.Refused, Refusal{Nonce: nonce, Reason: trim(reason, 300), At: stamp(now)})
	if len(st.Refused) > keepRefusals {
		st.Refused = st.Refused[len(st.Refused)-keepRefusals:]
	}
}

func (st *engineState) op(nonce string) *SwitchOp {
	for i := range st.Ops {
		if st.Ops[i].Nonce == nonce {
			return &st.Ops[i]
		}
	}
	return nil
}

// opFor is the op for one switch of a policy: a batch has one op per switch under the same nonce.
func (st *engineState) opFor(nonce, sw string) *SwitchOp {
	for i := range st.Ops {
		if st.Ops[i].Nonce == nonce && st.Ops[i].Switch == sw {
			return &st.Ops[i]
		}
	}
	return nil
}

// setOp replaces the op for (nonce, switch), or adds it.
func (st *engineState) setOp(o SwitchOp) {
	if old := st.opFor(o.Nonce, o.Switch); old != nil {
		*old = o
		return
	}
	st.addOp(o)
}

func (st *engineState) addOp(o SwitchOp) {
	st.Ops = append(st.Ops, o)
	if len(st.Ops) > keepOps {
		st.Ops = st.Ops[len(st.Ops)-keepOps:]
	}
}

// processEnvelopes handles the envelopes from one report reply. It returns true when something changed that
// the platform should hear about right away.
func processEnvelopes(cfg Config, envs []Envelope) bool {
	if len(envs) == 0 {
		return false
	}
	if off := cfg.switchesOff(); off != "" {
		log.Printf("switches: ignoring %d signed policies: %s", len(envs), off)
		return false
	}
	if len(envs) > maxEnvelopes {
		envs = envs[:maxEnvelopes]
	}
	changed := false
	err := withLock(func() error {
		st := loadEngineState()
		defer st.save()
		for _, env := range envs {
			processOne(cfg, st, env)
			changed = true
		}
		return nil
	})
	if err != nil {
		log.Printf("switches: %v", err)
	}
	return changed
}

func processOne(cfg Config, st *engineState, env Envelope) {
	now := nowFn()
	v, err := verifyEnvelope(env, verifyParams{Keys: st.pinnedKeys(cfg), Origin: cfg.Origin, RPID: cfg.RPID, ServerID: cfg.ServerID, Now: now})
	if err != nil {
		nonce := ""
		if re, ok := err.(*RefusedError); ok {
			nonce = re.Nonce
		}
		st.refuse(nonce, err.Error(), now)
		// A signed request that names an op we never ran is shown on that op, so the owner sees why.
		if nonce != "" && st.op(nonce) == nil && st.Nonces[nonce].IsZero() {
			if p, perr := parsePolicy(env.Policy); perr == nil && (p.Type == "switch" || p.Type == "switches") {
				for _, n := range policySwitches(p) {
					st.addOp(SwitchOp{Nonce: nonce, Switch: n, State: opRefused, Reason: err.Error(), At: stamp(now), Batch: batchSize(p), Steps: []SwitchStep{}})
				}
			}
		}
		return
	}
	pol := v.Policy
	// (f) Each nonce works once.
	if !st.Nonces[pol.Nonce].IsZero() {
		st.refuse(pol.Nonce, "replayed: this signed request was already used", now)
		return
	}
	last := st.Counters[v.Key.ID]
	if (v.Counter != 0 || last != 0) && v.Counter <= last {
		st.refuse(pol.Nonce, fmt.Sprintf("the passkey's sign counter did not go up (%d after %d): a cloned passkey?", v.Counter, last), now)
		return
	}
	// Used from here on, whatever happens next, so a crash mid-switch can't make it usable again.
	st.Nonces[pol.Nonce] = now
	st.Counters[v.Key.ID] = v.Counter
	for n, t := range st.Nonces {
		if now.Sub(t) > keepNonces {
			delete(st.Nonces, n)
		}
	}
	st.save()

	switch pol.Type {
	case "switch":
		st.setOp(runSwitch(st, pol, now)) // replaces an earlier, refused copy of this request
	case "switches":
		runBatch(st, pol, now)
	case "confirm":
		if pol.Switch == sessionUndoSwitch {
			undoSession(st, pol, now)
		} else {
			confirmOp(st, pol, now)
		}
	case "keys":
		updateKeys(cfg, st, pol, now)
	}
}

// policySwitches is what a switch or switches policy turns on.
func policySwitches(p Policy) []string {
	if p.Type == "switches" {
		return p.Switches
	}
	return []string{p.Switch}
}

func batchSize(p Policy) int {
	if p.Type == "switches" {
		return len(p.Switches)
	}
	return 0
}

// batchOrder is the order a batch runs in: switches that need no login first (an apt run can take a while and
// must not eat the login window), then SSH, then the firewall last.
var batchOrder = []string{
	"updates.unattended_on",
	"updates.security_now",
	"ssh.max_auth_tries_3",
	"ssh.root_login_off",
	"ssh.password_auth_off",
	"firewall.on_keep_ssh",
}

// rateCheck is the shared gate for a signed change: one per 10 minutes (a batch counts as one), and no other
// checkpoint waiting. It returns the refusal reason, or "".
func rateCheck(st *engineState, now time.Time) string {
	if next := st.LastSwitchAt.Add(switchRate); now.Before(next) {
		return "one signed change per 10 minutes on this server; try again after " + next.UTC().Format("15:04 UTC")
	}
	if p := pendingCheckpoint(); p != nil {
		return "checkpoint " + p.ID + " is still waiting for a confirm; confirm or undo it first"
	}
	return ""
}

// runBatch runs a switches policy (D-090): one passkey tap, but every switch still has its own allow, pre-checks,
// checkpoint, change and verify. A switch that fails puts back only its own checkpoint; the others carry on.
// The ones that need a login share one deadline, and one new login (or your confirm) keeps them all.
func runBatch(st *engineState, pol Policy, now time.Time) {
	var names []string
	for _, n := range batchOrder {
		if has(pol.Switches, n) {
			names = append(names, n)
		}
	}
	if why := rateCheck(st, now); why != "" {
		for _, n := range names {
			st.setOp(SwitchOp{Nonce: pol.Nonce, Switch: n, State: opRefused, Reason: why, At: stamp(now), Batch: len(names), Steps: []SwitchStep{}})
		}
		log.Printf("switches: batch of %d refused: %s", len(names), why)
		return
	}
	st.LastSwitchAt = now
	for _, n := range names {
		one := pol
		one.Type, one.Switch, one.Switches = "switch", n, nil
		op := runOne(st, one, nowFn(), pol.Nonce)
		op.Batch = len(names)
		st.setOp(op)
		st.save()
	}
}

func runSwitch(st *engineState, pol Policy, now time.Time) SwitchOp {
	return runOne(st, pol, now, "")
}

// runOne runs one switch. batch is the policy nonce when it is part of a batch (the rate check was done once for
// the whole batch), else "".
func runOne(st *engineState, pol Policy, now time.Time, batch string) SwitchOp {
	op := SwitchOp{Nonce: pol.Nonce, Switch: pol.Switch, At: stamp(now), Steps: []SwitchStep{}}
	refused := func(reason string) SwitchOp {
		op.State, op.Reason = opRefused, reason
		log.Printf("switches: %s refused: %s", pol.Switch, reason)
		return op
	}
	// (g) The second key: allowed on this server by root.
	if !switchAllowed(pol.Switch) {
		return refused("not allowed on this server. Run: sudo securemyserver allow " + pol.Switch)
	}
	// (h) One signed change per 10 minutes.
	if batch == "" {
		if why := rateCheck(st, now); why != "" {
			return refused(why)
		}
	}
	l := &opLog{}
	plan, err := planSwitch(pol.Switch, now)
	if err != nil {
		l.add("pre-checks", err, "")
		op.Steps = l.steps
		return refused(err.Error())
	}
	l.add("pre-checks", nil, plan.summary)
	m, err := createBatchCheckpoint(plan.targets, switchWindow, "switch "+pol.Switch, batch)
	if err != nil {
		l.add("checkpoint", err, "")
		op.Steps = l.steps
		return refused("could not save a checkpoint: " + err.Error())
	}
	if batch == "" {
		st.LastSwitchAt = now
	}
	op.Checkpoint, op.NeedsLogin = m.ID, plan.needsLogin
	l.add("checkpoint", nil, m.ID+", restores at "+m.Deadline.Format("15:04:05 UTC")+" unless confirmed")
	rollback := func(why string) SwitchOp {
		if err := restoreCheckpoint(m, why); err != nil {
			l.add("restore", err, "")
			why += "; the restore failed too: " + err.Error()
		} else {
			l.add("restore", nil, "checkpoint "+m.ID+" put back")
		}
		op.State, op.Reason, op.Steps, op.At = opRolledBack, why, l.steps, stamp(nowFn())
		log.Printf("switches: %s rolled back: %s", pol.Switch, why)
		return op
	}
	if err := plan.apply(l); err != nil {
		return rollback("the change failed: " + err.Error())
	}
	if err := plan.verify(l); err != nil {
		return rollback("the check after the change failed: " + err.Error())
	}
	op.AppliedAt, op.Steps = stamp(nowFn()), l.steps
	if plan.needsLogin {
		op.State, op.Deadline = opApplied, stamp(m.Deadline)
		op.Reason = "applied (" + plan.summary + "). Waiting for a new SSH key login, or your confirm, before " + m.Deadline.Format("15:04 UTC")
		if !loginsVerifiable() {
			op.Reason = "applied (" + plan.summary + "). This server has no systemd journal, so a login can't be proven: confirm in the dashboard, or run sudo securemyserver confirm from a new SSH session, before " + m.Deadline.Format("15:04 UTC")
		}
		log.Printf("switches: %s applied (%s); waiting for a new key login until %s", pol.Switch, plan.summary, stamp(m.Deadline))
		return op
	}
	if batch == "" {
		_ = confirmCheckpoint(m, "switch "+pol.Switch+" verified")
	} else {
		setStatus(m, cpConfirmed, "switch "+pol.Switch+" verified") // only this one, not the batch
		if m.Timer != "" {
			stopTimer(m.Timer)
		}
	}
	op.State, op.Reason, op.Proof = opConfirmed, "applied and verified ("+plan.summary+")", proofVerified
	log.Printf("switches: %s applied and verified", pol.Switch)
	return op
}

func confirmOp(st *engineState, pol Policy, now time.Time) {
	o := st.opFor(pol.Confirms, pol.Switch)
	if o == nil || o.State != opApplied {
		state := "unknown"
		if o != nil {
			state = o.State
		}
		st.refuse(pol.Nonce, fmt.Sprintf("nothing to confirm: %s is %s", pol.Switch, state), now)
		return
	}
	m, err := loadManifest(o.Checkpoint)
	if err == nil {
		err = confirmCheckpoint(m, "confirmed by the owner in the dashboard")
	}
	if err != nil {
		st.refuse(pol.Nonce, "confirm failed: "+err.Error(), now)
		return
	}
	// The confirm keeps the whole batch, the way the checkpoint confirm did.
	for i := range st.Ops {
		b := &st.Ops[i]
		if b.Nonce == pol.Confirms && b.State == opApplied {
			b.State, b.Reason, b.At, b.Proof = opConfirmed, "confirmed by you in the dashboard (passkey)", stamp(now), proofOwner
			log.Printf("switches: %s confirmed by the owner", b.Switch)
		}
	}
}

func updateKeys(cfg Config, st *engineState, pol Policy, now time.Time) {
	for _, k := range pol.Keys {
		if _, err := parseOwnerKey(k.ID, k.SPKI); err != nil {
			st.refuse(pol.Nonce, "key update has a key this agent can't use: "+err.Error(), now)
			return
		}
	}
	keys := append([]PolicyKey{}, pol.Keys...)
	sort.Slice(keys, func(i, j int) bool { return keys[i].ID < keys[j].ID })
	st.Keys = &pinnedSet{BaseHash: confKeysHash(cfg.OwnerKeys), Keys: keys, UpdatedAt: now.UTC()}
	st.addOp(SwitchOp{Nonce: pol.Nonce, Switch: keysUpdateName, State: opConfirmed, At: stamp(now),
		Reason: fmt.Sprintf("pinned keys updated: %d passkey(s)", len(keys)), Steps: []SwitchStep{}})
	log.Printf("switches: pinned keys updated (%d)", len(keys))
}

// authSince is how the tick looks for a new login: the events, and whether the journal attests them (D-069).
// A variable for tests.
var authSince = func(since time.Time) ([]AuthEvent, bool) {
	a, _ := collectAuth(since)
	return a.Events, a.Verified
}

// loginsVerifiable: this server has a running journal, so a new login can confirm a switch on its own.
var loginsVerifiable = journalRunning

// tickSwitches follows applied switches: confirm on a new key login, roll back at the deadline, and pick up
// what `securemyserver confirm` or `undo` did by hand. Then any pending checkpoint past its deadline is restored.
func tickSwitches() bool {
	changed := false
	err := withLock(func() error {
		st := loadEngineState()
		now := nowFn()
		for i := range st.Ops {
			o := &st.Ops[i]
			if o.State != opApplied || o.Checkpoint == "" {
				continue
			}
			m, err := loadManifest(o.Checkpoint)
			if err != nil {
				continue
			}
			switch m.Status {
			case cpConfirmed:
				o.State, o.Reason, o.At, o.Proof, changed = opConfirmed, "confirmed on the server ("+m.StatusNote+")", stamp(now), proofServer, true
				if strings.HasPrefix(m.StatusNote, loginNote) { // a batch mate's login confirmed this one too
					o.Reason, o.Proof = "confirmed: a new SSH key login worked after the change ("+strings.TrimPrefix(m.StatusNote, loginNote)+")", proofLogin
				}
				continue
			case cpRestored, cpRestoreFailed:
				o.State, o.Reason, o.At, changed = opRolledBack, "restored on the server: "+m.StatusNote, stamp(now), true
				continue
			}
			applied, _ := time.Parse(time.RFC3339, o.AppliedAt)
			if o.NeedsLogin && !applied.IsZero() {
				events, verified := authSince(applied.Add(-time.Second))
				// Only a login the journal attests confirms on its own: any local user can write auth.log lines.
				if who := newKeyLogin(events, applied); who != "" && verified {
					if err := confirmCheckpoint(m, loginNote+who); err == nil {
						o.State, o.At, o.Proof, changed = opConfirmed, stamp(now), proofLogin, true
						o.Reason = "confirmed: a new SSH key login worked after the change (" + who + ")"
						log.Printf("switches: %s confirmed by a new key login (%s)", o.Switch, who)
					}
					continue
				}
			}
			if !now.Before(m.Deadline) {
				why := "no new SSH key login within 10 minutes, so the change was rolled back"
				if err := restoreCheckpoint(m, why); err != nil {
					why = "the deadline passed, but the restore failed: " + err.Error()
				}
				o.State, o.Reason, o.At, changed = opRolledBack, why, stamp(now), true
				log.Printf("switches: %s: %s", o.Switch, why)
			}
		}
		if changed {
			st.save()
		}
		enforceDeadlines(now)
		closeIdleSessions(now)
		return nil
	})
	if err != nil {
		log.Printf("switches: %v", err)
	}
	return changed
}

// loginNote starts the checkpoint note when a new login confirmed it, so batch mates show the same proof.
const loginNote = "a new key login after the change: "

// newKeyLogin finds a successful public key login after t. It returns "user from ip", or "".
func newKeyLogin(events []AuthEvent, t time.Time) string {
	for _, e := range events {
		ts, err := time.Parse(time.RFC3339Nano, e.TS)
		if err != nil || !ts.After(t) || e.Result != "ok" || e.Method != "publickey" {
			continue
		}
		return e.User + " from " + e.IP
	}
	return ""
}

// switchesReport is the switches part of the next report.
func switchesReport(cfg Config) *Switches {
	sw := &Switches{Allowed: []string{}, OwnerKeys: []string{}, Seen: []string{}, Ops: []SwitchOp{}, Refused: []Refusal{}}
	sw.Allowed, _ = allowedSwitches()
	if sw.Allowed == nil {
		sw.Allowed = []string{}
	}
	sw.Off = cfg.switchesOff()
	sw.Enabled = sw.Off == ""
	_ = withLock(func() error {
		st := loadEngineState()
		for _, k := range st.pinnedKeys(cfg) {
			sw.OwnerKeys = append(sw.OwnerKeys, k.ID)
		}
		for n := range st.Nonces {
			sw.Seen = append(sw.Seen, n)
		}
		sort.Strings(sw.Seen)
		ops := st.Ops
		if len(ops) > 10 {
			ops = ops[len(ops)-10:]
		}
		sw.Ops = append(sw.Ops, ops...)
		ref := st.Refused
		if len(ref) > 10 {
			ref = ref[len(ref)-10:]
		}
		sw.Refused = append(sw.Refused, ref...)
		if p := pendingCheckpoint(); p != nil {
			sw.Checkpoint = &CheckpointInfo{ID: p.ID, Deadline: stamp(p.Deadline), Targets: p.Targets, Reason: p.Reason}
		}
		return nil
	})
	return sw
}

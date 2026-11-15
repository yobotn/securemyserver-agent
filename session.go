package main

// AI session checkpoints (D-015, gap 10). securemyserver-gate runs, as the securemyserver-ai user,
//
//	sudo -n /usr/local/sbin/securemyserver checkpoint --session <gate session id> --auto
//
// before every command that uses sudo. Through a sudoers rule that allows only that command form, this saves a
// checkpoint of a fixed list of targets the first time, and only records the activity after that. If it cannot be
// saved, the gate refuses the command (fail closed).
//
// An AI session is the run of sudo commands with less than 15 minutes between them, across SSH connections. It has
// no deadline and never restores itself. When it ends (15 minutes idle) the agent freezes its diff; while it is open
// the diff is live. The owner can undo the newest session within 24 hours with a passkey-signed policy
// {type: confirm, switch: session.undo, confirms: <checkpoint id>}, and only after root ran
// `securemyserver allow session-undo`. The restore validates (sshd -t, visudo -c) before anything is reloaded.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const (
	cpKindSession   = "session"
	cpSessionOpen   = "open"
	cpSessionClosed = "closed"

	sessionUndoAllow  = "session-undo" // `securemyserver allow session-undo`: the server-side key
	sessionUndoSwitch = "session.undo" // the switch name in the signed confirm policy

	maxSessionLinks    = 50
	reportSessions     = 5
	reportSessionsBack = 48 * time.Hour
)

var (
	sessionIdle       = 15 * time.Minute
	sessionUndoWindow = 24 * time.Hour
	gateSessionRE     = regexp.MustCompile(`^[0-9a-f]{16}$`)
	// haveNft: the session checkpoint saves the live ruleset only where nft is installed.
	haveNft = func() bool { _, err := lookPath("nft"); return err == nil }
)

// sessionTargets is the fixed list an AI session checkpoint saves.
func sessionTargets() []string {
	t := []string{"sshdir", "ufw"}
	if haveNft() {
		t = append(t, "nft")
	}
	return append(t, "apt", "apt-sources", "sudoers", "systemd")
}

// sessionCheckpoints lists the AI session checkpoints, oldest first.
func sessionCheckpoints() []*Manifest {
	var out []*Manifest
	for _, m := range listCheckpoints() {
		if m.Kind == cpKindSession {
			out = append(out, m)
		}
	}
	return out
}

func latestSession() *Manifest {
	all := sessionCheckpoints()
	if len(all) == 0 {
		return nil
	}
	return all[len(all)-1]
}

// touchSession is `checkpoint --session <id> --auto`. Call with the lock held. created: a new checkpoint was saved.
func touchSession(gateSession string) (m *Manifest, created bool, err error) {
	if !gateSessionRE.MatchString(gateSession) {
		return nil, false, errors.New("--session must be the 16 hex characters securemyserver-gate uses")
	}
	now := nowFn()
	if last := latestSession(); last != nil && last.Status == cpSessionOpen {
		if now.Sub(last.LastActivity) < sessionIdle {
			if !has(last.AISessions, gateSession) && len(last.AISessions) < maxSessionLinks {
				last.AISessions = append(last.AISessions, gateSession)
			}
			last.LastActivity = now.UTC()
			if err := saveManifest(last); err != nil {
				return nil, false, err
			}
			return last, false, nil
		}
		closeSession(last) // idle: this is a new session
	}
	m, err = createSessionCheckpoint(gateSession, now)
	return m, err == nil, err
}

func createSessionCheckpoint(gateSession string, now time.Time) (*Manifest, error) {
	m := &Manifest{
		ID:           newCheckpointID(now),
		CreatedAt:    now.UTC(),
		Targets:      sessionTargets(),
		Reason:       "before the first sudo of AI session " + gateSession,
		Session:      auditSession(),
		Status:       cpSessionOpen,
		StatusAt:     now.UTC(),
		Kind:         cpKindSession,
		AISessions:   []string{gateSession},
		LastActivity: now.UTC(),
	}
	dir := cpPath(m.ID)
	if err := os.MkdirAll(rp(checkpointDir), 0o700); err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	fail := func(err error) (*Manifest, error) {
		os.RemoveAll(dir)
		return nil, err
	}
	entries, err := snapshot(filepath.Join(dir, "files"), rootsOf(m.Targets))
	if err != nil {
		return fail(err)
	}
	m.Entries = entries
	active := ufwIsActive()
	m.UFWActive = &active
	if has(m.Targets, "nft") {
		out, err := nftList()
		if err != nil {
			return fail(fmt.Errorf("nft list ruleset: %w", err))
		}
		if err := writeFileAtomic(filepath.Join(dir, "nft-ruleset.nft"), out, 0o600); err != nil {
			return fail(err)
		}
		sum := sha256.Sum256(out)
		m.NftSHA256 = hex.EncodeToString(sum[:])
	}
	if err := saveManifest(m); err != nil {
		return fail(err)
	}
	pruneCheckpoints()
	return m, nil
}

/* ---------- The diff: live while the session is open, frozen when it ends ---------- */

type sessionDiff struct {
	Files     []FileChange `json:"files"`
	Truncated bool         `json:"truncated"`
}

func diffFile(m *Manifest) string { return filepath.Join(cpPath(m.ID), "diff.json") }

func diffSHA(d sessionDiff) string {
	b, _ := json.Marshal(d)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// freezeSession computes the diff and the after state and stores them with the checkpoint.
func freezeSession(m *Manifest) error {
	files, truncated, err := checkpointDiff(m)
	if err != nil {
		return err
	}
	state, err := stateDigest(m)
	if err != nil {
		return err
	}
	d := sessionDiff{Files: files, Truncated: truncated}
	if d.Files == nil {
		d.Files = []FileChange{}
	}
	if err := writeJSON(diffFile(m), d); err != nil {
		return err
	}
	m.AfterState, m.DiffSHA256 = state, diffSHA(d)
	return nil
}

// closeSession ends an open session: its diff is frozen. Call with the lock held.
func closeSession(m *Manifest) {
	if m.Status != cpSessionOpen {
		return
	}
	if err := freezeSession(m); err != nil {
		log.Printf("checkpoint %s: could not freeze the session diff: %v", m.ID, err)
	}
	m.ClosedAt = m.LastActivity.Add(sessionIdle).UTC()
	if now := nowFn().UTC(); m.ClosedAt.After(now) {
		m.ClosedAt = now
	}
	setStatus(m, cpSessionClosed, "the AI session ended (15 minutes without a sudo command)")
}

// closeIdleSessions closes every open session with no sudo for 15 minutes. Call with the lock held.
func closeIdleSessions(now time.Time) {
	for _, m := range sessionCheckpoints() {
		if m.Status == cpSessionOpen && now.Sub(m.LastActivity) >= sessionIdle {
			closeSession(m)
		}
	}
}

// diffOf is the session's diff: frozen once it ended, live while it is open.
func diffOf(m *Manifest) (sessionDiff, error) {
	if m.Status != cpSessionOpen {
		var d sessionDiff
		if err := readJSON(diffFile(m), &d); err != nil {
			return sessionDiff{Files: []FileChange{}}, err
		}
		return d, nil
	}
	files, truncated, err := checkpointDiff(m)
	if files == nil {
		files = []FileChange{}
	}
	return sessionDiff{Files: files, Truncated: truncated}, err
}

// undoUntil is when the owner can no longer undo m: never after the next session starts, or 24 hours after the
// session's last sudo command. Zero: not undoable.
func undoUntil(m *Manifest, latest *Manifest) time.Time {
	if latest == nil || latest.ID != m.ID || (m.Status != cpSessionOpen && m.Status != cpSessionClosed) {
		return time.Time{}
	}
	return m.LastActivity.Add(sessionUndoWindow).UTC()
}

/* ---------- The report ---------- */

// AISessionCheckpoint is one AI session's checkpoint and what changed since, in the report.
type AISessionCheckpoint struct {
	ID           string        `json:"id"`                   // the checkpoint id
	Sessions     []string      `json:"sessions"`             // the securemyserver-gate session ids it covers
	CreatedAt    string        `json:"created_at"`           // before the first sudo
	LastActivity string        `json:"last_activity"`        // the last sudo command
	State        string        `json:"state"`                // open | closed | restored | restore_failed
	StateNote    string        `json:"state_note,omitempty"` // what the restore checked, or why it failed
	StateAt      string        `json:"state_at"`
	UndoUntil    string        `json:"undo_until,omitempty"` // empty: can't be undone from the dashboard (any more)
	UndoAllowed  bool          `json:"undo_allowed"`         // root ran `securemyserver allow session-undo`
	Targets      []string      `json:"targets"`              // what the checkpoint saved, from a fixed list
	DiffSHA256   string        `json:"diff_sha256"`
	Files        *[]FileChange `json:"files,omitempty"` // left out when the platform already has this diff
	Truncated    bool          `json:"truncated"`
}

// sessionsReport is the ai_sessions part of the next report: the newest session checkpoints of the last 48 hours.
// The diff goes along only when it changed since the platform last accepted it.
func sessionsReport() []AISessionCheckpoint {
	out := []AISessionCheckpoint{}
	_ = withLock(func() error {
		now := nowFn()
		closeIdleSessions(now)
		all := sessionCheckpoints()
		latest := latestSession()
		allowed := allowedName(sessionUndoAllow)
		for i := len(all) - 1; i >= 0 && len(out) < reportSessions; i-- {
			m := all[i]
			if now.Sub(m.LastActivity) > reportSessionsBack {
				break
			}
			d, err := diffOf(m)
			if err != nil {
				log.Printf("checkpoint %s: diff: %v", m.ID, err)
			}
			sha := diffSHA(d)
			c := AISessionCheckpoint{
				ID: m.ID, Sessions: append([]string{}, m.AISessions...), CreatedAt: stamp(m.CreatedAt), LastActivity: stamp(m.LastActivity),
				State: m.Status, StateNote: trim(m.StatusNote, 400), StateAt: stamp(m.StatusAt), UndoAllowed: allowed,
				Targets: append([]string{}, m.Targets...), DiffSHA256: sha, Truncated: d.Truncated,
			}
			if u := undoUntil(m, latest); !u.IsZero() && now.Before(u) {
				c.UndoUntil = stamp(u)
			}
			if sha != m.SentDiff {
				files := d.Files
				c.Files = &files
			}
			out = append(out, c)
		}
		return nil
	})
	return out
}

// markSessionsSent records which diffs the platform accepted, so they are not sent again.
func markSessionsSent(sent []AISessionCheckpoint) {
	if len(sent) == 0 {
		return
	}
	_ = withLock(func() error {
		for _, c := range sent {
			if c.Files == nil {
				continue
			}
			m, err := loadManifest(c.ID)
			if err != nil || m.SentDiff == c.DiffSHA256 {
				continue
			}
			m.SentDiff = c.DiffSHA256
			_ = saveManifest(m)
		}
		return nil
	})
}

/* ---------- Undo this session (signed) ---------- */

// undoSession runs a signed {type: confirm, switch: session.undo, confirms: <checkpoint id>}. The result is an op
// (confirmed = restored) or a refusal, both in the next report, and the checkpoint's state.
func undoSession(st *engineState, pol Policy, now time.Time) {
	refuse := func(reason string) {
		st.refuse(pol.Nonce, "undo refused: "+reason, now)
	}
	if !allowedName(sessionUndoAllow) {
		refuse("not allowed on this server. Run: sudo securemyserver allow " + sessionUndoAllow)
		return
	}
	m, err := loadManifest(pol.Confirms)
	if err != nil || m.Kind != cpKindSession {
		refuse("no AI session checkpoint " + pol.Confirms + " on this server")
		return
	}
	latest := latestSession()
	switch {
	case m.Status == cpRestored || m.Status == cpRestoreFailed:
		refuse("checkpoint " + m.ID + " was already restored (" + m.Status + ")")
		return
	case latest == nil || latest.ID != m.ID:
		refuse("a newer AI session started since; only root can restore this one: sudo securemyserver undo " + m.ID)
		return
	case !now.Before(m.LastActivity.Add(sessionUndoWindow)):
		refuse("the 24-hour undo window has passed; only root can restore it: sudo securemyserver undo " + m.ID)
		return
	}
	if p := pendingCheckpoint(); p != nil {
		refuse("checkpoint " + p.ID + " (a switch or a fix prompt) is still waiting; confirm or undo it first")
		return
	}
	l := &opLog{}
	if m.Status == cpSessionOpen {
		if err := freezeSession(m); err != nil {
			l.add("diff", err, "")
			refuse("could not save the session diff first: " + err.Error())
			return
		}
		m.ClosedAt = now.UTC()
		setStatus(m, cpSessionClosed, "ended by the owner's undo")
		l.add("session", nil, "the open session was ended and its diff saved")
	} else {
		state, err := stateDigest(m)
		if err != nil {
			refuse("could not read the files: " + err.Error())
			return
		}
		if state != m.AfterState {
			refuse("the files changed again after the session ended, so undoing it would also undo those changes. Restore by hand: sudo securemyserver undo " + m.ID)
			return
		}
		l.add("unchanged since", nil, "the files are as the session left them")
	}
	m.UndoNonce = pol.Nonce
	_ = saveManifest(m)
	op := SwitchOp{Nonce: pol.Nonce, Switch: sessionUndoSwitch, At: stamp(now), Checkpoint: m.ID, Steps: []SwitchStep{}}
	if err := restoreCheckpoint(m, "undone by the owner in the dashboard (passkey)"); err != nil {
		l.add("restore", err, "")
		op.State, op.Reason = opRefused, "the restore failed, nothing was changed: "+trim(err.Error(), 300)
		log.Printf("session undo %s: %v", m.ID, err)
	} else {
		l.add("restore", nil, m.StatusNote)
		op.State, op.Reason = opConfirmed, trim("restored checkpoint "+m.ID+": "+m.StatusNote, 390)
		log.Printf("session undo %s: restored (%s)", m.ID, m.StatusNote)
	}
	op.Steps = l.steps
	st.addOp(op)
}

/* ---------- CLI: checkpoint --session <id> --auto ---------- */

// cmdSessionCheckpoint is the only form the securemyserver-ai sudoers rule allows. The arguments are checked
// exactly, because a sudoers wildcard matches more than one word.
func cmdSessionCheckpoint(args []string, stdout, stderr io.Writer) int {
	if len(args) != 3 || args[0] != "--session" || args[2] != "--auto" || !gateSessionRE.MatchString(args[1]) {
		fmt.Fprintln(stderr, "usage: securemyserver checkpoint --session <16 hex> --auto (run by securemyserver-gate)")
		return 2
	}
	if err := requireRoot(); err != nil {
		fmt.Fprintln(stderr, "securemyserver checkpoint:", err)
		return 1
	}
	var m *Manifest
	var created bool
	err := withLock(func() error {
		var err error
		m, created, err = touchSession(args[1])
		return err
	})
	if err != nil {
		fmt.Fprintln(stderr, "securemyserver checkpoint:", err)
		return 1
	}
	if created {
		files := 0
		for _, e := range m.Entries {
			if e.Kind == "file" {
				files++
			}
		}
		fmt.Fprintf(stdout, "created %s %d\n", m.ID, files)
	} else {
		fmt.Fprintf(stdout, "open %s\n", m.ID)
	}
	return 0
}

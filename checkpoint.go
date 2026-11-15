package main

// Checkpoints: the undo net under every change (D-014). `securemyserver checkpoint ssh` copies the named targets
// into /var/lib/securemyserver/checkpoints/<id>/ with a manifest (path, mode, owner, sha256 of every file) and
// starts a deadline. Unless `securemyserver confirm` runs before it, the checkpoint is put back: by the agent
// loop, and by a systemd-run transient timer as a backup (no systemd: the agent loop only).
// A restore is checked (sshd -t) before anything is reloaded. If the saved copy itself fails the check, the
// files that were there before the restore are put back and the restore is reported as failed.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	cpPending       = "pending"
	cpConfirmed     = "confirmed"
	cpRestored      = "restored"
	cpRestoreFailed = "restore_failed"

	maxCheckpointEntries = 4000
	maxCheckpointBytes   = 64 << 20
	keepCheckpoints      = 20
)

// The only things a checkpoint can save. Each name maps to fixed paths; nothing comes from the network.
// sshdir, sudoers, systemd and apt-sources are for the AI session checkpoint (session.go); root can name them too.
var checkpointTargets = map[string][]string{
	"ssh":         {"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d"},
	"sshdir":      {"/etc/ssh"}, // all of /etc/ssh: host keys are saved (0700, root only) but never put in a diff
	"ufw":         {"/etc/ufw", "/etc/default/ufw"},
	"nft":         {}, // the live ruleset (nft list ruleset), restored with nft -f
	"apt":         {"/etc/apt/apt.conf.d"},
	"apt-sources": {"/etc/apt/sources.list", "/etc/apt/sources.list.d"},
	"sudoers":     {"/etc/sudoers.d"},
	"systemd":     {"/etc/systemd/system"},
}

var targetOrder = []string{"ssh", "sshdir", "ufw", "nft", "apt", "apt-sources", "sudoers", "systemd"}

var checkpointIDRE = regexp.MustCompile(`^\d{8}-\d{6}-[0-9a-f]{4}$`)

type Manifest struct {
	ID         string    `json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	Deadline   time.Time `json:"deadline"`
	Targets    []string  `json:"targets"`
	Reason     string    `json:"reason"`
	Session    string    `json:"session,omitempty"` // audit session id of whoever made it
	Timer      string    `json:"timer,omitempty"`   // systemd transient unit, when one was started
	UFWActive  *bool     `json:"ufw_active,omitempty"`
	NftSHA256  string    `json:"nft_sha256,omitempty"`
	Entries    []cpEntry `json:"entries"`
	Status     string    `json:"status"`
	StatusAt   time.Time `json:"status_at"`
	StatusNote string    `json:"status_note,omitempty"`

	// Several switches under one passkey tap (D-090): each switch gets its own checkpoint, stacked in order (Seq)
	// under the policy's nonce, with one shared deadline. Restoring one also restores those stacked after it
	// (newest first), and confirming one confirms the whole batch, so restores never run out of order.
	Batch string `json:"batch,omitempty"`
	Seq   int    `json:"seq,omitempty"`

	// AI session checkpoints (session.go): made through securemyserver-gate before the first sudo of an AI session.
	// They have no deadline and never restore themselves; the owner's signed "Undo this session" restores them.
	Kind         string    `json:"kind,omitempty"`          // "" (a checkpoint before a change) | session
	AISessions   []string  `json:"ai_sessions,omitempty"`   // securemyserver-gate session ids it covers
	LastActivity time.Time `json:"last_activity,omitempty"` // the last sudo command of the session
	ClosedAt     time.Time `json:"closed_at,omitempty"`
	AfterState   string    `json:"after_state,omitempty"` // digest of the targets when the session ended; undo refuses if they changed since
	DiffSHA256   string    `json:"diff_sha256,omitempty"` // the frozen diff in diff.json
	SentDiff     string    `json:"sent_diff,omitempty"`   // the diff sha the platform last accepted
	UndoNonce    string    `json:"undo_nonce,omitempty"`  // the signed policy that undid it
}

type cpEntry struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"` // file | dir | symlink | absent
	Mode   uint32 `json:"mode,omitempty"`
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Link   string `json:"link,omitempty"`
}

func cpPath(id string) string { return rp(checkpointDir + "/" + id) }

// Commands the restore runs. Variables so tests can stand in for sshd and ufw.
var (
	sshdTest = func() error {
		_, errb, err := run(20*time.Second, "sshd", "-t")
		if err != nil {
			return fmt.Errorf("sshd -t: %s", trim(strings.TrimSpace(string(errb)), 300))
		}
		return nil
	}
	// visudoCheck checks /etc/sudoers and everything it includes. No visudo (no sudo installed): nothing to check.
	visudoCheck = func() error {
		if _, err := lookPath("visudo"); err != nil {
			return nil
		}
		out, errb, err := run(20*time.Second, "visudo", "-c")
		if err != nil {
			return fmt.Errorf("visudo -c: %s", trim(strings.TrimSpace(string(out)+" "+string(errb)), 300))
		}
		return nil
	}
	daemonReload = func() error {
		if !isSystemd() {
			return nil
		}
		return runChecked(60*time.Second, "systemctl", "daemon-reload")
	}
	reloadSSHFn = reloadSSH
	ufwIsActive = func() bool {
		if _, err := lookPath("ufw"); err != nil {
			return false
		}
		out, _, _ := run(15*time.Second, "ufw", "status")
		return parseUFWStatus(out) == "active"
	}
	runUFW       = func(args ...string) error { return runChecked(2*time.Minute, "ufw", args...) }
	nftList      = func() ([]byte, error) { out, _, err := run(30*time.Second, "nft", "list", "ruleset"); return out, err }
	nftLoad      = func(file string) error { return runChecked(30*time.Second, "nft", "-f", file) }
	startTimer   = startUndoTimer
	stopTimer    = func(unit string) { _, _, _ = run(15*time.Second, "systemctl", "stop", unit+".timer") }
	auditSession = readAuditSession
	nowFn        = time.Now
)

func runChecked(timeout time.Duration, name string, args ...string) error {
	_, errb, err := run(timeout, name, args...)
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, trim(strings.TrimSpace(string(errb)), 300))
	}
	return nil
}

// reloadSSH reloads sshd without dropping open sessions: systemctl reload (ssh or sshd), else SIGHUP to the pid
// in /run/sshd.pid (no systemd, e.g. a container). With socket activation and no sshd running, the next
// connection reads the new config anyway.
func reloadSSH() error {
	if isSystemd() {
		for _, unit := range []string{"ssh", "sshd"} {
			if _, _, err := run(30*time.Second, "systemctl", "reload", unit); err == nil {
				return nil
			}
		}
		for _, unit := range []string{"ssh", "sshd"} {
			if out, _, _ := run(10*time.Second, "systemctl", "is-active", unit); strings.TrimSpace(string(out)) == "active" {
				return fmt.Errorf("systemctl reload %s failed", unit)
			}
		}
		return nil // not running: socket activation starts it with the new config
	}
	b, err := readCapped("/run/sshd.pid", 64)
	if err != nil {
		return fmt.Errorf("no systemd and no /run/sshd.pid: reload sshd by hand")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid < 1 { // 1 is fine: sshd can be a container's init
		return fmt.Errorf("bad /run/sshd.pid")
	}
	return syscall.Kill(pid, syscall.SIGHUP)
}

// readAuditSession is the kernel audit session id. It is set at login (pam_loginuid) and kept through sudo, so
// "confirm from a NEW session" can be checked. Empty when the kernel does not track it.
func readAuditSession() string {
	b, err := os.ReadFile("/proc/self/sessionid")
	s := strings.TrimSpace(string(b))
	if err != nil || s == "" || s == "4294967295" {
		return ""
	}
	return s
}

func newCheckpointID(now time.Time) string {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return now.UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b[:])
}

func parseTargets(args []string) ([]string, error) {
	seen := map[string]bool{}
	for _, a := range args {
		a = strings.ToLower(strings.TrimSpace(a))
		if _, ok := checkpointTargets[a]; !ok {
			return nil, fmt.Errorf("unknown target %q (use: %s)", a, strings.Join(targetOrder, ", "))
		}
		seen[a] = true
	}
	if seen["sshdir"] {
		delete(seen, "ssh") // sshdir holds ssh
	}
	var out []string
	for _, t := range targetOrder {
		if seen[t] {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("name what to save: %s", strings.Join(targetOrder, ", "))
	}
	return out, nil
}

func rootsOf(targets []string) []string {
	var out []string
	for _, t := range targets {
		out = append(out, checkpointTargets[t]...)
	}
	return out
}

func hasSSH(targets []string) bool { return has(targets, "ssh") || has(targets, "sshdir") }

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

/* ---------- Snapshot and apply ---------- */

// snapshot copies every root (files, symlinks, dirs, recursively) into filesDir, mirroring the real paths.
func snapshot(filesDir string, roots []string) ([]cpEntry, error) {
	var entries []cpEntry
	var total int64
	for _, root := range roots {
		if _, err := os.Lstat(rp(root)); errors.Is(err, fs.ErrNotExist) {
			entries = append(entries, cpEntry{Path: root, Kind: "absent"})
			continue
		} else if err != nil {
			return nil, err
		}
		err := filepath.WalkDir(rp(root), func(real string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if len(entries) >= maxCheckpointEntries {
				return fmt.Errorf("more than %d files under %s", maxCheckpointEntries, root)
			}
			path := strings.TrimPrefix(real, fsRoot)
			st, err := os.Lstat(real)
			if err != nil {
				return err
			}
			e := cpEntry{Path: path, Mode: uint32(st.Mode().Perm() | st.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky))}
			if sys, ok := st.Sys().(*syscall.Stat_t); ok {
				e.UID, e.GID = int(sys.Uid), int(sys.Gid)
			}
			dst := filepath.Join(filesDir, path)
			switch {
			case st.IsDir():
				e.Kind = "dir"
				if err := os.MkdirAll(dst, 0o700); err != nil {
					return err
				}
			case st.Mode()&fs.ModeSymlink != 0:
				e.Kind = "symlink"
				if e.Link, err = os.Readlink(real); err != nil {
					return err
				}
			case st.Mode().IsRegular():
				e.Kind, e.Size = "file", st.Size()
				total += st.Size()
				if total > maxCheckpointBytes {
					return fmt.Errorf("more than %d MB under %s", maxCheckpointBytes>>20, root)
				}
				sum, err := copyFile(real, dst)
				if err != nil {
					return err
				}
				e.SHA256 = sum
			default:
				return nil // sockets, devices: never in config dirs, never copied
			}
			entries = append(entries, e)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return entries, nil
}

func copyFile(src, dst string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, h), in); err != nil {
		out.Close()
		return "", err
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func under(path, root string) bool { return path == root || strings.HasPrefix(path, root+"/") }

// verifyStored checks every saved copy against its sha256 before anything is touched.
func verifyStored(entries []cpEntry, filesDir string) error {
	for _, e := range entries {
		if e.Kind != "file" {
			continue
		}
		sum, err := fileSHA256(filepath.Join(filesDir, e.Path))
		if err != nil {
			return fmt.Errorf("saved copy of %s: %w", e.Path, err)
		}
		if sum != e.SHA256 {
			return fmt.Errorf("saved copy of %s does not match its sha256: the checkpoint is damaged", e.Path)
		}
	}
	return nil
}

// apply makes each root exactly match the entries: extra files are removed, saved files written back with their
// mode and owner.
func apply(entries []cpEntry, filesDir string, roots []string) error {
	for _, root := range roots {
		var want []cpEntry
		absent := false
		for _, e := range entries {
			if under(e.Path, root) {
				if e.Kind == "absent" && e.Path == root {
					absent = true
				}
				want = append(want, e)
			}
		}
		if absent {
			if err := os.RemoveAll(rp(root)); err != nil {
				return err
			}
			continue
		}
		wantKind := map[string]string{}
		for _, e := range want {
			wantKind[e.Path] = e.Kind
		}
		// Remove what was not there, or is now a different kind of thing. Deepest paths first.
		var have []string
		_ = filepath.WalkDir(rp(root), func(real string, d fs.DirEntry, err error) error {
			if err == nil {
				have = append(have, strings.TrimPrefix(real, fsRoot))
			}
			return nil
		})
		sort.Sort(sort.Reverse(sort.StringSlice(have)))
		for _, p := range have {
			st, err := os.Lstat(rp(p))
			if err != nil {
				continue
			}
			kind := "file"
			if st.IsDir() {
				kind = "dir"
			} else if st.Mode()&fs.ModeSymlink != 0 {
				kind = "symlink"
			}
			if wantKind[p] == kind {
				continue
			}
			if err := os.RemoveAll(rp(p)); err != nil {
				return err
			}
		}
		sort.Slice(want, func(i, j int) bool { return want[i].Path < want[j].Path }) // parents first
		for _, e := range want {
			real := rp(e.Path)
			mode := fs.FileMode(e.Mode).Perm()
			switch e.Kind {
			case "dir":
				if err := os.MkdirAll(real, mode); err != nil {
					return err
				}
				if err := os.Chmod(real, fs.FileMode(e.Mode)); err != nil {
					return err
				}
			case "file":
				b, err := os.ReadFile(filepath.Join(filesDir, e.Path))
				if err != nil {
					return err
				}
				if err := writeFileAtomic(real, b, mode); err != nil {
					return err
				}
			case "symlink":
				_ = os.Remove(real)
				if err := os.Symlink(e.Link, real); err != nil {
					return err
				}
			default:
				continue
			}
			if err := os.Lchown(real, e.UID, e.GID); err != nil {
				return err
			}
		}
	}
	return nil
}

/* ---------- Checkpoints ---------- */

func saveManifest(m *Manifest) error {
	return writeJSON(filepath.Join(cpPath(m.ID), "manifest.json"), m)
}

func loadManifest(id string) (*Manifest, error) {
	if !checkpointIDRE.MatchString(id) {
		return nil, fmt.Errorf("%q is not a checkpoint id", id)
	}
	var m Manifest
	if err := readJSON(filepath.Join(cpPath(id), "manifest.json"), &m); err != nil {
		return nil, err
	}
	if m.ID != id {
		return nil, fmt.Errorf("checkpoint %s: manifest id mismatch", id)
	}
	return &m, nil
}

// listCheckpoints returns every checkpoint, oldest first.
func listCheckpoints() []*Manifest {
	ents, _ := os.ReadDir(rp(checkpointDir))
	var out []*Manifest
	for _, e := range ents {
		if !e.IsDir() || !checkpointIDRE.MatchString(e.Name()) {
			continue
		}
		if m, err := loadManifest(e.Name()); err == nil {
			out = append(out, m)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].Seq < out[j].Seq
	})
	return out
}

func pendingCheckpoint() *Manifest {
	for _, m := range listCheckpoints() {
		if m.Status == cpPending {
			return m
		}
	}
	return nil
}

// createCheckpoint saves the targets and starts the deadline. Call with the lock held. Only one checkpoint can
// be pending at a time, so restores never have to be ordered.
func createCheckpoint(targets []string, window time.Duration, reason string) (*Manifest, error) {
	return createBatchCheckpoint(targets, window, reason, "")
}

// createBatchCheckpoint is createCheckpoint for one switch of a batch (D-090). Checkpoints of the same batch may
// stack on each other; the later ones take the first one's deadline, so the batch has one deadline.
func createBatchCheckpoint(targets []string, window time.Duration, reason, batch string) (*Manifest, error) {
	now := nowFn()
	seq := 0
	for _, p := range listCheckpoints() {
		if batch != "" && p.Batch == batch && p.Seq >= seq {
			seq = p.Seq + 1
		}
		if p.Status != cpPending {
			continue
		}
		if batch == "" || p.Batch != batch {
			return nil, fmt.Errorf("checkpoint %s is still waiting (until %s): confirm or undo it first", p.ID, p.Deadline.UTC().Format("15:04:05 UTC"))
		}
		window = p.Deadline.Sub(now)
		if window < time.Second {
			return nil, fmt.Errorf("checkpoint %s is at its deadline", p.ID)
		}
	}
	m := &Manifest{
		ID:        newCheckpointID(now),
		CreatedAt: now.UTC(),
		Deadline:  now.Add(window).UTC(),
		Targets:   targets,
		Reason:    cleanReason(reason),
		Session:   auditSession(),
		Status:    cpPending,
		StatusAt:  now.UTC(),
		Batch:     batch,
		Seq:       seq,
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
	entries, err := snapshot(filepath.Join(dir, "files"), rootsOf(targets))
	if err != nil {
		return fail(err)
	}
	m.Entries = entries
	if has(targets, "ufw") {
		active := ufwIsActive() // false when ufw is not installed
		m.UFWActive = &active
	}
	if has(targets, "nft") {
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
	if isSystemd() {
		if unit, err := startTimer(m.ID, window); err != nil {
			log.Printf("checkpoint %s: no systemd backup timer (%v); the agent loop still restores it", m.ID, err)
		} else {
			m.Timer = unit
			_ = saveManifest(m)
		}
	}
	pruneCheckpoints()
	return m, nil
}

func cleanReason(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	return trim(strings.TrimSpace(s), 120)
}

// startUndoTimer starts a transient systemd timer that runs `securemyserver undo --if-pending <id>` at the
// deadline. It is the backup for the agent loop (which may not be running).
func startUndoTimer(id string, window time.Duration) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	unit := "securemyserver-undo-" + id
	secs := int(window.Seconds())
	if secs < 1 {
		secs = 1
	}
	err = runChecked(30*time.Second, "systemd-run", "--unit="+unit, "--description=SecureMyServer: restore checkpoint "+id+" unless confirmed",
		"--on-active="+strconv.Itoa(secs)+"s", "--timer-property=AccuracySec=1s", "--collect", exe, "undo", "--if-pending", id)
	return unit, err
}

func pruneCheckpoints() {
	all := listCheckpoints()
	if len(all) <= keepCheckpoints {
		return
	}
	for _, m := range all[:len(all)-keepCheckpoints] {
		if m.Status != cpPending && m.Status != cpSessionOpen {
			os.RemoveAll(cpPath(m.ID))
		}
	}
}

func setStatus(m *Manifest, status, note string) {
	m.Status, m.StatusAt, m.StatusNote = status, nowFn().UTC(), note
	if err := saveManifest(m); err != nil {
		log.Printf("checkpoint %s: save status: %v", m.ID, err)
	}
}

// confirmCheckpoint keeps the change: the deadline no longer applies. Call with the lock held. In a batch it
// confirms every checkpoint of that batch still waiting: one new login proves them all.
func confirmCheckpoint(m *Manifest, note string) error {
	if m.Status != cpPending {
		return fmt.Errorf("checkpoint %s is %s, not waiting for a confirm", m.ID, m.Status)
	}
	setStatus(m, cpConfirmed, note)
	if m.Timer != "" {
		stopTimer(m.Timer)
	}
	for _, o := range batchMates(m) {
		if o.Status == cpPending {
			setStatus(o, cpConfirmed, note)
			if o.Timer != "" {
				stopTimer(o.Timer)
			}
		}
	}
	return nil
}

// batchMates are the other checkpoints of m's batch, oldest first.
func batchMates(m *Manifest) []*Manifest {
	var out []*Manifest
	if m.Batch == "" {
		return out
	}
	for _, o := range listCheckpoints() {
		if o.Batch == m.Batch && o.ID != m.ID {
			out = append(out, o)
		}
	}
	return out
}

// restoreCheckpoint puts the saved targets back, validates, then reloads. Call with the lock held. In a batch,
// the checkpoints stacked after m are restored first, newest first, so each one puts back what it saved.
func restoreCheckpoint(m *Manifest, why string) error {
	if m.Batch != "" && m.Status != cpRestored {
		mates := batchMates(m)
		for i := len(mates) - 1; i >= 0; i-- {
			o := mates[i]
			if o.Seq > m.Seq && (o.Status == cpPending || o.Status == cpConfirmed) {
				if err := restoreOne(o, why); err != nil {
					return fmt.Errorf("checkpoint %s, saved after %s, could not be restored first: %w", o.ID, m.ID, err)
				}
			}
		}
	}
	return restoreOne(m, why)
}

func restoreOne(m *Manifest, why string) error {
	if m.Status == cpRestored {
		return fmt.Errorf("checkpoint %s was already restored", m.ID)
	}
	dir := cpPath(m.ID)
	files := filepath.Join(dir, "files")
	roots := rootsOf(m.Targets)
	if err := verifyStored(m.Entries, files); err != nil {
		setStatus(m, cpRestoreFailed, err.Error())
		return err
	}
	var nft []byte
	if has(m.Targets, "nft") {
		b, err := os.ReadFile(filepath.Join(dir, "nft-ruleset.nft"))
		sum := sha256.Sum256(b)
		if err != nil || hex.EncodeToString(sum[:]) != m.NftSHA256 {
			err = fmt.Errorf("saved nft ruleset is missing or damaged")
			setStatus(m, cpRestoreFailed, err.Error())
			return err
		}
		nft = b
		// A session checkpoint puts the ruleset back only when it differs (Docker and the agent's own blocklist
		// table change it too), and never with the agent's old blocklist table: the next pull adds the table again.
		if m.Kind == cpKindSession {
			nft = []byte(stripOwnTable(string(b)))
			if cur, err := nftList(); err == nil && stripOwnTable(string(cur)) == string(nft) {
				nft = nil
			}
		}
	}
	// A safety copy of what is there now, so a backup that fails sshd -t can be undone.
	before := filepath.Join(dir, "before-restore")
	os.RemoveAll(before)
	prev, err := snapshot(before, roots)
	if err != nil {
		setStatus(m, cpRestoreFailed, "could not save the current files first: "+err.Error())
		return err
	}
	if err := apply(m.Entries, files, roots); err != nil {
		_ = apply(prev, before, roots)
		setStatus(m, cpRestoreFailed, "writing the saved files failed: "+err.Error())
		return err
	}
	var passed []string
	if hasSSH(m.Targets) {
		if err := sshdTest(); err != nil {
			_ = apply(prev, before, roots)
			msg := "THE SAVED SSH CONFIG FAILS sshd -t. Nothing was changed: the current config is left as it was. " + err.Error()
			log.Printf("checkpoint %s: %s", m.ID, msg)
			setStatus(m, cpRestoreFailed, msg)
			return errors.New(msg)
		}
		passed = append(passed, "sshd -t")
	}
	if has(m.Targets, "sudoers") {
		if err := visudoCheck(); err != nil {
			_ = apply(prev, before, roots)
			msg := "THE SAVED SUDOERS FAIL visudo -c. Nothing was changed: the current files are left as they were. " + err.Error()
			log.Printf("checkpoint %s: %s", m.ID, msg)
			setStatus(m, cpRestoreFailed, msg)
			return errors.New(msg)
		}
		passed = append(passed, "visudo -c")
	}
	var notes []string
	if hasSSH(m.Targets) {
		if err := reloadSSHFn(); err != nil {
			notes = append(notes, "ssh reload: "+err.Error())
		}
	}
	if has(m.Targets, "systemd") {
		if err := daemonReload(); err != nil {
			notes = append(notes, "systemctl daemon-reload: "+err.Error())
		}
	}
	if has(m.Targets, "ufw") && m.UFWActive != nil {
		var err error
		switch {
		case *m.UFWActive && ufwIsActive():
			err = runUFW("reload")
		case *m.UFWActive:
			err = runUFW("--force", "enable")
		case ufwIsActive():
			err = runUFW("disable")
		}
		if err != nil {
			notes = append(notes, err.Error())
		}
	}
	if nft != nil {
		f := filepath.Join(dir, "nft-restore.nft")
		if err := writeFileAtomic(f, append([]byte("flush ruleset\n"), nft...), 0o600); err == nil {
			if err := nftLoad(f); err != nil {
				notes = append(notes, err.Error())
			}
		}
	}
	note := why
	if len(passed) > 0 {
		note += "; " + strings.Join(passed, " and ") + " passed"
	}
	if len(notes) > 0 {
		note += " (" + strings.Join(notes, "; ") + ")"
		log.Printf("checkpoint %s restored with warnings: %s", m.ID, strings.Join(notes, "; "))
	}
	setStatus(m, cpRestored, note)
	if m.Timer != "" {
		stopTimer(m.Timer)
	}
	return nil
}

// enforceDeadlines restores every pending checkpoint whose deadline passed. The agent loop calls it.
func enforceDeadlines(now time.Time) {
	all := listCheckpoints()
	for i := len(all) - 1; i >= 0; i-- { // newest first, so stacked batch checkpoints go back in order
		m, err := loadManifest(all[i].ID)
		if err != nil {
			continue
		}
		if m.Status == cpPending && !now.Before(m.Deadline) {
			if err := restoreCheckpoint(m, "deadline passed without a confirm (agent)"); err != nil {
				log.Printf("checkpoint %s: restore at deadline failed: %v", m.ID, err)
			} else {
				log.Printf("checkpoint %s: restored at its deadline (nobody confirmed)", m.ID)
			}
		}
	}
}

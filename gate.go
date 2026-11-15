package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"securemyserver.com/securemyserver/internal/gatelog"
)

// The agent reads the securemyserver-gate audit log (it never writes it) and reports new commands, plus whether the
// log is usable. If securemyserver-ai could not write the log, securemyserver-gate refuses to run commands, and the
// dashboard shows an audit gap.

const maxAICommands = 2000

// maxAICommandBytes keeps the report well under the platform's 2 MiB limit. Past it the oldest commands
// are left out and counted in Dropped, so the dashboard can say so.
const maxAICommandBytes = 512 << 10

// gateTSFormat is fixed width so timestamps sort as strings.
const gateTSFormat = "2006-01-02T15:04:05.000000Z"

type Gate struct {
	// Log: ok | missing | unwritable | not_set_up (no securemyserver-ai user and no log)
	Log        string      `json:"log"`
	Source     string      `json:"source"` // journal (journald runs; entries checked by _UID and _EXE) | file (gate.log)
	Detail     string      `json:"detail,omitempty"`
	Installed  bool        `json:"installed"` // /usr/lib/securemyserver/securemyserver-gate exists, root-owned, not writable by others
	UserExists bool        `json:"user_exists"`
	AppendOnly bool        `json:"append_only"` // chattr +a is set on the log (file source only)
	BadLines   int         `json:"bad_lines"`   // lines that did not parse (forged or damaged)
	Dropped    int         `json:"dropped"`     // commands left out to keep the report small
	Forged     int         `json:"forged"`      // journal entries named securemyserver-gate that another program or user wrote
	Suppressed int         `json:"suppressed"`  // messages journald dropped from securemyserver-ai sessions (rate limit), which may hide gate entries
	Commands   []AICommand `json:"commands"`
}

type AICommand struct {
	ID         string `json:"id"`
	TS         string `json:"ts"` // start time
	Session    string `json:"session"`
	FromIP     string `json:"from_ip,omitempty"`
	User       string `json:"user"`
	Command    string `json:"command"`
	CmdLen     int    `json:"cmd_len"`
	Ended      bool   `json:"ended"`
	Exit       *int   `json:"exit,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	BytesOut   int64  `json:"bytes_out"`
	Truncated  bool   `json:"truncated"`
	TimedOut   bool   `json:"timed_out"`
	Refused    string `json:"refused,omitempty"` // interactive | too_long | no_checkpoint
}

// gateFirstRead stays true until a report is accepted (main.go clears it).
var gateFirstRead = true

func collectGate(since time.Time) *Gate {
	if gateFirstRead {
		since = time.Now().AddDate(0, 0, -7) // after a restart, resend a week; the platform dedupes by id
	}
	// securemyserver-gate writes to the journal whenever its socket exists, so the agent reads it then, and the
	// file (which securemyserver-ai can append to) is ignored.
	if journalSocketUp(gatelog.JournalSocket) && journalRunning() {
		if g, ok := collectGateJournal(since); ok {
			return g
		}
	}
	g := gateStatus(gatelog.Path, gatelog.Dir, gatelog.GatePath)
	g.Source = "file"
	if g.Log == "ok" || g.Log == "unwritable" {
		if b, err := readTail(gatelog.Path, 8<<20); err == nil {
			g.Commands, g.BadLines = parseGateLog(b, since)
			all := len(g.Commands)
			g.Commands = trimToBudget(g.Commands, maxAICommandBytes)
			g.Dropped = all - len(g.Commands)
		}
	}
	return g
}

// journalSocketUp: the socket securemyserver-gate writes to exists. The gate makes the same check.
func journalSocketUp(path string) bool {
	st, err := os.Lstat(path)
	return err == nil && st.Mode()&os.ModeSocket != 0
}

// collectGateJournal reads the gate's journal entries. ok is false when journalctl failed; the file is read then.
func collectGateJournal(since time.Time) (*Gate, bool) {
	g, uid, gids, exists := gateBase(gatelog.GatePath)
	g.Source = "journal"
	if !exists {
		g.Log = "not_set_up"
		return g, true
	}
	g.Log = "ok"
	if st, err := os.Stat(gatelog.JournalSocket); err != nil || !canAccess(st, uid, gids, 0o2) {
		g.Log, g.Detail = "unwritable", gatelog.User+" cannot write to the journal socket "+gatelog.JournalSocket+", so securemyserver-gate refuses every command"
	}
	sinceArg := "@" + strconv.FormatInt(since.Unix(), 10)
	out, err := runJournal(60*time.Second, "--since", sinceArg, "SYSLOG_IDENTIFIER="+gatelog.Identifier)
	if err != nil {
		return nil, false
	}
	lines, forged := trustedGateLines(out, uid, gatelog.GatePath)
	g.Commands, g.BadLines = parseGateLog(lines, since)
	g.Forged = forged
	all := len(g.Commands)
	g.Commands = trimToBudget(g.Commands, maxAICommandBytes)
	g.Dropped = all - len(g.Commands)
	if out, err := runJournal(30*time.Second, "--since", sinceArg, "MESSAGE_ID="+journalDroppedID, "_TRANSPORT=driver"); err == nil {
		g.Suppressed = suppressedFor(out, uid)
	}
	return g, true
}

// trustedGateLines keeps the MESSAGE of entries journald received over its native protocol (_TRANSPORT=journal)
// from the securemyserver-ai uid running the gate binary (_EXE). journald fills both from the socket credentials
// and /proc; a sender cannot set them. Every other entry with the gate's identifier counts as forged.
func trustedGateLines(b []byte, uid int, exe string) ([]byte, int) {
	var out []byte
	forged := 0
	want := strconv.Itoa(uid)
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var e journalEntry
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		if ident, _ := journalString(e.Ident); ident != gatelog.Identifier {
			continue
		}
		msg, ok1 := journalString(e.Message)
		tr, ok2 := journalString(e.Transport)
		u, ok3 := journalString(e.UID)
		x, ok4 := journalString(e.Exe)
		if !ok1 || !ok2 || !ok3 || !ok4 || tr != "journal" || u != want || x != exe {
			forged++
			continue
		}
		out = append(out, strings.ReplaceAll(msg, "\n", " ")...)
		out = append(out, '\n')
	}
	return out, forged
}

// journalDroppedID is journald's "Suppressed N messages from <cgroup>" notice (SD_MESSAGE_JOURNAL_DROPPED).
const journalDroppedID = "a596d6fe7bfa4994828e72309e95d61e"

var suppressedRE = regexp.MustCompile(`^Suppressed (\d+) messages from (\S+)`)

// suppressedFor adds up the messages journald dropped from uid's sessions, or from the ssh unit (where sessions stay
// when pam_systemd is not used). A flood there could make journald's rate limit drop the gate's own entries.
func suppressedFor(b []byte, uid int) int {
	slice := "/user-" + strconv.Itoa(uid) + ".slice/"
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var e journalEntry
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		msg, _ := journalString(e.Message)
		tr, _ := journalString(e.Transport)
		m := suppressedRE.FindStringSubmatch(msg)
		if tr != "driver" || m == nil {
			continue
		}
		if p := m[2]; strings.Contains(p, slice) || strings.HasSuffix(p, "/ssh.service") || strings.HasSuffix(p, "/sshd.service") {
			if k, err := strconv.Atoi(m[1]); err == nil && k > 0 && k < 1<<30 {
				n += k
			}
		}
	}
	return n
}

// gateBase checks the gate binary and looks up securemyserver-ai.
func gateBase(gatePath string) (*Gate, int, map[int]bool, bool) {
	g := &Gate{Commands: []AICommand{}}
	if st, err := os.Stat(gatePath); err == nil {
		sys, _ := st.Sys().(*syscall.Stat_t)
		g.Installed = st.Mode().IsRegular() && st.Mode()&0o111 != 0 && sys != nil && sys.Uid == 0 && st.Mode().Perm()&0o022 == 0
		if !g.Installed {
			g.Detail = gatePath + " must be owned by root and not writable by others"
		}
	}
	pw, _ := readCapped("/etc/passwd", 4<<20)
	grp, _ := readCapped("/etc/group", 4<<20)
	uid, gids, exists := lookupUser(pw, grp, gatelog.User)
	g.UserExists = exists
	return g, uid, gids, exists
}

func gateStatus(logPath, dir, gatePath string) *Gate {
	g, uid, gids, exists := gateBase(gatePath)

	lst, err := os.Lstat(logPath)
	switch {
	case err != nil && !exists:
		g.Log = "not_set_up"
		return g
	case err != nil:
		g.Log, g.Detail = "missing", logPath+" does not exist, so securemyserver-gate refuses every command"
		return g
	case !lst.Mode().IsRegular():
		g.Log, g.Detail = "unwritable", logPath+" is not a regular file"
		return g
	}
	if !exists {
		g.Log, g.Detail = "unwritable", "user "+gatelog.User+" does not exist"
		return g
	}
	flags := fileFlags(logPath)
	g.AppendOnly = flags&fsAppendFL != 0
	if why := gateLogUnwritable(lst, flags, uid, gids); why != "" {
		g.Log, g.Detail = "unwritable", why
		return g
	}
	if dst, err := os.Stat(dir); err != nil || !canAccess(dst, uid, gids, 0o1) {
		g.Log, g.Detail = "unwritable", gatelog.User+" cannot enter "+dir
		return g
	}
	g.Log = "ok"
	return g
}

func gateLogUnwritable(st os.FileInfo, flags uint32, uid int, gids map[int]bool) string {
	if flags&fsImmutableFL != 0 {
		return "the log is immutable (chattr +i)"
	}
	if !canAccess(st, uid, gids, 0o2) {
		return gatelog.User + " cannot write the log (expected owner root, group " + gatelog.User + ", mode 0620)"
	}
	return ""
}

// canAccess checks the classic owner/group/other bits for want (1 = x, 2 = w, 4 = r).
func canAccess(st os.FileInfo, uid int, gids map[int]bool, want os.FileMode) bool {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	perm := st.Mode().Perm()
	switch {
	case int(sys.Uid) == uid:
		return perm>>6&want == want
	case gids[int(sys.Gid)]:
		return perm>>3&want == want
	default:
		return perm&want == want
	}
}

// lookupUser returns the uid and all group ids (primary and supplementary) of name.
func lookupUser(passwd, group []byte, name string) (int, map[int]bool, bool) {
	gids := map[int]bool{}
	uid, found := -1, false
	for _, l := range strings.Split(string(passwd), "\n") {
		f := strings.Split(l, ":")
		if len(f) >= 4 && f[0] == name {
			u, err1 := strconv.Atoi(f[2])
			g, err2 := strconv.Atoi(f[3])
			if err1 == nil && err2 == nil {
				uid, found = u, true
				gids[g] = true
			}
			break
		}
	}
	for _, l := range strings.Split(string(group), "\n") {
		f := strings.Split(l, ":")
		if len(f) < 4 {
			continue
		}
		for _, m := range strings.Split(f[3], ",") {
			if strings.TrimSpace(m) == name {
				if g, err := strconv.Atoi(f[2]); err == nil {
					gids[g] = true
				}
			}
		}
	}
	return uid, gids, found
}

const (
	fsIocGetflags = 0x80086601 // FS_IOC_GETFLAGS on 64-bit Linux
	fsImmutableFL = 0x10
	fsAppendFL    = 0x20
)

// fileFlags reads the chattr flags. 0 if the filesystem does not support them.
func fileFlags(path string) uint32 {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0
	}
	defer f.Close()
	var flags uint32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), fsIocGetflags, uintptr(unsafe.Pointer(&flags))); e != 0 {
		return 0
	}
	return flags
}

var (
	hex32RE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hex16RE = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

// parseGateLog merges start/end/refused lines by id and returns commands with any line newer than
// since, newest last, at most maxAICommands. Lines are untrusted (securemyserver-ai can append to the log), so
// every field is checked and cleaned again; lines that fail count as bad.
func parseGateLog(b []byte, since time.Time) ([]AICommand, int) {
	byID := map[string]*AICommand{}
	latest := map[string]time.Time{}
	bad := 0
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 256<<10)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		var l gatelog.Line
		if json.Unmarshal(sc.Bytes(), &l) != nil || l.V != 1 || !hex32RE.MatchString(l.ID) || !hex16RE.MatchString(l.Session) {
			bad++
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, l.TS)
		if err != nil || (l.Ev != "start" && l.Ev != "end" && l.Ev != "refused") {
			bad++
			continue
		}
		if l.FromIP != "" {
			ip := net.ParseIP(l.FromIP)
			if ip == nil {
				bad++
				continue
			}
			l.FromIP = ip.String()
		}
		c := byID[l.ID]
		if c == nil {
			if len(byID) >= 50000 {
				continue
			}
			c = &AICommand{ID: l.ID, Session: l.Session, FromIP: l.FromIP, TS: ts.UTC().Format(gateTSFormat)}
			byID[l.ID] = c
		}
		if ts.After(latest[l.ID]) {
			latest[l.ID] = ts
		}
		switch l.Ev {
		case "start", "refused":
			c.TS = ts.UTC().Format(gateTSFormat)
			c.User = cleanText(l.User, 64)
			c.Command = gatelog.SanitizeCommand(l.Cmd, gatelog.MaxLoggedCommand)
			c.CmdLen = clampInt(l.CmdLen, 0, 10_000_000)
			if l.Ev == "refused" {
				c.Refused, c.Ended = cleanText(l.Reason, 32), true
			}
		case "end":
			c.Ended = true
			if l.Exit != nil {
				e := clampInt(*l.Exit, -1, 255)
				c.Exit = &e
			}
			c.DurationMS = clamp64(l.DurationMS, 0, 86_400_000)
			c.BytesOut = clamp64(l.BytesOut, 0, 1<<40)
			c.Truncated, c.TimedOut = l.Truncated, l.TimedOut
		}
	}
	out := []AICommand{}
	for id, c := range byID {
		if latest[id].After(since) {
			out = append(out, *c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TS < out[j].TS })
	if len(out) > maxAICommands {
		out = out[len(out)-maxAICommands:]
	}
	return out, bad
}

func clampInt(v, lo, hi int) int {
	return int(clamp64(int64(v), int64(lo), int64(hi)))
}

func clamp64(v, lo, hi int64) int64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// trimToBudget drops the oldest commands until the command text fits in max bytes.
func trimToBudget(cmds []AICommand, max int) []AICommand {
	total := 0
	for i := len(cmds) - 1; i >= 0; i-- {
		total += len(cmds[i].Command) + 200
		if total > max {
			return cmds[i+1:]
		}
	}
	return cmds
}

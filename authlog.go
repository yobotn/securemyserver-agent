package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxEvents = 5000

// sshdComms are the process names journald may record for sshd's lines (_COMM, which journald reads itself from
// /proc). sshd-session and sshd-auth are OpenSSH 9.8 and 10.0.
var sshdComms = map[string]bool{"sshd": true, "sshd-session": true, "sshd-auth": true}

// journalSSHDMatch selects sshd's lines by what they claim (SYSLOG_IDENTIFIER) or by unit, so forged lines are
// seen too and counted as rejected; parseJournal then trusts only journald's own fields.
var journalSSHDMatch = []string{
	"SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session", "SYSLOG_IDENTIFIER=sshd-auth",
	"+", "_SYSTEMD_UNIT=ssh.service", "_SYSTEMD_UNIT=sshd.service",
}

// journalOutputFields keeps journalctl's JSON small. Needs systemd 236 or later; runJournal retries without it.
const journalOutputFields = "--output-fields=MESSAGE,_UID,_COMM,_EXE,_TRANSPORT,SYSLOG_IDENTIFIER"

// journalRunning reports whether the systemd journal is there to read.
func journalRunning() bool {
	if _, err := os.Stat("/run/systemd/journal"); err != nil {
		return false
	}
	_, err := lookPath("journalctl")
	return err == nil
}

// runJournal runs journalctl with JSON output and the given arguments, with --output-fields when supported.
func runJournal(timeout time.Duration, args ...string) ([]byte, error) {
	base := []string{"--no-pager", "-q", "-o", "json"}
	withFields := append(append(append([]string{}, base...), journalOutputFields), args...)
	out, _, err := run(timeout, "journalctl", withFields...)
	if err != nil {
		out, _, err = run(timeout, "journalctl", append(base, args...)...)
	}
	return out, err
}

// AuthCollect is what one read of the SSH log gives.
type AuthCollect struct {
	Events []AuthEvent
	// Source is journal, a log file path, or none.
	Source string
	// Verified is true only for the journal: each line's _UID and _COMM, which journald sets itself, show that
	// root's sshd wrote it. A syslog file can't tell sshd's lines from `logger -t sshd` run by any user.
	Verified bool
	// Rejected counts journal lines that looked like sshd logins but were not written by root's sshd.
	Rejected int
}

// collectAuth returns SSH auth events newer than since, from the systemd journal when it is running,
// otherwise from /var/log/auth.log (Debian, Ubuntu) or /var/log/secure (RHEL family), plus the file rotated
// just before it when that rotation happened after since.
func collectAuth(since time.Time) (AuthCollect, error) {
	if journalRunning() {
		args := append([]string{"--since", "@" + strconv.FormatInt(since.Unix(), 10)}, journalSSHDMatch...)
		out, err := runJournal(60*time.Second, args...)
		if err == nil {
			ev, rejected := parseJournal(out, since)
			return AuthCollect{Events: ev, Source: "journal", Verified: true, Rejected: rejected}, nil
		}
	}
	now := time.Now()
	for _, p := range []string{"/var/log/auth.log", "/var/log/secure"} {
		b, err := readTail(p, 32<<20)
		if err != nil {
			continue
		}
		ev := parseSyslog(b, since, now)
		// The previous file, when it was rotated after the last report: lines written just before the rotation.
		if files := rotatedLogs(p); len(files) > 1 && files[1].mod.After(since) {
			if old, err := readLogFile(files[1].path, 16<<20); err == nil {
				ev = append(parseSyslog(old, since, now), ev...)
			}
		}
		if len(ev) > maxEvents {
			ev = ev[len(ev)-maxEvents:]
		}
		return AuthCollect{Events: ev, Source: p}, nil
	}
	return AuthCollect{Events: []AuthEvent{}, Source: "none"}, nil
}

func readTail(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > max {
		if _, err := f.Seek(st.Size()-max, io.SeekStart); err != nil {
			return nil, err
		}
	}
	return io.ReadAll(io.LimitReader(f, max))
}

// maxGzipRead stops a gzip bomb: past this many decompressed bytes the rest of a rotated file is skipped.
const maxGzipRead = 256 << 20

// readLogFile reads the last max bytes of a log file, decompressing it when it ends in .gz.
func readLogFile(path string, max int) ([]byte, error) {
	if !strings.HasSuffix(path, ".gz") {
		return readTail(path, int64(max))
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return keepTail(io.LimitReader(zr, maxGzipRead), max)
}

// keepTail reads r to the end and keeps only its last max bytes.
func keepTail(r io.Reader, max int) ([]byte, error) {
	buf := make([]byte, 0, 1<<20)
	chunk := make([]byte, 256<<10)
	for {
		n, err := r.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if len(buf) > 2*max {
			buf = append(buf[:0], buf[len(buf)-max:]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if len(buf) > max {
		buf = buf[len(buf)-max:]
	}
	return buf, nil
}

type logFile struct {
	path string
	mod  time.Time
}

// rotatedLogMaxFiles caps how many rotated files the agent looks at.
const rotatedLogMaxFiles = 20

// rotatedNameRE: ".1", ".2.gz", "-20261101", "-20261101.gz".
var rotatedNameRE = regexp.MustCompile(`^(?:\.\d{1,3}|-\d{8})(?:\.gz)?$`)

// rotatedLogs lists base and its rotated copies, newest first: auth.log, auth.log.1, auth.log.2.gz, ... (logrotate
// numbering) or secure, secure-20261101, secure-20261025.gz (dateext). Only regular files, never symlinks.
func rotatedLogs(base string) []logFile {
	out := []logFile{}
	if st, err := os.Stat(base); err == nil && st.Mode().IsRegular() {
		out = append(out, logFile{base, st.ModTime()})
	}
	var more []logFile
	for _, pat := range []string{base + ".*", base + "-*"} {
		names, _ := filepath.Glob(pat)
		for _, n := range names {
			if !rotatedNameRE.MatchString(strings.TrimPrefix(n, base)) {
				continue
			}
			if st, err := os.Lstat(n); err == nil && st.Mode().IsRegular() {
				more = append(more, logFile{n, st.ModTime()})
			}
		}
	}
	sort.SliceStable(more, func(i, j int) bool { return more[i].mod.After(more[j].mod) })
	out = append(out, more...)
	if len(out) > rotatedLogMaxFiles {
		out = out[:rotatedLogMaxFiles]
	}
	return out
}

// journalEntry holds the fields the agent reads from `journalctl -o json`. Fields that start with an underscore
// are set by journald itself from the sending process's credentials; a client cannot set them.
type journalEntry struct {
	Message   json.RawMessage `json:"MESSAGE"`
	Realtime  string          `json:"__REALTIME_TIMESTAMP"`
	UID       json.RawMessage `json:"_UID"`
	Comm      json.RawMessage `json:"_COMM"`
	Exe       json.RawMessage `json:"_EXE"`
	Transport json.RawMessage `json:"_TRANSPORT"`
	Ident     json.RawMessage `json:"SYSLOG_IDENTIFIER"`
}

// journalString reads a journal JSON value: a string, or an array of bytes (non-UTF-8 values). A field that
// appears more than once comes as an array of those and is not accepted.
func journalString(v json.RawMessage) (string, bool) {
	if len(v) == 0 || string(v) == "null" {
		return "", false
	}
	var s string
	if json.Unmarshal(v, &s) == nil {
		return s, true
	}
	var nums []int
	if json.Unmarshal(v, &nums) != nil {
		return "", false
	}
	raw := make([]byte, 0, len(nums))
	for _, n := range nums {
		if n < 0 || n > 255 {
			return "", false
		}
		raw = append(raw, byte(n))
	}
	return string(raw), true
}

// sshdTrusted: journald says root's sshd wrote this line.
func (e journalEntry) sshdTrusted() bool {
	uid, ok1 := journalString(e.UID)
	comm, ok2 := journalString(e.Comm)
	return ok1 && ok2 && uid == "0" && sshdComms[comm]
}

// parseJournal returns the trusted SSH auth events newer than since, and how many lines looked like sshd logins
// but were not written by root's sshd (for example `logger -t sshd` run by a user).
func parseJournal(b []byte, since time.Time) ([]AuthEvent, int) {
	return parseJournalCapped(b, since, maxEvents)
}

func parseJournalCapped(b []byte, since time.Time, max int) ([]AuthEvent, int) {
	out := []AuthEvent{}
	rejected := 0
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() && len(out) < max {
		var e journalEntry
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		msg, ok := journalString(e.Message)
		if !ok {
			continue
		}
		us, err := strconv.ParseInt(e.Realtime, 10, 64)
		if err != nil {
			continue
		}
		ts := time.UnixMicro(us).UTC()
		if !ts.After(since) {
			continue
		}
		ev, ok := parseSSHMessage(msg, ts)
		if !ok {
			continue
		}
		if !e.sshdTrusted() {
			rejected++
			continue
		}
		out = append(out, ev)
	}
	return out, rejected
}

var (
	// 2026-11-08T10:12:01.123456+00:00 host sshd[123]: msg   (rsyslog on Ubuntu 24.04 and newer)
	isoLineRE = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\S+)\s+\S+\s+sshd(?:-session)?(?:\[\d+\])?:\s+(.*)$`)
	// Nov  8 10:12:01 host sshd[123]: msg   (classic syslog, no year)
	bsdLineRE = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd(?:-session)?(?:\[\d+\])?:\s+(.*)$`)
)

func parseSyslog(b []byte, since, now time.Time) []AuthEvent {
	return parseSyslogCapped(b, since, now, maxEvents)
}

// parseSyslogCapped: now is the reference for the year of classic syslog lines.
func parseSyslogCapped(b []byte, since, now time.Time, max int) []AuthEvent {
	out := []AuthEvent{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() && len(out) < max {
		line := sc.Text()
		var ts time.Time
		var msg string
		if m := isoLineRE.FindStringSubmatch(line); m != nil {
			t, err := time.Parse(time.RFC3339Nano, m[1])
			if err != nil {
				continue
			}
			ts, msg = t.UTC(), m[2]
		} else if m := bsdLineRE.FindStringSubmatch(line); m != nil {
			stamp := strings.Join(strings.Fields(m[1]), " ") + " " + strconv.Itoa(now.Year())
			t, err := time.ParseInLocation("Jan 2 15:04:05 2006", stamp, time.Local)
			if err != nil {
				continue
			}
			if t.After(now.Add(24 * time.Hour)) { // December lines read in January
				t = t.AddDate(-1, 0, 0)
			}
			ts, msg = t.UTC(), m[2]
		} else {
			continue
		}
		if !ts.After(since) {
			continue
		}
		if ev, ok := parseSSHMessage(msg, ts); ok {
			out = append(out, ev)
		}
	}
	return out
}

var (
	acceptedRE    = regexp.MustCompile(`^Accepted (\S+) for (.*?) from (\S+) port \d+(?: ssh2)?(?::\s+(\S+)\s+(\S+))?`)
	failedInvRE   = regexp.MustCompile(`^Failed (\S+) for invalid user (.*?) from (\S+) port \d+`)
	failedRE      = regexp.MustCompile(`^Failed (\S+) for (.*?) from (\S+) port \d+`)
	invalidUserRE = regexp.MustCompile(`^Invalid user (.*?) from (\S+) port \d+`)
)

// parseSSHMessage turns one sshd log message into an event. Only Accepted, Failed and Invalid user
// lines count; everything else is ignored.
func parseSSHMessage(msg string, ts time.Time) (AuthEvent, bool) {
	ev := AuthEvent{TS: ts.UTC().Format(time.RFC3339Nano)}
	var ip string
	if m := acceptedRE.FindStringSubmatch(msg); m != nil {
		ev.Result, ev.Method, ev.User, ip = "ok", m[1], m[2], m[3]
		if strings.HasPrefix(m[5], "SHA256:") || strings.HasPrefix(m[5], "MD5:") {
			ev.KeyFP = m[5]
		}
	} else if m := failedInvRE.FindStringSubmatch(msg); m != nil {
		ev.Result, ev.Method, ev.User, ip, ev.InvalidUser = "failed", m[1], m[2], m[3], true
	} else if m := failedRE.FindStringSubmatch(msg); m != nil {
		ev.Result, ev.Method, ev.User, ip = "failed", m[1], m[2], m[3]
	} else if m := invalidUserRE.FindStringSubmatch(msg); m != nil {
		ev.Result, ev.Method, ev.User, ip, ev.InvalidUser = "failed", "none", m[1], m[2], true
	} else {
		return ev, false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ev, false
	}
	ev.IP = parsed.String()
	if len(ev.User) > 64 {
		ev.User = ev.User[:64]
	}
	if len(ev.Method) > 32 {
		ev.Method = ev.Method[:32]
	}
	sum := sha256.Sum256([]byte(ev.TS + "|" + msg))
	ev.ID = hex.EncodeToString(sum[:16])
	return ev, true
}

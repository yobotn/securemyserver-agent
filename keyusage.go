package main

import (
	"strconv"
	"strings"
	"time"
)

// Last-used data for keys comes from sshd's own lines:
//   Accepted publickey for <user> from <ip> port N ssh2: <TYPE> SHA256:<fp>
// On the first report after start the agent scans up to 90 days back; after that it updates from each
// report's auth events. The result is kept in memory only (the agent writes nothing to disk).
//
// From the journal only lines journald attributes to root's sshd count (_UID=0, _COMM sshd, sshd-session or
// sshd-auth; see parseJournal), so `logger` can't fake a recent use. Without a journal it reads auth.log (or secure)
// and its rotated copies, newest first, and the source is marked unverified: any user can write such a line.

type keyUse struct {
	TS time.Time
	IP string
}

const keyUsageDays = 90

// keyUsage maps user + "\x00" + fingerprint to the newest use seen.
var keyUsage = map[string]keyUse{}
var keyUsageSource = ""
var keyUsageVerified = false

// keyScanBudget caps the bytes of syslog files the first scan reads, all files together.
const keyScanBudget = 96 << 20

func noteKeyUse(m map[string]keyUse, user, fp, ip string, ts time.Time) {
	if !strings.HasPrefix(fp, "SHA256:") || len(m) >= 20000 {
		return
	}
	id := user + "\x00" + fp
	if cur, ok := m[id]; !ok || ts.After(cur.TS) {
		m[id] = keyUse{TS: ts, IP: ip}
	}
}

func noteKeyEvents(m map[string]keyUse, events []AuthEvent) {
	for _, e := range events {
		if e.Result != "ok" || e.Method != "publickey" || e.KeyFP == "" {
			continue
		}
		if ts, err := time.Parse(time.RFC3339Nano, e.TS); err == nil {
			noteKeyUse(m, e.User, e.KeyFP, e.IP, ts)
		}
	}
}

// updateKeyUsage folds this report's events in, and on the first call scans further back.
func updateKeyUsage(events []AuthEvent, now time.Time) {
	if keyUsageSource == "" {
		keyUsageSource, keyUsageVerified = scanKeyUsage(keyUsage, now.AddDate(0, 0, -keyUsageDays), now)
	}
	noteKeyEvents(keyUsage, events)
}

// scanKeyUsage returns the source it read and whether that source proves who wrote each line.
func scanKeyUsage(m map[string]keyUse, since, now time.Time) (string, bool) {
	if journalRunning() {
		base := append([]string{"--since", "@" + strconv.FormatInt(since.Unix(), 10)}, journalSSHDMatch...)
		// --grep needs journalctl built with PCRE2; fall back to reading every line.
		out, err := runJournal(60*time.Second, append([]string{"--grep", "Accepted publickey"}, base...)...)
		if err != nil {
			out, err = runJournal(60*time.Second, base...)
		}
		if err == nil {
			ev, _ := parseJournalCapped(out, since, 1<<30)
			noteKeyEvents(m, ev)
			return "journal", true
		}
	}
	for _, p := range []string{"/var/log/auth.log", "/var/log/secure"} {
		files := rotatedLogs(p)
		if len(files) == 0 {
			continue
		}
		scanSyslogFiles(m, files, since, now)
		return p, false
	}
	return "none", false
}

// scanSyslogFiles reads files newest first until one is older than since or the byte budget is spent.
func scanSyslogFiles(m map[string]keyUse, files []logFile, since, now time.Time) {
	budget := keyScanBudget
	for i, f := range files {
		if budget <= 0 {
			return
		}
		// A rotated file last written before since holds nothing newer (the current file is always read).
		if i > 0 && f.mod.Before(since) {
			return
		}
		b, err := readLogFile(f.path, min(budget, 32<<20))
		if err != nil {
			continue
		}
		budget -= len(b)
		// Classic syslog lines carry no year: a rotated file's lines belong to the year it was last written.
		ref := f.mod
		if ref.After(now) {
			ref = now
		}
		noteKeyEvents(m, parseSyslogCapped(b, since, ref, 1<<30))
	}
}

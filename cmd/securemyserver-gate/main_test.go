package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"securemyserver.com/securemyserver/internal/gatelog"
)

const conn = "203.0.113.7 51234 10.0.0.2 22"

func setup(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "gate.log")
	journalSocket = filepath.Join(dir, "no-journal")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	timeout, maxOutput = gatelog.Timeout, gatelog.MaxOutputBytes
	return dir
}

func lines(t *testing.T) []gatelog.Line {
	t.Helper()
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	var out []gatelog.Line
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		var l gatelog.Line
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatalf("bad line %q: %v", sc.Text(), err)
		}
		out = append(out, l)
	}
	return out
}

func TestRunsAndLogs(t *testing.T) {
	setup(t)
	var out, errb bytes.Buffer
	code := gate("echo hello; exit 3", conn, strings.NewReader(""), &out, &errb)
	if code != 3 || out.String() != "hello\n" {
		t.Fatalf("code %d out %q err %q", code, out.String(), errb.String())
	}
	ls := lines(t)
	if len(ls) != 2 || ls[0].Ev != "start" || ls[1].Ev != "end" || ls[0].ID != ls[1].ID {
		t.Fatalf("lines %+v", ls)
	}
	if ls[0].Cmd != "echo hello; exit 3" || ls[0].FromIP != "203.0.113.7" || len(ls[0].Session) != 16 || len(ls[0].ID) != 32 {
		t.Fatalf("start %+v", ls[0])
	}
	if ls[1].Exit == nil || *ls[1].Exit != 3 || ls[1].BytesOut != 6 || ls[1].Truncated || ls[1].TimedOut {
		t.Fatalf("end %+v", ls[1])
	}
}

func TestInteractiveRefused(t *testing.T) {
	setup(t)
	var out, errb bytes.Buffer
	if code := gate("", conn, strings.NewReader(""), &out, &errb); code != 1 {
		t.Fatalf("code %d", code)
	}
	if !strings.Contains(errb.String(), "interactive shells are not allowed") {
		t.Fatalf("stderr %q", errb.String())
	}
	ls := lines(t)
	if len(ls) != 1 || ls[0].Ev != "refused" || ls[0].Reason != "interactive" {
		t.Fatalf("lines %+v", ls)
	}
}

func TestTooLongRefused(t *testing.T) {
	dir := setup(t)
	marker := filepath.Join(dir, "ran")
	cmd := "touch " + marker + " #" + strings.Repeat("x", gatelog.MaxCommandChars)
	var out, errb bytes.Buffer
	if code := gate(cmd, conn, strings.NewReader(""), &out, &errb); code != 1 {
		t.Fatalf("code %d", code)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("over-limit command ran")
	}
	ls := lines(t)
	if len(ls) != 1 || ls[0].Reason != "too_long" || ls[0].CmdLen != len(cmd) || len(ls[0].Cmd) > 512 {
		t.Fatalf("lines %+v", ls)
	}
}

func TestFailClosed(t *testing.T) {
	dir := setup(t)
	marker := filepath.Join(dir, "ran")
	for name, breakLog := range map[string]func(){
		"missing":   func() { os.Remove(logPath) },
		"read-only": func() { os.Chmod(logPath, 0o400) },
		"symlink": func() {
			os.Remove(logPath)
			os.Symlink(filepath.Join(dir, "elsewhere"), logPath)
			os.WriteFile(filepath.Join(dir, "elsewhere"), nil, 0o600)
		},
	} {
		setup(t)
		breakLog()
		if os.Getuid() == 0 && name == "read-only" {
			continue // root ignores file modes
		}
		var out, errb bytes.Buffer
		code := gate("touch "+marker, conn, strings.NewReader(""), &out, &errb)
		if code != 1 || !strings.Contains(errb.String(), "command NOT run") {
			t.Fatalf("%s: code %d stderr %q", name, code, errb.String())
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatalf("%s: command ran without an audit line", name)
		}
	}
}

func TestTimeoutKillsGroup(t *testing.T) {
	dir := setup(t)
	timeout = 500 * time.Millisecond
	marker := filepath.Join(dir, "late")
	var out, errb bytes.Buffer
	started := time.Now()
	// The background child is in the same process group and must die too.
	code := gate("(sleep 2; touch "+marker+") & sleep 30", conn, strings.NewReader(""), &out, &errb)
	if code != 124 || time.Since(started) > 5*time.Second {
		t.Fatalf("code %d after %s", code, time.Since(started))
	}
	time.Sleep(2500 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("background child survived the timeout")
	}
	ls := lines(t)
	if len(ls) != 2 || !ls[1].TimedOut || *ls[1].Exit != 124 {
		t.Fatalf("lines %+v", ls)
	}
}

func TestOutputCap(t *testing.T) {
	setup(t)
	maxOutput = 1000
	var out, errb bytes.Buffer
	code := gate("head -c 5000 /dev/zero; head -c 100 /dev/zero >&2", conn, strings.NewReader(""), &out, &errb)
	if code != 0 || out.Len() != 1000 {
		t.Fatalf("code %d stdout %d", code, out.Len())
	}
	if !strings.Contains(errb.String(), "output truncated at 1000 bytes (5100 bytes produced)") {
		t.Fatalf("stderr %q", errb.String())
	}
	ls := lines(t)
	if !ls[1].Truncated || ls[1].BytesOut != 5100 {
		t.Fatalf("end %+v", ls[1])
	}
}

func TestSanitizedCommandInLog(t *testing.T) {
	setup(t)
	var out, errb bytes.Buffer
	gate("echo \x1b[2Jhi"+string(rune(0x202e))+" #\nexit 0", conn, strings.NewReader(""), &out, &errb)
	ls := lines(t)
	if ls[0].Cmd != `echo \x1b[2Jhi`+`\u202e #`+"\nexit 0" {
		t.Fatalf("cmd %q", ls[0].Cmd)
	}
}

func TestHelpers(t *testing.T) {
	if fromIP("2001:db8::1 5000 2001:db8::2 22") != "2001:db8::1" || fromIP("") != "" || fromIP("1.2.3.4;rm 1 2 3") != "" {
		t.Fatal("fromIP")
	}
	if sessionID(conn, 10) == sessionID(conn, 11) || sessionID(conn, 10) != sessionID(conn, 10) {
		t.Fatal("sessionID")
	}
}

func TestUsesSudo(t *testing.T) {
	for cmd, want := range map[string]bool{
		"sudo -n systemctl reload nginx":  true,
		"cd /etc && sudo sed -i s/a/b/ x": true,
		"bash -c 'sudo true'":             true,
		"/usr/bin/sudo -n true":           true,
		"sudoedit /etc/hosts":             true,
		"echo pseudo; ls sudoers.d":       false,
		"cat /etc/sudoers.d/x":            false,
		"uname -a":                        false,
	} {
		if got := usesSudo(cmd); got != want {
			t.Errorf("usesSudo(%q) = %v, want %v", cmd, got, want)
		}
	}
}

func TestSudoNeedsCheckpoint(t *testing.T) {
	dir := setup(t)
	marker := filepath.Join(dir, "ran")
	old := checkpointCmd
	t.Cleanup(func() { checkpointCmd = old })
	// No checkpoint (the binary is missing, sudo refuses, or the disk is full): the command does not run.
	checkpointCmd = []string{"/bin/sh", "-c", "echo 'disk full' >&2; exit 1", "x", "x", "", "x"}
	var out, errb bytes.Buffer
	if code := gate("sudo true; touch "+marker, conn, strings.NewReader(""), &out, &errb); code != 1 || !strings.Contains(errb.String(), "command NOT run") || !strings.Contains(errb.String(), "disk full") {
		t.Fatalf("code %d err %q", code, errb.String())
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("command ran without a checkpoint")
	}
	ls := lines(t)
	if len(ls) != 1 || ls[0].Ev != "refused" || ls[0].Reason != "no_checkpoint" || !strings.Contains(ls[0].Cmd, "sudo true") {
		t.Fatalf("lines %+v", ls)
	}
	// A checkpoint: it runs, and the first one says so. Commands without sudo never ask.
	checkpointCmd = []string{"/bin/sh", "-c", "echo created 20261108-100000-abcd 12", "x", "x", "", "x"}
	errb.Reset()
	if code := gate("echo sudo-free; touch "+marker, conn, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("plain: %d %q", code, errb.String())
	}
	if strings.Contains(errb.String(), "checkpoint") {
		t.Fatal("no checkpoint for a command without sudo")
	}
	if code := gate("sudo true || true", conn, strings.NewReader(""), &out, &errb); !strings.Contains(errb.String(), "checkpoint 20261108-100000-abcd saved") {
		t.Fatalf("code %d err %q", code, errb.String())
	}
	checkpointCmd = []string{"/bin/sh", "-c", "echo nonsense", "x", "x", "", "x"}
	if code := gate("sudo true", conn, strings.NewReader(""), &out, &errb); code != 1 {
		t.Fatal("an unexpected answer must fail closed")
	}
}

// With journald running, lines go to its socket in the native protocol and not to the file; when the socket stops
// taking them, the command does not run.
func TestJournalWriteAndFailClosed(t *testing.T) {
	dir := setup(t)
	journalSocket = filepath.Join(dir, "journal.sock")
	l, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: journalSocket, Net: "unixgram"})
	if err != nil {
		t.Skip("no unix datagram sockets here:", err)
	}
	got := make(chan string, 4)
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, err := l.Read(buf)
			if err != nil {
				return
			}
			got <- string(buf[:n])
		}
	}()
	var out, errb bytes.Buffer
	if code := gate("echo hi", conn, strings.NewReader(""), &out, &errb); code != 0 || out.String() != "hi\n" {
		t.Fatalf("code %d out %q err %q", code, out.String(), errb.String())
	}
	start := <-got
	if !strings.Contains(start, "SYSLOG_IDENTIFIER=securemyserver-gate\n") || !strings.Contains(start, "SECUREMYSERVER_GATE_EV=start\n") ||
		!strings.HasPrefix(start, `MESSAGE={"v":1,"ev":"start"`) {
		t.Fatalf("start entry %q", start)
	}
	if end := <-got; !strings.Contains(end, "SECUREMYSERVER_GATE_EV=end\n") {
		t.Fatalf("end entry %q", end)
	}
	if b, _ := os.ReadFile(logPath); len(b) != 0 {
		t.Fatalf("file written too: %q", b)
	}
	// The socket is there but nobody reads it: the write fails and the command is refused.
	l.Close()
	if _, err := os.Lstat(journalSocket); err != nil {
		t.Skip("the socket file went with the listener")
	}
	out.Reset()
	errb.Reset()
	if code := gate("echo should-not-run", conn, strings.NewReader(""), &out, &errb); code == 0 || out.Len() != 0 {
		t.Fatalf("ran without a journal entry: code %d out %q", code, out.String())
	}
}

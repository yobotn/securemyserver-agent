// securemyserver-gate is the forced command for the securemyserver-ai user:
//
//	restrict,from="<ip>",expiry-time="<date>",command="/usr/lib/securemyserver/securemyserver-gate" ssh-ed25519 AAAA... securemyserver-ai
//
// sshd runs it for every connection with that key; the platform never runs it. It logs each command before
// running it (fail closed: no log entry, no command): to the systemd journal when journald runs, where journald
// records its uid and executable so the agent can tell its entries from forged ones, else to
// /var/log/securemyserver/gate.log. It also enforces a length limit, a timeout and an output cap, then runs the command with /bin/sh -c.
//
// It is an audit log and a set of limits, not a sandbox. The command runs as securemyserver-ai with whatever
// that user may do; the sudo presets in /etc/sudoers.d/securemyserver-ai are the real boundary.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe"

	"securemyserver.com/securemyserver/internal/gatelog"
)

// Package variables so the tests can point them elsewhere. Nothing at run time changes them.
var (
	logPath = gatelog.Path
	// journalSocket: when it exists (journald runs), lines go to the journal and never to logPath.
	journalSocket = gatelog.JournalSocket
	timeout       = gatelog.Timeout
	maxOutput     = int64(gatelog.MaxOutputBytes)
	shell         = "/bin/sh"
	now           = time.Now
	// checkpointCmd is the exact command the sudoers preset allows: sudo -n <agent> checkpoint --session <id> --auto.
	checkpointCmd     = []string{gatelog.SudoPath, "-n", gatelog.AgentPath, "checkpoint", "--session", "", "--auto"}
	checkpointTimeout = 90 * time.Second
)

// sudoRE finds sudo (or sudoedit) as a word anywhere in the command, with or without a path: "sudo x",
// "cd /etc && sudo x", "bash -c 'sudo x'", "/usr/bin/sudo x". It is a heuristic on the text: a command that builds
// the word at run time (a variable, an alias) runs without a checkpoint. It can't change root-owned files without
// sudo either way, and the sudo presets stay the boundary.
var sudoRE = regexp.MustCompile(`(?:^|[^A-Za-z0-9_.-])(?:[A-Za-z0-9_./-]*/)?sudo(?:edit)?(?:$|[^A-Za-z0-9_.-])`)

func usesSudo(cmd string) bool { return sudoRE.MatchString(cmd) }

// checkpoint asks the agent binary, through sudo, for the session checkpoint. It returns a note for the AI when a
// new checkpoint was saved, and an error when none could be saved.
func checkpoint(session string) (string, error) {
	args := append([]string{}, checkpointCmd...)
	args[5] = session
	c := exec.Command(args[0], args[1:]...)
	c.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	c.Stdin = nil
	var out, errb strings.Builder
	c.Stdout, c.Stderr = &limitedBuilder{b: &out, max: 4096}, &limitedBuilder{b: &errb, max: 4096}
	if err := c.Start(); err != nil {
		return "", fmt.Errorf("cannot run %s: %v", args[0], err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			msg := strings.TrimSpace(errb.String())
			if msg == "" {
				msg = err.Error()
			}
			return "", errors.New(gatelog.SanitizeCommand(msg, 300))
		}
	case <-time.After(checkpointTimeout):
		_ = c.Process.Kill()
		return "", fmt.Errorf("the checkpoint took longer than %s", checkpointTimeout)
	}
	f := strings.Fields(out.String())
	switch {
	case len(f) >= 2 && f[0] == "created":
		return "checkpoint " + gatelog.SanitizeCommand(f[1], 40) + " saved before the first sudo of this AI session (the owner can undo the session in the dashboard)", nil
	case len(f) >= 2 && f[0] == "open":
		return "", nil
	}
	return "", errors.New("unexpected answer from securemyserver checkpoint")
}

type limitedBuilder struct {
	b   *strings.Builder
	max int
}

func (l *limitedBuilder) Write(p []byte) (int, error) {
	if room := l.max - l.b.Len(); room > 0 {
		if len(p) > room {
			l.b.Write(p[:room])
		} else {
			l.b.Write(p)
		}
	}
	return len(p), nil
}

func main() {
	os.Exit(gate(os.Getenv("SSH_ORIGINAL_COMMAND"), os.Getenv("SSH_CONNECTION"), os.Stdin, os.Stdout, os.Stderr))
}

func say(stderr io.Writer, msg string) {
	fmt.Fprintf(stderr, "securemyserver-gate: %s\n", msg)
}

func gate(cmd, conn string, stdin io.Reader, stdout, stderr io.Writer) int {
	base := gatelog.Line{
		V:       1,
		ID:      randomID(),
		Session: sessionID(conn, os.Getppid()),
		FromIP:  fromIP(conn),
		User:    gatelog.SanitizeCommand(os.Getenv("USER"), 64),
		UID:     os.Getuid(),
		CmdLen:  utf8.RuneCountInString(cmd),
	}

	if strings.TrimSpace(cmd) == "" {
		l := base
		l.Ev, l.Reason = "refused", "interactive"
		_ = writeLine(l) // best effort: nothing runs either way
		say(stderr, "interactive shells are not allowed for this key (tier 1). Run one command per connection, for example: ssh securemyserver-ai@server 'uname -a'")
		return 1
	}
	if base.CmdLen > gatelog.MaxCommandChars {
		l := base
		l.Ev, l.Reason = "refused", "too_long"
		l.Cmd = gatelog.SanitizeCommand(cmd, 512) // a prefix is enough to see what it was
		_ = writeLine(l)
		say(stderr, fmt.Sprintf("command refused: %d characters, the limit is %d. Split it, or copy a script file first and run that.", base.CmdLen, gatelog.MaxCommandChars))
		return 1
	}

	// Before a command that uses sudo, a checkpoint of the server's config (D-015, gap 10). The first sudo of an AI
	// session saves it; later ones only record activity. Fail closed: no checkpoint, no command.
	if usesSudo(cmd) {
		note, err := checkpoint(base.Session)
		if err != nil {
			l := base
			l.Ev, l.Reason = "refused", "no_checkpoint"
			l.Cmd = gatelog.SanitizeCommand(cmd, gatelog.MaxLoggedCommand)
			_ = writeLine(l)
			say(stderr, "command NOT run: it uses sudo, and the checkpoint that makes it undoable could not be saved ("+err.Error()+"). Ask the owner to check `sudo securemyserver status` and the sudoers preset.")
			return 1
		}
		if note != "" {
			say(stderr, note)
		}
	}

	start := base
	start.Ev = "start"
	start.Cmd = gatelog.SanitizeCommand(cmd, gatelog.MaxLoggedCommand)
	if err := writeLine(start); err != nil {
		// Fail closed: a command that cannot be audited does not run.
		say(stderr, "audit log unavailable ("+err.Error()+"); command NOT run. The owner sees an audit gap in the dashboard.")
		return 1
	}

	res := execute(cmd, stdin, stdout, stderr)

	end := base
	end.Ev = "end"
	end.CmdLen = 0
	end.Exit = &res.exit
	end.DurationMS = res.duration.Milliseconds()
	end.BytesOut = res.bytesOut
	end.Truncated = res.truncated
	end.TimedOut = res.timedOut
	end.Reason = res.signal
	if err := writeLine(end); err != nil {
		say(stderr, "could not write the end of this command to the audit log: "+err.Error())
	}
	return res.exit
}

type result struct {
	exit      int
	duration  time.Duration
	bytesOut  int64
	truncated bool
	timedOut  bool
	signal    string
}

func execute(cmdline string, stdin io.Reader, stdout, stderr io.Writer) result {
	started := now()
	c := exec.Command(shell, "-c", cmdline)
	c.Stdin = stdin
	budget := &outputBudget{left: maxOutput}
	c.Stdout = &cappedWriter{w: stdout, b: budget}
	c.Stderr = &cappedWriter{w: stderr, b: budget}
	// Own process group, so a timeout kills the command and everything it started in the group.
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// If a background child keeps stdout open after the shell exits, stop waiting for it.
	c.WaitDelay = 2 * time.Second

	if err := c.Start(); err != nil {
		say(stderr, "could not start /bin/sh: "+err.Error())
		return result{exit: 126, duration: now().Sub(started)}
	}
	pgid := c.Process.Pid

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT, syscall.SIGPIPE)
	defer signal.Stop(sigs)
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var res result
	var waitErr error
loop:
	for {
		select {
		case waitErr = <-done:
			break loop
		case <-timer.C:
			res.timedOut = true
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		case s := <-sigs:
			// The client went away or we were asked to stop: pass it on to the whole group.
			if sig, ok := s.(syscall.Signal); ok {
				res.signal = sig.String()
				_ = syscall.Kill(-pgid, sig)
			}
		}
	}
	// Anything left in the group (background jobs) goes too.
	_ = syscall.Kill(-pgid, syscall.SIGKILL)

	res.duration = now().Sub(started)
	res.bytesOut, res.truncated = budget.total, budget.truncated
	res.exit = exitCode(c, waitErr)
	if res.timedOut {
		res.exit = 124
		say(stderr, fmt.Sprintf("command killed after %s (timeout)", timeout))
	}
	if res.truncated {
		say(stderr, fmt.Sprintf("output truncated at %d bytes (%d bytes produced)", maxOutput, res.bytesOut))
	}
	return res
}

func exitCode(c *exec.Cmd, err error) int {
	if c.ProcessState == nil {
		return 125
	}
	if ws, ok := c.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	if code := c.ProcessState.ExitCode(); code >= 0 {
		return code
	}
	if err != nil && !errors.Is(err, exec.ErrWaitDelay) {
		return 125
	}
	return 0
}

// outputBudget is shared by stdout and stderr: 1 MB in total.
type outputBudget struct {
	mu        sync.Mutex
	left      int64
	total     int64
	truncated bool
}

type cappedWriter struct {
	w io.Writer
	b *outputBudget
}

// Write passes bytes through until the budget is spent, then drops the rest but keeps counting, so
// the command never blocks on a full pipe.
func (c *cappedWriter) Write(p []byte) (int, error) {
	c.b.mu.Lock()
	c.b.total += int64(len(p))
	n := int64(len(p))
	if n > c.b.left {
		n = c.b.left
		c.b.truncated = true
	}
	c.b.left -= n
	c.b.mu.Unlock()
	if n > 0 {
		_, _ = c.w.Write(p[:n]) // a closed client is not the command's problem
	}
	return len(p), nil
}

// writeLine records one JSON line: in the systemd journal when journald runs, else appended to the audit log.
// Either way an error means the line was not recorded, and the caller does not run the command.
func writeLine(l gatelog.Line) error {
	l.TS = now().UTC().Format(time.RFC3339Nano)
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	if st, err := os.Lstat(journalSocket); err == nil && st.Mode()&os.ModeSocket != 0 {
		return writeJournal(l, b)
	}
	return writeFile(append(b, '\n'))
}

// writeJournal sends one entry to journald over its native socket. journald adds _UID, _EXE and the other
// trusted fields from the socket credentials; the agent accepts only entries from this binary as securemyserver-ai.
func writeJournal(l gatelog.Line, line []byte) error {
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: journalSocket, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("journal: %v", err)
	}
	defer c.Close()
	msg := gatelog.JournalMessage([][2]string{
		{"MESSAGE", string(line)},
		{"SYSLOG_IDENTIFIER", gatelog.Identifier},
		{"PRIORITY", "6"},
		{"SECUREMYSERVER_GATE_EV", l.Ev},
		{"SECUREMYSERVER_GATE_ID", l.ID},
	})
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Write(msg)
	if err == nil && n != len(msg) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("journal: %v", err)
	}
	waitJournalRead(c)
	return nil
}

// journalReadWait bounds how long the gate waits for journald to take an entry off the socket.
var journalReadWait = 2 * time.Second

// waitJournalRead keeps the gate alive until journald has received the entry. journald reads _EXE and _COMM from
// /proc/<pid> when it processes a datagram, so a gate that exited first (a fast command) would leave them out, and
// the agent would count its own entry as unverified. SIOCOUTQ on a unix socket is the bytes the receiver has not
// taken yet; journald processes an entry right after it takes it, so a short pause after that covers the rest.
func waitJournalRead(c *net.UnixConn) {
	raw, err := c.SyscallConn()
	if err != nil {
		return
	}
	deadline := time.Now().Add(journalReadWait)
	for time.Now().Before(deadline) {
		var queued int32
		var ierr syscall.Errno
		if raw.Control(func(fd uintptr) {
			_, _, ierr = syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCOUTQ, uintptr(unsafe.Pointer(&queued)))
		}) != nil || ierr != 0 {
			return
		}
		if queued == 0 {
			time.Sleep(20 * time.Millisecond)
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// writeFile appends one JSON line to the audit log in a single write. The file must already exist
// (root creates it; see daemon/README.md); securemyserver-gate never creates or follows a symlink to it.
func writeFile(b []byte) error {
	f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		f.Close()
		return errors.New("audit log is not a regular file")
	}
	n, err := f.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// No randomness means something is badly wrong; a time-based id still keeps lines apart.
		return fmt.Sprintf("%032x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// sessionID groups the commands of one SSH connection: sshd sets SSH_CONNECTION per connection and
// every channel of a multiplexed connection is a child of the same sshd process.
func sessionID(conn string, ppid int) string {
	sum := sha256.Sum256([]byte(conn + "|" + strconv.Itoa(ppid)))
	return hex.EncodeToString(sum[:8])
}

// fromIP is the client address: the first field of SSH_CONNECTION ("ip port ip port").
func fromIP(conn string) string {
	f := strings.Fields(conn)
	if len(f) == 0 {
		return ""
	}
	ip := f[0]
	for _, r := range ip {
		if !strings.ContainsRune("0123456789abcdefABCDEF.:", r) {
			return ""
		}
	}
	if len(ip) > 45 {
		return ""
	}
	return ip
}

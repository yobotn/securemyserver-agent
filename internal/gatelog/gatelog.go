// Package gatelog is the shared format of /var/log/securemyserver/gate.log: securemyserver-gate writes it,
// securemyserver agent reads it and reports it. One JSON object per line.
package gatelog

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	Dir      = "/var/log/securemyserver"
	Path     = Dir + "/gate.log"
	GatePath = "/usr/lib/securemyserver/securemyserver-gate"
	User     = "securemyserver-ai"
	// AgentPath is the securemyserver binary securemyserver-gate asks, through sudo, for a checkpoint before the
	// first sudo command of an AI session. The sudoers preset allows exactly that command form.
	AgentPath = "/usr/local/sbin/securemyserver"
	SudoPath  = "/usr/bin/sudo"

	MaxCommandChars = 5000             // longer commands are refused
	MaxOutputBytes  = 1 << 20          // stdout + stderr; the rest is dropped and the run is marked truncated
	Timeout         = 60 * time.Second // then the whole process group is killed
	// MaxLoggedCommand caps the sanitized command in the log (escapes can make it longer than the input).
	MaxLoggedCommand = 8000
)

// Line is one log entry. ev is "start" (written before the command runs; if it cannot be written the
// command does not run), "end" (after it finished) or "refused" (not run at all).
type Line struct {
	V          int    `json:"v"`
	Ev         string `json:"ev"`
	ID         string `json:"id"`      // 32 hex chars, random, shared by start and end
	TS         string `json:"ts"`      // RFC 3339, UTC
	Session    string `json:"session"` // 16 hex chars: sha256(SSH_CONNECTION | parent pid)
	FromIP     string `json:"from_ip,omitempty"`
	User       string `json:"user,omitempty"`
	UID        int    `json:"uid"`
	Cmd        string `json:"cmd,omitempty"` // sanitized, see SanitizeCommand
	CmdLen     int    `json:"cmd_len"`       // characters in the original command
	Exit       *int   `json:"exit,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
	BytesOut   int64  `json:"bytes_out,omitempty"` // all bytes the command produced, including dropped ones
	Truncated  bool   `json:"truncated,omitempty"`
	TimedOut   bool   `json:"timed_out,omitempty"`
	Reason     string `json:"reason,omitempty"` // refused: interactive | too_long | no_checkpoint; end: signal name
}

// SanitizeCommand keeps newlines and tabs, and turns every other control character, invalid UTF-8,
// C1 control and bidi override into a visible escape (\x1b, \u202e), so a command cannot hide text
// from whoever reads the log or the dashboard. The result is capped at max bytes.
func SanitizeCommand(s string, max int) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		var piece string
		switch {
		case r == utf8.RuneError && size <= 1:
			piece = fmt.Sprintf(`\x%02x`, s[i])
		case r == '\n' || r == '\t':
			piece = string(r)
		case r < 0x20 || r == 0x7f:
			piece = fmt.Sprintf(`\x%02x`, r)
		case (r >= 0x80 && r <= 0x9f) || IsBidiControl(r):
			piece = fmt.Sprintf(`\u%04x`, r)
		default:
			piece = s[i : i+size]
		}
		if b.Len()+len(piece) > max {
			break
		}
		b.WriteString(piece)
		i += size
	}
	return b.String()
}

func IsBidiControl(r rune) bool {
	return (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == 0x200e || r == 0x200f || r == 0x061c
}

// The systemd journal is where securemyserver-gate writes when journald runs (agent 0.8.0). journald stamps every
// entry with the sender's uid and executable (_UID, _EXE), which a client cannot set, so the agent can tell the
// gate's own entries from lines securemyserver-ai writes itself. Without journald the gate appends to Path.
const (
	JournalSocket = "/run/systemd/journal/socket"
	Identifier    = "securemyserver-gate"
)

// JournalMessage encodes fields in journald's native protocol: KEY=value lines, or for a value with a newline
// KEY, a newline, its length as 64-bit little endian, the value and a newline. Keys are upper case ASCII.
func JournalMessage(fields [][2]string) []byte {
	var b []byte
	for _, f := range fields {
		if strings.ContainsRune(f[1], '\n') {
			b = append(b, f[0]...)
			b = append(b, '\n')
			n := uint64(len(f[1]))
			for i := 0; i < 8; i++ {
				b = append(b, byte(n>>(8*i)))
			}
			b = append(b, f[1]...)
			b = append(b, '\n')
			continue
		}
		b = append(b, f[0]...)
		b = append(b, '=')
		b = append(b, f[1]...)
		b = append(b, '\n')
	}
	return b
}

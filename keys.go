package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// Key inventory: for every user with a login shell (and root), the keys in their authorized_keys
// files. The agent sends the fingerprint, type, size, options and a cleaned comment. It never sends the
// public key itself, and it never reads private keys.

const (
	maxKeysTotal   = 2000
	maxKeysPerFile = 200
	maxCommentLen  = 128
)

type SSHKeys struct {
	// Complete is false when a key file existed but could not be read, so the platform must not
	// treat missing keys as removed.
	Complete      bool     `json:"complete"`
	UsageSource   string   `json:"usage_source"`   // where last-used data came from
	UsageVerified bool     `json:"usage_verified"` // true only for the journal; auth.log lines can be written with logger by any user
	Keys          []SSHKey `json:"keys"`
}

type SSHKey struct {
	User        string     `json:"user"`
	File        string     `json:"file"`
	Line        int        `json:"line"`
	Type        string     `json:"type"`
	Bits        int        `json:"bits"`
	Fingerprint string     `json:"fingerprint"` // SHA256:<base64, no padding>, like ssh-keygen -lf
	Comment     string     `json:"comment"`
	Options     KeyOptions `json:"options"`
	// UserCanEdit: the user owns the key file, its directory or the home directory, so they can
	// change their own key options (expected for humans, a problem for securemyserver-ai).
	UserCanEdit bool   `json:"user_can_edit"`
	LastUsedAt  string `json:"last_used_at,omitempty"`
	LastFromIP  string `json:"last_from_ip,omitempty"`
}

type KeyOptions struct {
	Restrict        bool     `json:"restrict"`
	From            []string `json:"from,omitempty"`
	ExpiryTime      string   `json:"expiry_time,omitempty"` // raw value, YYYYMMDD[HHMM[SS]][Z]
	ExpiresAt       string   `json:"expires_at,omitempty"`  // RFC 3339, in the server's time zone
	Command         string   `json:"command,omitempty"`
	VerifyRequired  bool     `json:"verify_required"`
	NoTouchRequired bool     `json:"no_touch_required"`
	Other           []string `json:"other,omitempty"` // names only of other options (values not sent)
}

var keyTypes = map[string]bool{
	"ssh-rsa": true, "ssh-dss": true, "ssh-ed25519": true,
	"ecdsa-sha2-nistp256": true, "ecdsa-sha2-nistp384": true, "ecdsa-sha2-nistp521": true,
	"sk-ssh-ed25519@openssh.com": true, "sk-ecdsa-sha2-nistp256@openssh.com": true,
	"ssh-rsa-cert-v01@openssh.com": true, "ssh-dss-cert-v01@openssh.com": true,
	"ssh-ed25519-cert-v01@openssh.com": true, "ecdsa-sha2-nistp256-cert-v01@openssh.com": true,
	"ecdsa-sha2-nistp384-cert-v01@openssh.com": true, "ecdsa-sha2-nistp521-cert-v01@openssh.com": true,
	"sk-ssh-ed25519-cert-v01@openssh.com": true, "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com": true,
}

// keyOwner is one account whose authorized_keys files are read.
type keyOwner struct {
	Name string
	UID  int
	Home string
}

// collectKeys reads every key owner's authorized_keys files. authorizedKeysFile is the
// `sshd -T` value (space separated, %h %u %U %% tokens); empty means the OpenSSH default.
func collectKeys(owners []keyOwner, authorizedKeysFile string, usage map[string]keyUse, usageSource string, usageVerified bool) *SSHKeys {
	out := &SSHKeys{Complete: true, UsageSource: usageSource, UsageVerified: usageVerified, Keys: []SSHKey{}}
	seen := map[string]bool{}
	for _, o := range owners {
		for _, path := range keyFilePaths(authorizedKeysFile, o) {
			b, canEdit, err := readKeyFile(path, o.UID)
			if err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					out.Complete = false
				}
				continue
			}
			for _, k := range parseAuthorizedKeys(b) {
				id := o.Name + "\x00" + k.Fingerprint
				if seen[id] || len(out.Keys) >= maxKeysTotal {
					continue
				}
				seen[id] = true
				k.User, k.File, k.UserCanEdit = o.Name, path, canEdit
				if u, ok := usage[id]; ok {
					k.LastUsedAt, k.LastFromIP = u.TS.UTC().Format(time.RFC3339), u.IP
				}
				out.Keys = append(out.Keys, k)
			}
		}
	}
	return out
}

// keyOwnersFrom lists users with a login shell plus root, from /etc/passwd.
func keyOwnersFrom(passwd []byte) []keyOwner {
	out := []keyOwner{}
	sc := bufio.NewScanner(bytes.NewReader(passwd))
	for sc.Scan() {
		f := strings.Split(sc.Text(), ":")
		if len(f) < 7 || strings.HasPrefix(f[0], "#") {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil || (noLoginShells[strings.TrimSpace(f[6])] && uid != 0) {
			continue
		}
		if len(out) < 500 {
			out = append(out, keyOwner{Name: f[0], UID: uid, Home: f[5]})
		}
	}
	return out
}

func keyFilePaths(setting string, o keyOwner) []string {
	setting = strings.TrimSpace(setting)
	if setting == "" {
		setting = ".ssh/authorized_keys .ssh/authorized_keys2"
	}
	if setting == "none" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, tok := range strings.Fields(setting) {
		p := expandKeyPathTokens(tok, o)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = filepath.Join(o.Home, p)
		}
		p = filepath.Clean(p)
		if !seen[p] && len(out) < 8 {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func expandKeyPathTokens(s string, o keyOwner) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'h':
			b.WriteString(o.Home)
		case 'u':
			b.WriteString(o.Name)
		case 'U':
			b.WriteString(strconv.Itoa(o.UID))
		case '%':
			b.WriteByte('%')
		default:
			return "" // unknown token: sshd would refuse it too
		}
	}
	return b.String()
}

// readKeyFile reads a regular file without blocking on FIFOs, and reports whether the user can edit
// it (owns the file, its directory or the directory above that).
func readKeyFile(path string, uid int) ([]byte, bool, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if !st.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%s is not a regular file", path)
	}
	b, err := readCapped(path, 1<<20)
	if err != nil {
		return nil, false, err
	}
	canEdit := false
	for p, i := path, 0; i < 3; p, i = filepath.Dir(p), i+1 {
		if s, err := os.Stat(p); err == nil {
			if sys, ok := s.Sys().(*syscall.Stat_t); ok && (int(sys.Uid) == uid && uid != 0) {
				canEdit = true
			}
			if s.Mode().Perm()&0o002 != 0 && s.Mode()&os.ModeSticky == 0 {
				canEdit = true // world-writable: anyone can edit
			}
		}
	}
	return b, canEdit, nil
}

// parseAuthorizedKeys parses authorized_keys content. Lines that are not valid keys are skipped.
func parseAuthorizedKeys(b []byte) []SSHKey {
	out := []SSHKey{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 256<<10)
	n := 0
	for sc.Scan() && len(out) < maxKeysPerFile {
		n++
		k, ok := parseKeyLine(sc.Text())
		if ok {
			k.Line = n
			out = append(out, k)
		}
	}
	return out
}

func parseKeyLine(line string) (SSHKey, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return SSHKey{}, false
	}
	var opts KeyOptions
	first, rest := splitField(line)
	if !keyTypes[first] {
		var err error
		if opts, err = parseKeyOptions(first); err != nil {
			return SSHKey{}, false
		}
		first, rest = splitField(rest)
		if !keyTypes[first] {
			return SSHKey{}, false
		}
	}
	b64, comment := splitField(rest)
	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return SSHKey{}, false
	}
	bits, err := keyBits(first, blob)
	if err != nil {
		return SSHKey{}, false
	}
	return SSHKey{
		Type:        first,
		Bits:        bits,
		Fingerprint: fingerprintSHA256(blob),
		Comment:     cleanText(comment, maxCommentLen),
		Options:     opts,
	}, true
}

// splitField returns the first whitespace-separated field, honouring double quotes (for the
// options field), and the rest with leading whitespace removed.
func splitField(s string) (string, string) {
	s = strings.TrimLeft(s, " \t")
	inQuote := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && inQuote && i+1 < len(s):
			i++
		case c == '"':
			inQuote = !inQuote
		case (c == ' ' || c == '\t') && !inQuote:
			return s[:i], strings.TrimLeft(s[i+1:], " \t")
		}
	}
	return s, ""
}

// fingerprintSHA256 matches `ssh-keygen -lf`: base64 of sha256 over the decoded key blob, no padding.
func fingerprintSHA256(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// parseKeyOptions parses the comma-separated options field of an authorized_keys line.
func parseKeyOptions(s string) (KeyOptions, error) {
	var o KeyOptions
	for i := 0; i < len(s); {
		j := i
		for j < len(s) && s[j] != '=' && s[j] != ',' {
			j++
		}
		name := strings.ToLower(s[i:j])
		var val string
		if j < len(s) && s[j] == '=' {
			if j+1 >= len(s) || s[j+1] != '"' {
				return o, errors.New("option value must be quoted")
			}
			var sb strings.Builder
			k := j + 2
			closed := false
			for ; k < len(s); k++ {
				if s[k] == '\\' && k+1 < len(s) && s[k+1] == '"' {
					sb.WriteByte('"')
					k++
					continue
				}
				if s[k] == '"' {
					closed = true
					break
				}
				sb.WriteByte(s[k])
			}
			if !closed {
				return o, errors.New("unterminated option value")
			}
			val = sb.String()
			j = k + 1
		}
		if name == "" {
			return o, errors.New("empty option")
		}
		switch name {
		case "restrict":
			o.Restrict = true
		case "verify-required":
			o.VerifyRequired = true
		case "no-touch-required":
			o.NoTouchRequired = true
		case "from":
			for _, p := range strings.Split(val, ",") {
				if p = cleanText(strings.TrimSpace(p), 64); p != "" && len(o.From) < 20 {
					o.From = append(o.From, p)
				}
			}
		case "expiry-time":
			o.ExpiryTime = cleanText(val, 16)
			if t, ok := parseExpiryTime(val, time.Local); ok {
				o.ExpiresAt = t.Format(time.RFC3339)
			}
		case "command":
			o.Command = cleanText(val, 256)
		default:
			n := cleanText(name, 32)
			if len(o.Other) < 20 && n != "" {
				o.Other = append(o.Other, n)
			}
		}
		if j < len(s) {
			if s[j] != ',' {
				return o, errors.New("expected comma between options")
			}
			j++
		}
		i = j
	}
	return o, nil
}

// parseExpiryTime parses YYYYMMDD[HHMM[SS]] with an optional trailing Z (UTC), like sshd.
func parseExpiryTime(v string, loc *time.Location) (time.Time, bool) {
	if strings.HasSuffix(v, "Z") || strings.HasSuffix(v, "z") {
		v, loc = v[:len(v)-1], time.UTC
	}
	layouts := map[int]string{8: "20060102", 12: "200601021504", 14: "20060102150405"}
	layout, ok := layouts[len(v)]
	if !ok {
		return time.Time{}, false
	}
	t, err := time.ParseInLocation(layout, v, loc)
	return t, err == nil
}

// keyBits reads the key size from the wire-format blob, like ssh-keygen: RSA modulus bits, DSA p
// bits, the ECDSA curve size, 256 for Ed25519. The blob's own type must match the line's type.
func keyBits(typ string, blob []byte) (int, error) {
	r := sshReader{b: blob}
	inner, err := r.str()
	if err != nil || string(inner) != typ {
		return 0, errors.New("key type mismatch")
	}
	if strings.Contains(typ, "-cert-v01@") {
		return 0, nil // certificate: size not decoded
	}
	switch typ {
	case "ssh-rsa":
		if _, err := r.str(); err != nil { // e
			return 0, err
		}
		n, err := r.str()
		if err != nil {
			return 0, err
		}
		return new(big.Int).SetBytes(n).BitLen(), nil
	case "ssh-dss":
		p, err := r.str()
		if err != nil {
			return 0, err
		}
		return new(big.Int).SetBytes(p).BitLen(), nil
	case "ecdsa-sha2-nistp256", "sk-ecdsa-sha2-nistp256@openssh.com":
		return 256, nil
	case "ecdsa-sha2-nistp384":
		return 384, nil
	case "ecdsa-sha2-nistp521":
		return 521, nil
	case "ssh-ed25519", "sk-ssh-ed25519@openssh.com":
		k, err := r.str()
		if err != nil || len(k) != 32 {
			return 0, errors.New("bad ed25519 key")
		}
		return 256, nil
	}
	return 0, nil
}

type sshReader struct{ b []byte }

func (r *sshReader) str() ([]byte, error) {
	if len(r.b) < 4 {
		return nil, errors.New("short blob")
	}
	n := binary.BigEndian.Uint32(r.b)
	if uint64(n) > uint64(len(r.b)-4) {
		return nil, errors.New("short blob")
	}
	s := r.b[4 : 4+n]
	r.b = r.b[4+n:]
	return s, nil
}

// cleanText makes an untrusted string safe to send: invalid UTF-8 and control characters (C0, DEL,
// C1, and bidi overrides) become spaces, and it is capped at max bytes on a rune boundary.
func cleanText(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || isBidiControl(r) {
			r = ' '
		}
		if b.Len()+utf8.RuneLen(r) > max {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

func isBidiControl(r rune) bool {
	return (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == 0x200e || r == 0x200f || r == 0x061c
}

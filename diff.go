package main

// The "Files changed" diff of an AI session (session.go): what changed between the session checkpoint and now, as
// unified diffs of text files only. Secrets never leave the server: files whose name looks like a key, a secret or
// a shadow file are listed without content, so are files holding a private key, binary files and big files, and
// values on lines that assign a password, token or key are replaced with [redacted]. Size-capped.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
)

const (
	maxDiffFileBytes    = 256 << 10 // bigger files are listed, not diffed
	maxDiffPerFile      = 32 << 10
	maxDiffTotal        = 128 << 10
	maxDiffChanges      = 200
	maxLCSCells         = 2_000_000
	diffContext         = 3
	redactedPlaceholder = "[redacted]"
)

// FileChange is one changed path of an AI session, as reported.
type FileChange struct {
	Path     string `json:"path"`               // the file, or "nft list ruleset" and "ufw" for live state
	Change   string `json:"change"`             // added | removed | modified
	Note     string `json:"note,omitempty"`     // mode, owner, symlink or ufw state changes, in words
	Diff     string `json:"diff,omitempty"`     // unified diff (text files only, values that look secret redacted)
	Skipped  string `json:"skipped,omitempty"`  // why there is no diff: secret | binary | too_large | directory | symlink | budget
	Redacted int    `json:"redacted,omitempty"` // lines whose value was replaced with [redacted]
}

// secretNameRE: files listed without their content, whatever is in them.
var secretNameRE = regexp.MustCompile(`(?i)(key|secret|shadow|token|passw|credential|\.pem$|\.p12$|\.pfx$|\.gpg$|\.asc$|\.jks$|\.kdbx$|id_rsa|id_ecdsa|id_ed25519)`)

// privateKeyRE: content that holds a private key is never sent, whatever the file is called.
var privateKeyRE = regexp.MustCompile(`PRIVATE KEY|OPENSSH PRIVATE|PuTTY-User-Key-File`)

func secretName(path string) bool { return secretNameRE.MatchString(filepath.Base(path)) }

var (
	urlCredRE = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/\s:@"']+:[^/\s@"']+@`)
	// assignRE: NAME=value or NAME: value where NAME mentions a password, token, secret or key.
	assignRE = regexp.MustCompile(`(?i)([A-Za-z0-9_.-]*(?:passw(?:or)?d|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?key|credential)[A-Za-z0-9_.-]*)(\s*[=:]\s*)(["']?)([^\s"']+)`)
	harmless = map[string]bool{"yes": true, "no": true, "true": true, "false": true, "on": true, "off": true, "0": true, "1": true}
)

// redactLine replaces values that look secret. sshd's "PasswordAuthentication no" is kept: no = or :, and a
// yes/no value is never a secret.
func redactLine(l string) (string, bool) {
	out := urlCredRE.ReplaceAllString(l, "${1}"+redactedPlaceholder+"@")
	out = assignRE.ReplaceAllStringFunc(out, func(m string) string {
		p := assignRE.FindStringSubmatch(m)
		name := strings.ToUpper(p[1])
		if harmless[strings.ToLower(p[4])] || p[4] == redactedPlaceholder || name == "NOPASSWD" || name == "PASSWD" { // sudoers tags
			return m
		}
		return p[1] + p[2] + p[3] + redactedPlaceholder
	})
	return out, out != l
}

// textLines splits a text file into lines, or says why it is not one.
func textLines(b []byte) ([]string, string) {
	if len(b) > maxDiffFileBytes {
		return nil, "too_large"
	}
	if bytes.IndexByte(b, 0) >= 0 || !utf8.Valid(b) {
		return nil, "binary"
	}
	if privateKeyRE.Match(b) {
		return nil, "secret"
	}
	if len(b) == 0 {
		return []string{}, ""
	}
	s := strings.TrimSuffix(string(b), "\n")
	return strings.Split(s, "\n"), ""
}

type diffOp struct {
	kind byte // ' ', '-', '+'
	a, b int  // position in a and in b when the op happens
}

// lineDiff is an edit script from a to b: common prefix and suffix, then an LCS of the middle (or, when that
// would be too big, everything in the middle replaced).
func lineDiff(a, b []string) []diffOp {
	pre := 0
	for pre < len(a) && pre < len(b) && a[pre] == b[pre] {
		pre++
	}
	suf := 0
	for suf < len(a)-pre && suf < len(b)-pre && a[len(a)-1-suf] == b[len(b)-1-suf] {
		suf++
	}
	ops := make([]diffOp, 0, len(a)+len(b))
	for i := 0; i < pre; i++ {
		ops = append(ops, diffOp{' ', i, i})
	}
	am, bm := a[pre:len(a)-suf], b[pre:len(b)-suf]
	n, m := len(am), len(bm)
	i, j := 0, 0
	if n > 0 && m > 0 && n*m <= maxLCSCells {
		w := m + 1
		dp := make([]int32, (n+1)*w)
		for x := n - 1; x >= 0; x-- {
			for y := m - 1; y >= 0; y-- {
				if am[x] == bm[y] {
					dp[x*w+y] = dp[(x+1)*w+y+1] + 1
				} else if dp[(x+1)*w+y] >= dp[x*w+y+1] {
					dp[x*w+y] = dp[(x+1)*w+y]
				} else {
					dp[x*w+y] = dp[x*w+y+1]
				}
			}
		}
		for i < n && j < m {
			switch {
			case am[i] == bm[j]:
				ops = append(ops, diffOp{' ', pre + i, pre + j})
				i++
				j++
			case dp[(i+1)*w+j] >= dp[i*w+j+1]:
				ops = append(ops, diffOp{'-', pre + i, pre + j})
				i++
			default:
				ops = append(ops, diffOp{'+', pre + i, pre + j})
				j++
			}
		}
	}
	for ; i < n; i++ {
		ops = append(ops, diffOp{'-', pre + i, pre + j})
	}
	for ; j < m; j++ {
		ops = append(ops, diffOp{'+', pre + n, pre + j})
	}
	for k := 0; k < suf; k++ {
		ops = append(ops, diffOp{' ', len(a) - suf + k, len(b) - suf + k})
	}
	return ops
}

// unifiedDiff renders a and b as unified diff hunks (3 lines of context). Empty when they are equal.
func unifiedDiff(a, b []string, fromName, toName string) string {
	ops := lineDiff(a, b)
	var changes []int
	for k, o := range ops {
		if o.kind != ' ' {
			changes = append(changes, k)
		}
	}
	if len(changes) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("--- " + fromName + "\n+++ " + toName + "\n")
	for c := 0; c < len(changes); {
		start := max(changes[c]-diffContext, 0)
		end := changes[c]
		for c < len(changes) && changes[c] <= end+2*diffContext {
			end = changes[c]
			c++
		}
		end = min(end+diffContext, len(ops)-1)
		aStart, bStart, aCount, bCount := ops[start].a, ops[start].b, 0, 0
		var body strings.Builder
		for _, o := range ops[start : end+1] {
			switch o.kind {
			case ' ':
				aCount++
				bCount++
				body.WriteString(" " + a[o.a] + "\n")
			case '-':
				aCount++
				body.WriteString("-" + a[o.a] + "\n")
			case '+':
				bCount++
				body.WriteString("+" + b[o.b] + "\n")
			}
		}
		fmt.Fprintf(&sb, "@@ -%s +%s @@\n", hunkRange(aStart, aCount), hunkRange(bStart, bCount))
		sb.WriteString(body.String())
	}
	return sb.String()
}

func hunkRange(start, count int) string {
	if count == 0 {
		return strconv.Itoa(start) + ",0"
	}
	if count == 1 {
		return strconv.Itoa(start + 1)
	}
	return strconv.Itoa(start+1) + "," + strconv.Itoa(count)
}

// redactAll redacts every line and counts the ones it changed.
func redactAll(lines []string) ([]string, int) {
	out := make([]string, len(lines))
	n := 0
	for i, l := range lines {
		r, changed := redactLine(l)
		out[i] = r
		if changed {
			n++
		}
	}
	return out, n
}

// fileDiff diffs one file between its saved copy (old, nil when it did not exist) and now (cur, nil when removed).
func fileDiff(path string, old, cur []byte, oldExists, curExists bool) (diff, skipped string, redacted int) {
	if secretName(path) {
		return "", "secret", 0
	}
	var a, b []string
	if oldExists {
		l, why := textLines(old)
		if why != "" {
			return "", why, 0
		}
		a = l
	}
	if curExists {
		l, why := textLines(cur)
		if why != "" {
			return "", why, 0
		}
		b = l
	}
	a, ra := redactAll(a)
	b, rb := redactAll(b)
	from, to := "a"+path, "b"+path
	if !oldExists {
		from = "/dev/null"
	}
	if !curExists {
		to = "/dev/null"
	}
	d := unifiedDiff(a, b, from, to)
	if len(d) > maxDiffPerFile {
		d = d[:maxDiffPerFile]
		if i := strings.LastIndexByte(d, '\n'); i > 0 {
			d = d[:i+1]
		}
		d += "... (diff cut at 32 KB)\n"
	}
	return d, "", max(ra, rb)
}

/* ---------- The state of a checkpoint's targets now ---------- */

// liveEntries lists what is under the roots now, like snapshot does, but without copying anything.
func liveEntries(roots []string) (map[string]cpEntry, error) {
	out := map[string]cpEntry{}
	for _, root := range roots {
		if _, err := os.Lstat(rp(root)); err != nil {
			continue // absent now
		}
		err := filepath.WalkDir(rp(root), func(real string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if len(out) >= maxCheckpointEntries {
				return fmt.Errorf("more than %d files under %s", maxCheckpointEntries, root)
			}
			path := strings.TrimPrefix(real, fsRoot)
			st, err := os.Lstat(real)
			if err != nil {
				return nil
			}
			e := cpEntry{Path: path, Mode: uint32(st.Mode().Perm() | st.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky))}
			if sys, ok := st.Sys().(*syscall.Stat_t); ok {
				e.UID, e.GID = int(sys.Uid), int(sys.Gid)
			}
			switch {
			case st.IsDir():
				e.Kind = "dir"
			case st.Mode()&fs.ModeSymlink != 0:
				e.Kind = "symlink"
				e.Link, _ = os.Readlink(real)
			case st.Mode().IsRegular():
				e.Kind, e.Size = "file", st.Size()
				if e.SHA256, err = fileSHA256(real); err != nil {
					return nil
				}
			default:
				return nil
			}
			out[path] = e
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// stateDigest is one hash over the targets as they are now: every entry, the ruleset (without the agent's own
// table) and whether ufw is active. Undo compares it with the state at the end of the session.
func stateDigest(m *Manifest) (string, error) {
	ents, err := liveEntries(rootsOf(m.Targets))
	if err != nil {
		return "", err
	}
	paths := make([]string, 0, len(ents))
	for p := range ents {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, p := range paths {
		e := ents[p]
		fmt.Fprintf(h, "%s\x00%s\x00%o\x00%d\x00%d\x00%s\x00%s\n", e.Path, e.Kind, e.Mode, e.UID, e.GID, e.SHA256, e.Link)
	}
	if has(m.Targets, "nft") {
		cur, err := nftList()
		if err != nil {
			return "", fmt.Errorf("nft list ruleset: %w", err)
		}
		fmt.Fprintf(h, "nft\x00%s\n", stripOwnTable(string(cur)))
	}
	if has(m.Targets, "ufw") {
		fmt.Fprintf(h, "ufw\x00%v\n", ufwIsActive())
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// stripOwnTable removes the agent's own blocklist table (table inet securemyserver { ... }) from an nft listing.
func stripOwnTable(ruleset string) string {
	var out []string
	skip := false
	for _, l := range strings.Split(ruleset, "\n") {
		if !skip && strings.HasPrefix(l, "table inet "+nftTable+" {") {
			skip = !strings.HasSuffix(strings.TrimSpace(l), "}")
			continue
		}
		if skip {
			if l == "}" {
				skip = false
			}
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func modeNote(old, cur cpEntry) string {
	var parts []string
	if old.Mode != cur.Mode {
		parts = append(parts, fmt.Sprintf("mode %04o -> %04o", old.Mode, cur.Mode))
	}
	if old.UID != cur.UID || old.GID != cur.GID {
		parts = append(parts, fmt.Sprintf("owner %d:%d -> %d:%d", old.UID, old.GID, cur.UID, cur.GID))
	}
	return strings.Join(parts, ", ")
}

// checkpointDiff compares a checkpoint with the live system. truncated: more changes or bytes than the caps.
func checkpointDiff(m *Manifest) (changes []FileChange, truncated bool, err error) {
	files := filepath.Join(cpPath(m.ID), "files")
	roots := rootsOf(m.Targets)
	saved := map[string]cpEntry{}
	for _, e := range m.Entries {
		if e.Kind != "absent" {
			saved[e.Path] = e
		}
	}
	cur, err := liveEntries(roots)
	if err != nil {
		return nil, false, err
	}
	paths := map[string]bool{}
	for p := range saved {
		paths[p] = true
	}
	for p := range cur {
		paths[p] = true
	}
	sorted := make([]string, 0, len(paths))
	for p := range paths {
		sorted = append(sorted, p)
	}
	sort.Strings(sorted)
	budget := maxDiffTotal
	add := func(c FileChange) {
		if len(changes) >= maxDiffChanges {
			truncated = true
			return
		}
		if len(c.Diff) > budget {
			c.Diff, c.Skipped, truncated = "", "budget", true
		}
		budget -= len(c.Diff)
		changes = append(changes, c)
	}
	read := func(p string) []byte {
		b, _ := readCapped(p, maxDiffFileBytes+1)
		return b
	}
	for _, p := range sorted {
		o, inOld := saved[p]
		c, inCur := cur[p]
		switch {
		case inOld && !inCur:
			fc := FileChange{Path: p, Change: "removed"}
			switch o.Kind {
			case "file":
				fc.Diff, fc.Skipped, fc.Redacted = fileDiff(p, read(filepath.Join(files, p)), nil, true, false)
			case "dir":
				fc.Skipped = "directory"
			case "symlink":
				fc.Skipped, fc.Note = "symlink", "was a link to "+trim(o.Link, 200)
			}
			add(fc)
		case !inOld && inCur:
			fc := FileChange{Path: p, Change: "added"}
			switch c.Kind {
			case "file":
				fc.Diff, fc.Skipped, fc.Redacted = fileDiff(p, nil, read(rp(p)), false, true)
			case "dir":
				fc.Skipped = "directory"
			case "symlink":
				fc.Skipped, fc.Note = "symlink", "a link to "+trim(c.Link, 200)
			}
			add(fc)
		case o.Kind != c.Kind:
			add(FileChange{Path: p, Change: "modified", Note: "was a " + o.Kind + ", now a " + c.Kind})
		default:
			note := modeNote(o, c)
			switch o.Kind {
			case "file":
				if o.SHA256 != c.SHA256 {
					fc := FileChange{Path: p, Change: "modified", Note: note}
					fc.Diff, fc.Skipped, fc.Redacted = fileDiff(p, read(filepath.Join(files, p)), read(rp(p)), true, true)
					add(fc)
					continue
				}
			case "symlink":
				if o.Link != c.Link {
					add(FileChange{Path: p, Change: "modified", Skipped: "symlink", Note: strings.TrimPrefix(note+", ", ", ") + "link " + trim(o.Link, 200) + " -> " + trim(c.Link, 200)})
					continue
				}
			}
			if note != "" {
				add(FileChange{Path: p, Change: "modified", Note: note})
			}
		}
	}
	if has(m.Targets, "nft") && m.NftSHA256 != "" {
		old, _ := os.ReadFile(filepath.Join(cpPath(m.ID), "nft-ruleset.nft"))
		if now, err := nftList(); err == nil {
			a, b := stripOwnTable(string(old)), stripOwnTable(string(now))
			if a != b {
				al, _ := textLines([]byte(a))
				bl, _ := textLines([]byte(b))
				d := unifiedDiff(al, bl, "a/nft list ruleset", "b/nft list ruleset")
				if len(d) > maxDiffPerFile {
					d = d[:maxDiffPerFile] + "... (diff cut at 32 KB)\n"
				}
				add(FileChange{Path: "nft list ruleset", Change: "modified", Diff: d})
			}
		}
	}
	if has(m.Targets, "ufw") && m.UFWActive != nil {
		if now := ufwIsActive(); now != *m.UFWActive {
			add(FileChange{Path: "ufw", Change: "modified", Note: "ufw " + activeWord(*m.UFWActive) + " -> " + activeWord(now)})
		}
	}
	return changes, truncated, nil
}

func activeWord(b bool) string {
	if b {
		return "active"
	}
	return "inactive"
}

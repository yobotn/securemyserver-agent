package main

// The signed blocklist (D-013, D-041, D-042). After each report, and only when root ran
// `securemyserver allow blocklist`, the agent pulls GET /v1/blocklist (If-None-Match: its version), and:
//
//  1. verifies the platform's Ed25519 signature over "securemyserver-blocklist-v1\n" + payload against a
//     blocklist_key pinned in agent.conf;
//  2. reads the payload strictly: this server's id, a version not older than the one applied, not expired,
//     at most 50,000 block and 20,000 allow entries, canonical prefixes no wider than /16 (IPv4) or /32 (IPv6),
//     and at most 2^24 IPv4 addresses in all;
//  3. never blocks: private, loopback and link-local ranges, anything that overlaps an allow entry (the
//     platform's allowlist and logins, plus every peer of an open SSH connection on this server);
//  4. writes /var/lib/securemyserver/blocklist.nft from parsed prefixes only (no shell, nothing from the
//     network is interpolated), checks it with `nft -c -f`, then loads it with `nft -f` in one transaction.
//
// The list is data, never a command: it can only drop inbound packets from the listed sources in its own table
// `inet securemyserver`. Established connections and loopback are always accepted first. Without nftables,
// nothing is done and the report says so. When the allow file is removed, the table is removed too.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	blocklistPrefix   = "securemyserver-blocklist-v1\n"
	nftTable          = "securemyserver"
	maxBlockEntries   = 50_000
	maxAllowEntries   = 20_000
	maxBlocklistBytes = 16 << 20
	maxCoveredV4      = 1 << 24
	minBlockBits4     = 16
	minBlockBits6     = 32
	blocklistSkew     = 5 * time.Minute

	blApplied    = "applied"
	blOff        = "off"
	blNotApplied = "not_applied"
	blError      = "error"
)

// BlocklistInfo is the blocklist part of the report: what this server applied, or why not.
type BlocklistInfo struct {
	Allowed   bool   `json:"allowed"` // root ran securemyserver allow blocklist
	State     string `json:"state"`   // applied | off | not_applied | error
	Detail    string `json:"detail,omitempty"`
	Version   int64  `json:"version"`  // the list version in nftables now
	Block4    int    `json:"block_v4"` // entries in the set securemyserver_block
	Block6    int    `json:"block_v6"` // entries in the set securemyserver_block6
	Allow     int    `json:"allow"`    // addresses that are never blocked (allowlist, logins, open SSH sessions)
	Skipped   int    `json:"skipped"`  // listed entries left out because they overlap an allow entry or are private
	AppliedAt string `json:"applied_at,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	CheckedAt string `json:"checked_at,omitempty"`
}

// blState is kept in /var/lib/securemyserver/blocklist.json.
type blState struct {
	Info      BlocklistInfo `json:"info"`
	SHA256    string        `json:"sha256"`
	ExpiresAt time.Time     `json:"expires_at"`
}

type blocklistReply struct {
	Payload   string `json:"payload"`   // base64 of the exact signed bytes
	Signature string `json:"signature"` // Ed25519, base64
	Key       string `json:"key"`       // the signing public key, base64 (informational; the pinned keys decide)
}

type blocklistPayload struct {
	V           int      `json:"v"`
	Type        string   `json:"type"`
	ServerID    string   `json:"server_id"`
	Version     int64    `json:"version"`
	GeneratedAt string   `json:"generated_at"`
	ExpiresAt   string   `json:"expires_at"`
	Block       []string `json:"block"`
	Allow       []string `json:"allow"`
}

// Commands the blocklist runs. Variables so tests can stand in for nft.
var (
	nftInstalled = func() bool { _, err := lookPath("nft"); return err == nil }
	nftCheck     = func(file string) error { return runChecked(60*time.Second, "nft", "-c", "-f", file) }
	nftApply     = func(file string) error { return runChecked(60*time.Second, "nft", "-f", file) }
	nftHasTable  = func() bool {
		out, _, err := run(15*time.Second, "nft", "list", "tables")
		return err == nil && bytes.Contains(out, []byte("table inet "+nftTable+"\n"))
	}
	sshPeers = establishedSSHPeers
)

func loadBlState() *blState {
	st := &blState{}
	_ = readJSON(rp(blocklistStateFile), st)
	return st
}

func (st *blState) save() {
	if err := writeJSON(rp(blocklistStateFile), st); err != nil {
		log.Printf("blocklist: save state: %v", err)
	}
}

// blocklistReport is the blocklist part of the next report.
func blocklistReport() *BlocklistInfo {
	var info BlocklistInfo
	_ = withLock(func() error {
		info = loadBlState().Info
		return nil
	})
	info.Allowed = blocklistAllowed()
	if info.State == "" {
		info.State = blOff
		if !info.Allowed {
			info.Detail = "not allowed on this server. Run: sudo securemyserver allow blocklist"
		} else {
			info.Detail = "waiting for the first pull"
		}
	}
	return &info
}

/* ---------- Verify ---------- */

// verifyBlocklist checks the signature and the payload. applied is the version in nftables now (0: none).
func verifyBlocklist(rep blocklistReply, keys []ed25519.PublicKey, serverID string, applied int64, now time.Time) (*blocklistPayload, []byte, error) {
	raw, err := base64.StdEncoding.DecodeString(rep.Payload)
	if err != nil || len(raw) == 0 || len(raw) > maxBlocklistBytes {
		return nil, nil, errors.New("the list is empty, too large or not base64")
	}
	sig, err := base64.StdEncoding.DecodeString(rep.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, nil, errors.New("the list has no valid signature")
	}
	msg := append([]byte(blocklistPrefix), raw...)
	ok := false
	for _, k := range keys {
		if ed25519.Verify(k, msg, sig) {
			ok = true
			break
		}
	}
	if !ok {
		return nil, nil, errors.New("the list is not signed by a blocklist_key pinned in agent.conf")
	}
	var p blocklistPayload
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, nil, fmt.Errorf("the list is not valid: %v", err)
	}
	if dec.More() {
		return nil, nil, errors.New("the list has trailing data")
	}
	if p.V != 1 || p.Type != "blocklist" {
		return nil, nil, errors.New("unsupported list version")
	}
	if p.ServerID != serverID {
		return nil, nil, errors.New("the list is for another server")
	}
	if p.Version <= 0 || p.Version < applied {
		return nil, nil, fmt.Errorf("version %d is older than the applied %d", p.Version, applied)
	}
	gen, err1 := parseStamp(p.GeneratedAt)
	exp, err2 := parseStamp(p.ExpiresAt)
	if err1 != nil || err2 != nil || !exp.After(gen) || exp.Sub(gen) > 7*24*time.Hour {
		return nil, nil, errors.New("the list has bad times")
	}
	if gen.After(now.Add(blocklistSkew)) {
		return nil, nil, errors.New("the list is from the future: check this server's clock")
	}
	if !now.Before(exp) {
		return nil, nil, errors.New("the list expired")
	}
	if len(p.Block) > maxBlockEntries || len(p.Allow) > maxAllowEntries {
		return nil, nil, fmt.Errorf("the list has more than %d block or %d allow entries", maxBlockEntries, maxAllowEntries)
	}
	return &p, raw, nil
}

/* ---------- Plan ---------- */

type blPlan struct {
	block4, block6, allow4, allow6 []netip.Prefix
	skipped                        int
}

func parseCanonical(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || p != p.Masked() || p.Addr().Is4In6() || p.Addr().Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("%q is not a canonical prefix", trim(s, 60))
	}
	return p, nil
}

// neverBlock: addresses that are never on a blocklist, whatever the list says.
func neverBlock(a netip.Addr) bool {
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() ||
		a.IsUnspecified() || a.IsInterfaceLocalMulticast() || (a.Is4() && a.As4()[0] == 0) ||
		(a.Is4() && a.As4()[0] == 100 && a.As4()[1]&0xc0 == 64) // 100.64.0.0/10, CGNAT
}

// planBlocklist turns the payload plus the local allow entries into the four nft sets.
func planBlocklist(p *blocklistPayload, local []netip.Prefix) (*blPlan, error) {
	allow := append([]netip.Prefix{}, local...)
	for _, s := range p.Allow {
		a, err := parseCanonical(s)
		if err != nil {
			return nil, fmt.Errorf("allow entry %v", err)
		}
		allow = append(allow, a)
	}
	allow = dedupePrefixes(allow)
	ov := newOverlap(allow)
	pl := &blPlan{}
	var block []netip.Prefix
	for _, s := range p.Block {
		b, err := parseCanonical(s)
		if err != nil {
			return nil, fmt.Errorf("block entry %v", err)
		}
		if (b.Addr().Is4() && b.Bits() < minBlockBits4) || (b.Addr().Is6() && b.Bits() < minBlockBits6) {
			return nil, fmt.Errorf("block entry %s is wider than /%d (IPv4) or /%d (IPv6)", b, minBlockBits4, minBlockBits6)
		}
		if neverBlock(b.Addr()) || ov.overlaps(b) {
			pl.skipped++
			continue
		}
		block = append(block, b)
	}
	block = dedupePrefixes(block)
	var covered int64
	for _, b := range block {
		if b.Addr().Is4() {
			covered += 1 << (32 - b.Bits())
			pl.block4 = append(pl.block4, b)
		} else {
			pl.block6 = append(pl.block6, b)
		}
	}
	if covered > maxCoveredV4 {
		return nil, fmt.Errorf("the list covers %d IPv4 addresses, more than the %d this agent accepts", covered, maxCoveredV4)
	}
	for _, a := range allow {
		if a.Addr().Is4() {
			pl.allow4 = append(pl.allow4, a)
		} else {
			pl.allow6 = append(pl.allow6, a)
		}
	}
	return pl, nil
}

// dedupePrefixes sorts and drops prefixes inside an earlier one (CIDR blocks either nest or don't touch).
func dedupePrefixes(ps []netip.Prefix) []netip.Prefix {
	sort.Slice(ps, func(i, j int) bool {
		if c := ps[i].Addr().Compare(ps[j].Addr()); c != 0 {
			return c < 0
		}
		return ps[i].Bits() < ps[j].Bits()
	})
	var out []netip.Prefix
	for _, p := range ps {
		if n := len(out); n > 0 && out[n-1].Addr().BitLen() == p.Addr().BitLen() && out[n-1].Bits() <= p.Bits() && out[n-1].Contains(p.Addr()) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// overlap answers "does this prefix overlap any allow entry" quickly: two CIDR blocks overlap exactly when one
// contains the other's first address.
type overlap struct {
	byLen map[int]map[netip.Prefix]bool // allow entries by prefix length, to find one that contains an address
	addrs []netip.Addr                  // allow entries' first addresses, sorted, to find one inside a prefix
}

func newOverlap(allow []netip.Prefix) *overlap {
	o := &overlap{byLen: map[int]map[netip.Prefix]bool{}}
	for _, a := range allow {
		if o.byLen[a.Bits()] == nil {
			o.byLen[a.Bits()] = map[netip.Prefix]bool{}
		}
		o.byLen[a.Bits()][a] = true
		o.addrs = append(o.addrs, a.Addr())
	}
	sort.Slice(o.addrs, func(i, j int) bool { return o.addrs[i].Compare(o.addrs[j]) < 0 })
	return o
}

func (o *overlap) overlaps(b netip.Prefix) bool {
	for bits, set := range o.byLen {
		if bits > b.Bits() || bits > b.Addr().BitLen() {
			continue
		}
		if p, err := b.Addr().Prefix(bits); err == nil && set[p] {
			return true
		}
	}
	i := sort.Search(len(o.addrs), func(i int) bool { return o.addrs[i].Compare(b.Addr()) >= 0 })
	return i < len(o.addrs) && b.Contains(o.addrs[i])
}

/* ---------- nftables ---------- */

// nftScript is the whole table, replaced in one transaction: create it if missing, delete it, define it again.
// Every element is a netip.Prefix printed by Go, so nothing from the network reaches nft as text.
func nftScript(pl *blPlan) []byte {
	var b bytes.Buffer
	b.WriteString("# Written by securemyserver agent from a signed blocklist (D-041). Do not edit: the next pull replaces it.\n")
	b.WriteString("table inet " + nftTable + " {}\n")
	b.WriteString("delete table inet " + nftTable + "\n")
	b.WriteString("table inet " + nftTable + " {\n")
	for _, s := range []struct{ name, typ string }{
		{"securemyserver_allow", "ipv4_addr"}, {"securemyserver_allow6", "ipv6_addr"},
		{"securemyserver_block", "ipv4_addr"}, {"securemyserver_block6", "ipv6_addr"},
	} {
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype %s\n\t\tflags interval\n\t\tauto-merge\n\t}\n", s.name, s.typ)
	}
	b.WriteString("\tchain input {\n")
	b.WriteString("\t\ttype filter hook input priority -10; policy accept;\n")
	b.WriteString("\t\tiifname \"lo\" accept\n")
	b.WriteString("\t\tct state established,related accept\n")
	b.WriteString("\t\tip saddr @securemyserver_allow accept\n")
	b.WriteString("\t\tip6 saddr @securemyserver_allow6 accept\n")
	b.WriteString("\t\tip saddr @securemyserver_block counter drop\n")
	b.WriteString("\t\tip6 saddr @securemyserver_block6 counter drop\n")
	b.WriteString("\t}\n}\n")
	for _, s := range []struct {
		name string
		ps   []netip.Prefix
	}{{"securemyserver_allow", pl.allow4}, {"securemyserver_allow6", pl.allow6}, {"securemyserver_block", pl.block4}, {"securemyserver_block6", pl.block6}} {
		for i := 0; i < len(s.ps); i += 500 {
			end := min(i+500, len(s.ps))
			parts := make([]string, 0, end-i)
			for _, p := range s.ps[i:end] {
				parts = append(parts, p.String())
			}
			fmt.Fprintf(&b, "add element inet %s %s { %s }\n", nftTable, s.name, strings.Join(parts, ", "))
		}
	}
	return b.Bytes()
}

func removeBlocklistTable() error {
	if !nftInstalled() || !nftHasTable() {
		return nil
	}
	f := rp(blocklistNftFile)
	if err := writeFileAtomic(f, []byte("table inet "+nftTable+" {}\ndelete table inet "+nftTable+"\n"), 0o600); err != nil {
		return err
	}
	return nftApply(f)
}

// applyPlan checks the file with nft -c first; only a file that passes is loaded.
func applyPlan(pl *blPlan) error {
	f := rp(blocklistNftFile)
	if err := writeFileAtomic(f, nftScript(pl), 0o600); err != nil {
		return err
	}
	if err := nftCheck(f); err != nil {
		return fmt.Errorf("nft -c refused the generated file: %v", err)
	}
	return nftApply(f)
}

// establishedSSHPeers are the remote addresses of open connections to sshd, so the admin who is logged in now
// is never cut off, whatever the list says.
func establishedSSHPeers() []netip.Prefix {
	ports := map[int]bool{22: true}
	if eff, err := sshdEffective(); err == nil {
		ports = map[int]bool{}
		for _, p := range strings.Split(eff["port"], ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
				ports[n] = true
			}
		}
	}
	var out []netip.Prefix
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		if b, err := readCapped(f, 16<<20); err == nil {
			out = append(out, parseEstablished(b, ports)...)
		}
	}
	return out
}

// parseEstablished returns the peers of ESTABLISHED (01) sockets whose local port is in ports.
func parseEstablished(b []byte, ports map[int]bool) []netip.Prefix {
	var out []netip.Prefix
	for i, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 4 || f[3] != "01" {
			continue
		}
		_, lport, ok := strings.Cut(f[1], ":")
		raddr, _, ok2 := strings.Cut(f[2], ":")
		if !ok || !ok2 {
			continue
		}
		lp, err := strconv.ParseUint(lport, 16, 16)
		if err != nil || !ports[int(lp)] {
			continue
		}
		ip, err := decodeProcAddr(raddr)
		if err != nil {
			continue
		}
		if a, ok := netip.AddrFromSlice(ip); ok {
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

/* ---------- Pull ---------- */

var blocklistClient = &http.Client{Timeout: 60 * time.Second}

// refreshBlocklist runs after each report. It never returns an error: what happened goes into the next report.
func refreshBlocklist(cfg Config, key *reportKey) {
	now := nowFn()
	var st *blState
	_ = withLock(func() error { st = loadBlState(); return nil })
	info := &st.Info
	info.CheckedAt = stamp(now)
	info.Allowed = blocklistAllowed()
	setOff := func(state, why string) {
		*info = BlocklistInfo{Allowed: info.Allowed, State: state, Detail: why, CheckedAt: stamp(now)}
		st.SHA256, st.ExpiresAt = "", time.Time{}
	}
	defer func() { _ = withLock(func() error { st.save(); return nil }) }()

	switch {
	case !info.Allowed:
		if err := removeBlocklistTable(); err != nil {
			setOff(blError, "not allowed any more, but removing the nft table failed: "+err.Error())
			return
		}
		setOff(blOff, "not allowed on this server. Run: sudo securemyserver allow blocklist")
		return
	case len(cfg.BlocklistKeys) == 0:
		setOff(blOff, "agent.conf has no blocklist_key")
		return
	case cfg.ServerID == "":
		setOff(blOff, "agent.conf has no server_id")
		return
	case !nftInstalled():
		setOff(blNotApplied, "not applied: nftables not installed")
		return
	}
	// When the table went away (a reboot, a ruleset flush), the current list is pulled and applied again; the
	// version still may not go backwards.
	present := nftHasTable()
	if info.State == blApplied && present && !st.ExpiresAt.IsZero() && !now.Before(st.ExpiresAt) {
		// No newer list for 24 hours (the platform is down or unreachable): stop blocking rather than keep a stale list.
		empty := &blPlan{}
		if err := applyPlan(empty); err != nil {
			info.State, info.Detail = blError, "the list expired, and emptying it failed: "+err.Error()
			return
		}
		info.Block4, info.Block6, info.Skipped = 0, 0, 0
		info.Detail = "the list expired without a newer one; the block sets are empty until the next pull"
	}
	u, err := cfg.blocklistURL()
	if err != nil {
		info.State, info.Detail = blError, err.Error()
		return
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		info.State, info.Detail = blError, err.Error()
		return
	}
	viaKey := ""
	if key != nil {
		viaKey = enrolledServer(cfg)
	}
	setAuth(req, cfg, viaKey)
	req.Header.Set("User-Agent", "securemyserver/"+agentVersion)
	if info.State == blApplied && present && info.Version > 0 {
		req.Header.Set("If-None-Match", `"`+strconv.FormatInt(info.Version, 10)+`"`)
	}
	if key != nil {
		key.signRequest(req, nil, now)
	}
	resp, err := blocklistClient.Do(req)
	if err != nil {
		keepError(info, "pull failed: "+err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified && info.State == blApplied {
		return
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*maxBlocklistBytes))
	if resp.StatusCode != http.StatusOK {
		keepError(info, fmt.Sprintf("pull failed: HTTP %d: %s", resp.StatusCode, trim(strings.TrimSpace(string(body)), 200)))
		return
	}
	var rep blocklistReply
	if err := json.Unmarshal(body, &rep); err != nil {
		keepError(info, "pull failed: the reply is not JSON")
		return
	}
	applied := info.Version // kept through errors, so an older list is never accepted
	p, raw, err := verifyBlocklist(rep, cfg.BlocklistKeys, cfg.ServerID, applied, now)
	if err != nil {
		keepError(info, "refused: "+err.Error())
		return
	}
	sum := sha256.Sum256(raw)
	pl, err := planBlocklist(p, sshPeers())
	if err != nil {
		keepError(info, "refused: "+err.Error())
		return
	}
	err = withLock(func() error { return applyPlan(pl) })
	if err != nil {
		keepError(info, "not applied: "+err.Error())
		return
	}
	exp, _ := parseStamp(p.ExpiresAt)
	*info = BlocklistInfo{
		Allowed: true, State: blApplied, Version: p.Version,
		Block4: len(pl.block4), Block6: len(pl.block6), Allow: len(pl.allow4) + len(pl.allow6), Skipped: pl.skipped,
		AppliedAt: stamp(now), ExpiresAt: stamp(exp), CheckedAt: stamp(now),
	}
	st.SHA256, st.ExpiresAt = hex.EncodeToString(sum[:]), exp
	log.Printf("blocklist: version %d applied: %d IPv4 and %d IPv6 entries blocked, %d never blocked, %d skipped", p.Version, info.Block4, info.Block6, info.Allow, info.Skipped)
}

// keepError reports an error, but leaves the applied list in nftables as it is.
func keepError(info *BlocklistInfo, why string) {
	log.Printf("blocklist: %s", why)
	if info.State == blApplied && info.Version > 0 {
		why += fmt.Sprintf(" (version %d stays applied)", info.Version)
	}
	info.State, info.Detail = blError, trim(why, 280)
}

// blocklistStatus is one line for `securemyserver status`.
func blocklistStatus() string {
	i := blocklistReport()
	if i.State == blApplied {
		return fmt.Sprintf("Blocklist: version %d, %d IPv4 and %d IPv6 entries, applied %s", i.Version, i.Block4, i.Block6, i.AppliedAt)
	}
	return "Blocklist: " + i.State + ": " + i.Detail
}

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

const blTestServer = "0b6c0000-0000-4000-8000-000000000001"

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func signedList(t *testing.T, priv ed25519.PrivateKey, p blocklistPayload) blocklistReply {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, append([]byte(blocklistPrefix), raw...))
	return blocklistReply{Payload: base64.StdEncoding.EncodeToString(raw), Signature: base64.StdEncoding.EncodeToString(sig)}
}

func payload(now time.Time, version int64, block, allow []string) blocklistPayload {
	return blocklistPayload{V: 1, Type: "blocklist", ServerID: blTestServer, Version: version,
		GeneratedAt: stamp(now.Add(-time.Minute)), ExpiresAt: stamp(now.Add(24 * time.Hour)), Block: block, Allow: allow}
}

func TestVerifyBlocklist(t *testing.T) {
	pub, priv := testKey(t)
	otherPub, otherPriv := testKey(t)
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	keys := []ed25519.PublicKey{pub}
	good := signedList(t, priv, payload(now, 10, []string{"192.0.2.0/24"}, nil))
	if p, _, err := verifyBlocklist(good, keys, blTestServer, 9, now); err != nil || p.Version != 10 {
		t.Fatalf("good list: %v", err)
	}
	if _, _, err := verifyBlocklist(good, keys, blTestServer, 10, now); err != nil {
		t.Fatalf("the same version again (the table went away): %v", err)
	}
	cases := map[string]struct {
		rep     blocklistReply
		keys    []ed25519.PublicKey
		applied int64
		want    string
	}{
		"not pinned": {signedList(t, otherPriv, payload(now, 10, nil, nil)), keys, 0, "not signed by a blocklist_key"},
		"older":      {good, keys, 11, "older than the applied"},
		"other server": {signedList(t, priv, func() blocklistPayload {
			p := payload(now, 10, nil, nil)
			p.ServerID = "0b6c0000-0000-4000-8000-000000000002"
			return p
		}()), keys, 0, "another server"},
		"expired": {signedList(t, priv, func() blocklistPayload { p := payload(now, 10, nil, nil); p.ExpiresAt = stamp(now); return p }()), keys, 0, "expired"},
		"future": {signedList(t, priv, func() blocklistPayload {
			p := payload(now, 10, nil, nil)
			p.GeneratedAt = stamp(now.Add(time.Hour))
			return p
		}()), keys, 0, "future"},
		"no keys": {good, nil, 0, "not signed"},
		"bad sig": {blocklistReply{Payload: good.Payload, Signature: "AAAA"}, keys, 0, "no valid signature"},
	}
	for name, c := range cases {
		if _, _, err := verifyBlocklist(c.rep, c.keys, blTestServer, c.applied, now); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
	// Tampering with one byte of the payload breaks the signature.
	raw, _ := base64.StdEncoding.DecodeString(good.Payload)
	tampered := strings.Replace(string(raw), "192.0.2.0/24", "192.0.3.0/24", 1)
	if _, _, err := verifyBlocklist(blocklistReply{Payload: base64.StdEncoding.EncodeToString([]byte(tampered)), Signature: good.Signature}, keys, blTestServer, 0, now); err == nil {
		t.Error("a tampered list was accepted")
	}
	// Unknown fields are refused, even when signed.
	extra := `{"v":1,"type":"blocklist","server_id":"` + blTestServer + `","version":3,"generated_at":"` + stamp(now) + `","expires_at":"` + stamp(now.Add(time.Hour)) + `","block":[],"allow":[],"run":"rm -rf /"}`
	sig := ed25519.Sign(priv, append([]byte(blocklistPrefix), extra...))
	if _, _, err := verifyBlocklist(blocklistReply{Payload: base64.StdEncoding.EncodeToString([]byte(extra)), Signature: base64.StdEncoding.EncodeToString(sig)}, keys, blTestServer, 0, now); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("unknown field: %v", err)
	}
	_ = otherPub
}

func TestPlanBlocklist(t *testing.T) {
	now := time.Now()
	p := payload(now, 1, []string{
		"192.0.2.0/24",      // a /24 rollup
		"192.0.2.7/32",      // inside it: merged away
		"198.51.100.200/32", // blocked
		"198.51.100.10/32",  // allowlisted by the platform
		"203.0.113.0/24",    // contains the open SSH session's peer: never blocked
		"10.0.0.1/32",       // private: never blocked
		"2001:db8::/48",     // IPv6
		"2001:db8:1::5/128", // IPv6
	}, []string{"198.51.100.10/32", "104.16.0.0/13"})
	pl, err := planBlocklist(&p, []netip.Prefix{netip.MustParsePrefix("203.0.113.9/32")})
	if err != nil {
		t.Fatal(err)
	}
	got := func(ps []netip.Prefix) string {
		s := make([]string, len(ps))
		for i, x := range ps {
			s[i] = x.String()
		}
		return strings.Join(s, " ")
	}
	if g := got(pl.block4); g != "192.0.2.0/24 198.51.100.200/32" {
		t.Errorf("block4 = %s", g)
	}
	if g := got(pl.block6); g != "2001:db8::/48 2001:db8:1::5/128" {
		t.Errorf("block6 = %s", g)
	}
	if g := got(pl.allow4); g != "104.16.0.0/13 198.51.100.10/32 203.0.113.9/32" {
		t.Errorf("allow4 = %s", g)
	}
	if pl.skipped != 3 {
		t.Errorf("skipped = %d, want 3 (allowlisted, open session, private)", pl.skipped)
	}

	for name, block := range map[string][]string{
		"too wide":      {"192.0.0.0/8"},
		"not canonical": {"192.0.2.5/24"},
		"injection":     {"192.0.2.1/32; flush ruleset"},
		"mapped":        {"::ffff:192.0.2.1/128"},
	} {
		q := payload(now, 1, block, nil)
		if _, err := planBlocklist(&q, nil); err == nil {
			t.Errorf("%s: accepted %v", name, block)
		}
	}
	// More than 2^24 IPv4 addresses in all is refused, even in allowed /16s.
	var wide []string
	for i := 0; i < 257; i++ {
		wide = append(wide, "11."+strconv.Itoa(i%256)+".0.0/16")
		if i == 256 {
			wide[i] = "12.0.0.0/16"
		}
	}
	q := payload(now, 1, wide, nil)
	if _, err := planBlocklist(&q, nil); err == nil || !strings.Contains(err.Error(), "IPv4 addresses") {
		t.Errorf("coverage cap: %v", err)
	}
}

func TestNftScript(t *testing.T) {
	pl := &blPlan{
		block4: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.200/32")},
		block6: []netip.Prefix{netip.MustParsePrefix("2001:db8::/48")},
		allow4: []netip.Prefix{netip.MustParsePrefix("203.0.113.9/32")},
	}
	s := string(nftScript(pl))
	for _, want := range []string{
		"table inet securemyserver {}\ndelete table inet securemyserver\ntable inet securemyserver {\n",
		"set securemyserver_block {\n\t\ttype ipv4_addr\n\t\tflags interval\n",
		"set securemyserver_block6 {\n\t\ttype ipv6_addr\n\t\tflags interval\n",
		"type filter hook input priority -10; policy accept;",
		"ct state established,related accept\n\t\tip saddr @securemyserver_allow accept",
		"ip saddr @securemyserver_block counter drop",
		"add element inet securemyserver securemyserver_block { 192.0.2.0/24, 198.51.100.200/32 }\n",
		"add element inet securemyserver securemyserver_block6 { 2001:db8::/48 }\n",
		"add element inet securemyserver securemyserver_allow { 203.0.113.9/32 }\n",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("nft script lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "securemyserver_allow6 {  }") || strings.Contains(s, "{ }") {
		t.Error("empty element lists are not valid nft")
	}
	// The established-accept and allow rules come before any drop.
	if strings.Index(s, "established") > strings.Index(s, "drop") || strings.Index(s, "@securemyserver_allow ") > strings.Index(s, "drop") {
		t.Error("rule order")
	}
}

func TestParseEstablished(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 0200A8C0:0016 0900710C:D431 01 00000000:00000000 02:000A7B2E 00000000     0        0 2 4 0000000000000000 20 4 30 10 -1
   2: 0200A8C0:01BB 0A00710C:D432 01 00000000:00000000 02:000A7B2E 00000000     0        0 3 4 0000000000000000 20 4 30 10 -1
`
	got := parseEstablished([]byte(tcp), map[int]bool{22: true})
	if len(got) != 1 || got[0].String() != "12.113.0.9/32" {
		t.Fatalf("got %v, want the SSH peer only", got)
	}
}

// blocklistSandbox: a temp root, nft replaced by recorders, and a platform that serves a signed list.
type blocklistSandbox struct {
	*sandbox
	cfg      Config
	priv     ed25519.PrivateKey
	list     blocklistPayload
	srv      *httptest.Server
	table    bool
	applied  []string
	requests []*http.Request
	nft      bool
}

func newBlocklistSandbox(t *testing.T) *blocklistSandbox {
	s := &blocklistSandbox{sandbox: newSandbox(t), nft: true}
	pub, priv := testKey(t)
	s.priv = priv
	s.list = payload(s.now, 100, []string{"192.0.2.0/24", "198.51.100.200/32", "2001:db8::/48"}, []string{"198.51.100.10/32"})
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests = append(s.requests, r)
		if r.Header.Get("If-None-Match") == `"`+strconv.FormatInt(s.list.Version, 10)+`"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_ = json.NewEncoder(w).Encode(signedList(t, s.priv, s.list))
	}))
	t.Cleanup(s.srv.Close)
	s.cfg = Config{Endpoint: s.srv.URL + "/v1/report", Token: "sms_test", ServerID: blTestServer, BlocklistKeys: []ed25519.PublicKey{pub}}
	oldInst, oldCheck, oldApply, oldHas, oldPeers := nftInstalled, nftCheck, nftApply, nftHasTable, sshPeers
	t.Cleanup(func() {
		nftInstalled, nftCheck, nftApply, nftHasTable, sshPeers = oldInst, oldCheck, oldApply, oldHas, oldPeers
	})
	nftInstalled = func() bool { return s.nft }
	nftCheck = func(string) error { return nil }
	nftApply = func(file string) error {
		b, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		s.applied = append(s.applied, string(b))
		s.table = !strings.HasSuffix(string(b), "delete table inet securemyserver\n")
		return nil
	}
	nftHasTable = func() bool { return s.table }
	sshPeers = func() []netip.Prefix { return nil }
	return s
}

func TestRefreshBlocklist(t *testing.T) {
	s := newBlocklistSandbox(t)
	key, err := loadReportKey(true)
	if err != nil {
		t.Fatal(err)
	}

	// Not allowed: nothing is pulled.
	refreshBlocklist(s.cfg, key)
	if i := blocklistReport(); i.State != blOff || !strings.Contains(i.Detail, "allow blocklist") || len(s.requests) != 0 {
		t.Fatalf("not allowed: %+v, %d requests", i, len(s.requests))
	}

	if err := allowSwitch(blocklistAllow); err != nil {
		t.Fatal(err)
	}
	if got, _ := allowedSwitches(); has(got, blocklistAllow) {
		t.Error("blocklist must not show as a switch")
	}
	s.nft = false
	refreshBlocklist(s.cfg, key)
	if i := blocklistReport(); i.State != blNotApplied || i.Detail != "not applied: nftables not installed" || len(s.requests) != 0 {
		t.Fatalf("no nft: %+v", i)
	}

	s.nft = true
	refreshBlocklist(s.cfg, key)
	i := blocklistReport()
	if i.State != blApplied || i.Version != 100 || i.Block4 != 2 || i.Block6 != 1 || i.Allow != 1 || !i.Allowed {
		t.Fatalf("applied: %+v", i)
	}
	if len(s.applied) != 1 || !strings.Contains(s.applied[0], "{ 192.0.2.0/24, 198.51.100.200/32 }") {
		t.Fatalf("nft file: %v", s.applied)
	}
	r := s.requests[0]
	if r.URL.Path != "/v1/blocklist" || r.Header.Get("Authorization") != "Bearer sms_test" || r.Header.Get("X-SMS-Signature") == "" {
		t.Errorf("request: %s %v", r.URL.Path, r.Header)
	}

	// Unchanged: a 304, nothing applied again.
	refreshBlocklist(s.cfg, key)
	if len(s.applied) != 1 || s.requests[1].Header.Get("If-None-Match") != `"100"` {
		t.Errorf("304 path: %d applies, If-None-Match %q", len(s.applied), s.requests[1].Header.Get("If-None-Match"))
	}

	// An older version is refused; the applied one stays.
	s.list.Version = 99
	refreshBlocklist(s.cfg, key)
	if i := blocklistReport(); i.State != blError || i.Version != 100 || !strings.Contains(i.Detail, "older") || len(s.applied) != 1 {
		t.Errorf("older version: %+v", i)
	}

	// A newer one is applied.
	s.list.Version, s.list.Block = 101, []string{"203.0.113.0/24"}
	refreshBlocklist(s.cfg, key)
	if i := blocklistReport(); i.State != blApplied || i.Version != 101 || i.Block4 != 1 || i.Block6 != 0 {
		t.Errorf("newer: %+v", i)
	}

	// The list expires without a newer one: the block sets are emptied.
	s.now = s.now.Add(25 * time.Hour)
	s.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	refreshBlocklist(s.cfg, key)
	if last := s.applied[len(s.applied)-1]; strings.Contains(last, "add element") {
		t.Errorf("expired list not emptied: %s", last)
	}

	// Disallowed: the table is removed.
	if err := disallowSwitch(blocklistAllow); err != nil {
		t.Fatal(err)
	}
	refreshBlocklist(s.cfg, key)
	if s.table || blocklistReport().State != blOff {
		t.Errorf("disallow: table %v, %+v", s.table, blocklistReport())
	}
}

func TestBlocklistConfig(t *testing.T) {
	pub, _ := testKey(t)
	k := base64.StdEncoding.EncodeToString(pub)
	cfg, err := parseConfig([]byte("endpoint = https://ingest.securemyserver.com/v1/report\ntoken = sms_x\nblocklist_key = " + k + "\n"))
	if err != nil || len(cfg.BlocklistKeys) != 1 {
		t.Fatalf("parse: %v", err)
	}
	if u, _ := cfg.blocklistURL(); u != "https://ingest.securemyserver.com/v1/blocklist" {
		t.Errorf("url = %s", u)
	}
	if _, err := parseConfig([]byte("endpoint = https://x/v1/report\ntoken = sms_x\nblocklist_key = AAAA\n")); err == nil {
		t.Error("a short key was accepted")
	}
}

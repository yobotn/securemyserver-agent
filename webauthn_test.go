package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const (
	testServer = "00000000-0000-4000-8000-000000000001"
	testOrigin = "https://securemyserver.com"
	testRPID   = "securemyserver.com"
)

// The same vector is checked in src/lib/switches/switches.test.ts, so both sides build the same bytes.
const (
	vectorCanonical = `{"expires_at":"2026-11-08T10:10:00Z","issued_at":"2026-11-08T10:00:00Z","nonce":"AAAAAAAAAAAAAAAAAAAAAA","server_id":"00000000-0000-4000-8000-000000000001","switch":"ssh.password_auth_off","type":"switch","v":1}`
	vectorChallenge = "iidsY1WA8YJAkdlYvt7z-QsjSQXRgSeD-130Cu48g1s"
)

func TestCanonicalVector(t *testing.T) {
	p := Policy{V: 1, Type: "switch", ServerID: testServer, Switch: "ssh.password_auth_off", Nonce: "AAAAAAAAAAAAAAAAAAAAAA",
		IssuedAt: "2026-11-08T10:00:00Z", ExpiresAt: "2026-11-08T10:10:00Z"}
	c, err := canonicalPolicy(p)
	if err != nil || string(c) != vectorCanonical {
		t.Fatalf("canonical: %v\n%s", err, c)
	}
	sum := sha256.Sum256(c)
	if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != vectorChallenge {
		t.Fatalf("challenge %s", got)
	}
	if _, err := parsePolicy(vectorCanonical); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		strings.Replace(vectorCanonical, `"v":1`, `"v":1,"x":1`, 1),                                      // unknown field
		strings.Replace(vectorCanonical, `{"expires_at"`, `{ "expires_at"`, 1),                           // whitespace
		strings.Replace(vectorCanonical, `"type":"switch"`, `"type":"switch","type":"switch"`, 1),        // duplicate
		strings.Replace(vectorCanonical, `"type":"switch"`, `"TYPE":"switch"`, 1),                        // case
		strings.Replace(vectorCanonical, `ssh.password_auth_off`, `ssh.password_auth_on`, 1),             // no "on" switch
		strings.Replace(vectorCanonical, `10:10:00Z`, `10:30:00Z`, 1),                                    // lives too long
		strings.Replace(vectorCanonical, `"switch":"ssh.password_auth_off"`, `"switch":"x;rm -rf /"`, 1), // not canonical-safe
	} {
		if _, err := parsePolicy(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

type testSigner struct {
	id      string
	priv    crypto.Signer
	key     OwnerKey
	counter uint32
}

func newSigner(t *testing.T, alg string) *testSigner {
	t.Helper()
	var priv crypto.Signer
	var err error
	switch alg {
	case "ES256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "EdDSA":
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case "RS256":
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	idb := make([]byte, 16)
	_, _ = rand.Read(idb)
	id := base64.RawURLEncoding.EncodeToString(idb)
	k, err := parseOwnerKey(id, base64.StdEncoding.EncodeToString(der))
	if err != nil || k.Alg != alg {
		t.Fatalf("parseOwnerKey: %v %s", err, k.Alg)
	}
	return &testSigner{id: id, priv: priv, key: k, counter: 1}
}

type sigOpts struct {
	typ, origin, rpID, challenge string
	flags                        byte
	crossOrigin                  bool
	badSig                       bool
}

func (s *testSigner) sign(t *testing.T, policy string, mod func(*sigOpts)) Envelope {
	t.Helper()
	sum := sha256.Sum256([]byte(policy))
	o := sigOpts{typ: "webauthn.get", origin: testOrigin, rpID: testRPID, challenge: base64.RawURLEncoding.EncodeToString(sum[:]), flags: flagUP | flagUV}
	if mod != nil {
		mod(&o)
	}
	cd, _ := json.Marshal(map[string]any{"type": o.typ, "challenge": o.challenge, "origin": o.origin, "crossOrigin": o.crossOrigin})
	rp := sha256.Sum256([]byte(o.rpID))
	ad := append(append([]byte{}, rp[:]...), o.flags)
	ad = binary.BigEndian.AppendUint32(ad, s.counter)
	s.counter++
	cdh := sha256.Sum256(cd)
	msg := append(append([]byte{}, ad...), cdh[:]...)
	var sig []byte
	var err error
	switch p := s.priv.(type) {
	case *ecdsa.PrivateKey:
		h := sha256.Sum256(msg)
		sig, err = ecdsa.SignASN1(rand.Reader, p, h[:])
	case ed25519.PrivateKey:
		sig = ed25519.Sign(p, msg)
	case *rsa.PrivateKey:
		h := sha256.Sum256(msg)
		sig, err = rsa.SignPKCS1v15(rand.Reader, p, crypto.SHA256, h[:])
	}
	if err != nil {
		t.Fatal(err)
	}
	if o.badSig {
		sig[len(sig)/2] ^= 0xff
	}
	enc := base64.RawURLEncoding.EncodeToString
	return Envelope{Policy: policy, CredentialID: s.id, AuthenticatorData: enc(ad), ClientDataJSON: enc(cd), Signature: enc(sig)}
}

var nonceN = 0

func testPolicy(t *testing.T, typ, sw string, now time.Time, mod func(*Policy)) string {
	t.Helper()
	nonceN++
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[8:], uint64(nonceN)+uint64(time.Now().UnixNano()))
	p := Policy{V: 1, Type: typ, ServerID: testServer, Switch: sw, Nonce: base64.RawURLEncoding.EncodeToString(b),
		IssuedAt: now.UTC().Truncate(time.Second).Format(time.RFC3339), ExpiresAt: now.UTC().Truncate(time.Second).Add(5 * time.Minute).Format(time.RFC3339)}
	if mod != nil {
		mod(&p)
	}
	c, err := canonicalPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(c)
}

func TestVerifyEnvelope(t *testing.T) {
	now := time.Now()
	es, ed, rs := newSigner(t, "ES256"), newSigner(t, "EdDSA"), newSigner(t, "RS256")
	stranger := newSigner(t, "ES256")
	vp := verifyParams{Keys: []OwnerKey{es.key, ed.key, rs.key}, Origin: testOrigin, RPID: testRPID, ServerID: testServer, Now: now}
	pol := testPolicy(t, "switch", "ssh.password_auth_off", now, nil)

	for _, s := range []*testSigner{es, ed, rs} {
		v, err := verifyEnvelope(s.sign(t, pol, nil), vp)
		if err != nil {
			t.Fatalf("%s: %v", s.key.Alg, err)
		}
		if v.Policy.Switch != "ssh.password_auth_off" || v.Key.ID != s.id || v.Counter == 0 {
			t.Fatalf("%s: %+v", s.key.Alg, v)
		}
	}

	refused := func(name string, env Envelope, vp verifyParams, want string) {
		t.Helper()
		_, err := verifyEnvelope(env, vp)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", name, err, want)
		}
	}
	refused("wrong key", stranger.sign(t, pol, nil), vp, "does not trust")
	refused("tampered challenge", es.sign(t, pol, func(o *sigOpts) { o.challenge = vectorChallenge }), vp, "challenge does not match")
	tampered := es.sign(t, pol, nil)
	tampered.Policy = strings.Replace(pol, "ssh.password_auth_off", "ssh.root_login_off", 1)
	refused("policy changed after signing", tampered, vp, "challenge does not match")
	refused("origin", es.sign(t, pol, func(o *sigOpts) { o.origin = "https://evil.example" }), vp, "origin")
	refused("rp id", es.sign(t, pol, func(o *sigOpts) { o.rpID = "evil.example" }), vp, "rpIdHash")
	refused("type create", es.sign(t, pol, func(o *sigOpts) { o.typ = "webauthn.create" }), vp, "webauthn.get")
	refused("no UP", es.sign(t, pol, func(o *sigOpts) { o.flags = flagUV }), vp, "presence")
	refused("no UV", es.sign(t, pol, func(o *sigOpts) { o.flags = flagUP }), vp, "verify the user")
	refused("cross origin", es.sign(t, pol, func(o *sigOpts) { o.crossOrigin = true }), vp, "cross-origin")
	for _, s := range []*testSigner{es, ed, rs} {
		refused("bad signature "+s.key.Alg, s.sign(t, pol, func(o *sigOpts) { o.badSig = true }), vp, "signature is not valid")
	}
	swapped := es.sign(t, pol, nil)
	swapped.CredentialID = ed.id // Ed25519 key, ES256 signature
	refused("signature from another pinned key", swapped, vp, "signature is not valid")

	other := vp
	other.ServerID = "00000000-0000-4000-8000-000000000002"
	refused("other server", es.sign(t, pol, nil), other, "another server")
	late := vp
	late.Now = now.Add(6 * time.Minute)
	refused("expired", es.sign(t, pol, nil), late, "expired")
	early := vp
	early.Now = now.Add(-5 * time.Minute)
	refused("from the future", es.sign(t, pol, nil), early, "future")
	refused("garbage policy", es.sign(t, "{}", nil), vp, "")
}

func TestParseOwnerKey(t *testing.T) {
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	der, _ := x509.MarshalPKIXPublicKey(&small.PublicKey)
	if _, err := parseOwnerKey("AAAAAAAAAAAAAAAAAAAAAA", base64.StdEncoding.EncodeToString(der)); err == nil {
		t.Fatal("accepted RSA-1024")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ = x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if _, err := parseOwnerKey("AAAAAAAAAAAAAAAAAAAAAA", base64.StdEncoding.EncodeToString(der)); err == nil {
		t.Fatal("accepted P-384")
	}
	if _, err := parseOwnerKey("not base64url!", "AAAA"); err == nil {
		t.Fatal("accepted a bad id")
	}
}

func TestConfigOwnerKeys(t *testing.T) {
	s := newSigner(t, "ES256")
	conf := "endpoint = http://localhost:3000/v1/report\ntoken = sms_x\nallow_http = true\nserver_id = " + testServer +
		"\norigin = http://localhost:3000\nowner_key = " + s.id + " " + s.key.SPKI + "\n"
	cfg, err := parseConfig([]byte(conf))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RPID != "localhost" || cfg.Origin != "http://localhost:3000" || len(cfg.OwnerKeys) != 1 || cfg.switchesOff() != "" {
		t.Fatalf("%+v", cfg)
	}
	if _, err := parseConfig([]byte(strings.Replace(conf, "allow_http = true\n", "", 1))); err == nil {
		t.Fatal("http origin without allow_http")
	}
	if _, err := parseConfig([]byte(conf + "rp_id = evil.example\n")); err == nil {
		t.Fatal("rp_id unrelated to origin")
	}
	plain, err := parseConfig([]byte("endpoint = https://ingest.securemyserver.com/v1/report\ntoken = sms_x\n"))
	if err != nil || plain.Origin != defaultOrigin || plain.RPID != "securemyserver.com" || plain.switchesOff() == "" {
		t.Fatalf("defaults: %+v %v", plain, err)
	}
}

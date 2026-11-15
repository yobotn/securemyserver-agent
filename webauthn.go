package main

// WebAuthn assertion verification for signed policies, done on the server with the standard library only.
// The agent never trusts the platform's own check: it verifies every envelope against the owner's passkey public
// keys pinned in agent.conf (or a key-set update signed by one of them).

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Envelope is what the platform stores and hands to the agent: the policy and the passkey's assertion over it.
type Envelope struct {
	Policy            string `json:"policy"`             // canonical JSON, exactly as signed
	CredentialID      string `json:"credential_id"`      // base64url
	AuthenticatorData string `json:"authenticator_data"` // base64url
	ClientDataJSON    string `json:"client_data_json"`   // base64url
	Signature         string `json:"signature"`          // base64url
}

// OwnerKey is one pinned passkey public key.
type OwnerKey struct {
	ID   string // credential id, base64url
	Alg  string // ES256 | EdDSA | RS256
	SPKI string // standard base64 DER
	pub  crypto.PublicKey
}

const (
	flagUP = 0x01
	flagUV = 0x04
)

// parseOwnerKey reads a pinned key: a credential id and its SPKI (base64 DER, the body of a PEM).
func parseOwnerKey(id, spki string) (OwnerKey, error) {
	k := OwnerKey{ID: id, SPKI: spki}
	if !credIDRE.MatchString(id) {
		return k, errors.New("credential id must be base64url")
	}
	der, err := base64.StdEncoding.DecodeString(spki)
	if err != nil {
		return k, errors.New("public key must be base64 SPKI DER")
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return k, fmt.Errorf("public key: %v", err)
	}
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		if p.Curve != elliptic.P256() {
			return k, errors.New("only P-256 ECDSA keys (ES256) are supported")
		}
		k.Alg = "ES256"
	case ed25519.PublicKey:
		k.Alg = "EdDSA"
	case *rsa.PublicKey:
		if p.N.BitLen() < 2048 {
			return k, errors.New("RSA keys must be at least 2048 bits")
		}
		k.Alg = "RS256"
	default:
		return k, errors.New("unsupported public key type")
	}
	k.pub = pub
	return k, nil
}

func b64url(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// Verified is an envelope whose signature, origin, RP and freshness all checked out.
type Verified struct {
	Policy  Policy
	Key     OwnerKey
	Counter uint32
}

type verifyParams struct {
	Keys     []OwnerKey
	Origin   string // https://securemyserver.com (http://localhost:3000 in development)
	RPID     string // securemyserver.com
	ServerID string
	Now      time.Time
}

// RefusedError says why an envelope was refused. Nonce is set once the policy could be read.
type RefusedError struct {
	Nonce  string
	Reason string
}

func (e *RefusedError) Error() string { return e.Reason }

// verifyEnvelope runs checks (a) to (f) without the persistent ones (nonce reuse and counter, see engine.go):
// pinned key, clientDataJSON type/challenge/origin, rpIdHash, UP and UV flags, the signature, then server id and
// expiry.
func verifyEnvelope(env Envelope, vp verifyParams) (*Verified, error) {
	refuse := func(nonce, format string, a ...any) (*Verified, error) {
		return nil, &RefusedError{Nonce: nonce, Reason: fmt.Sprintf(format, a...)}
	}
	if len(env.CredentialID) > 1400 || len(env.AuthenticatorData) > 4096 || len(env.ClientDataJSON) > 8192 || len(env.Signature) > 2048 {
		return refuse("", "envelope fields are too large")
	}
	pol, perr := parsePolicy(env.Policy)
	nonce := ""
	if perr == nil {
		nonce = pol.Nonce
	}
	// (a) The signing credential must be pinned on this server.
	var key *OwnerKey
	for i := range vp.Keys {
		if subtle.ConstantTimeCompare([]byte(vp.Keys[i].ID), []byte(env.CredentialID)) == 1 {
			key = &vp.Keys[i]
			break
		}
	}
	if key == nil {
		return refuse(nonce, "signed by a passkey this server does not trust (not in its pinned keys)")
	}
	if perr != nil {
		return refuse(nonce, "%v", perr)
	}
	authData, err1 := b64url(env.AuthenticatorData)
	clientData, err2 := b64url(env.ClientDataJSON)
	sig, err3 := b64url(env.Signature)
	if err1 != nil || err2 != nil || err3 != nil {
		return refuse(nonce, "envelope is not base64url")
	}
	// (b) clientDataJSON: a WebAuthn get over sha256(policy), from our origin.
	var cd struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin *bool  `json:"crossOrigin"`
	}
	if err := json.Unmarshal(clientData, &cd); err != nil {
		return refuse(nonce, "clientDataJSON is not JSON")
	}
	if cd.Type != "webauthn.get" {
		return refuse(nonce, "clientDataJSON type is %q, not webauthn.get", trim(cd.Type, 40))
	}
	sum := sha256.Sum256([]byte(env.Policy))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(cd.Challenge), []byte(want)) != 1 {
		return refuse(nonce, "challenge does not match the policy (it was changed after signing)")
	}
	if cd.Origin != vp.Origin {
		return refuse(nonce, "signed on origin %q, expected %q", trim(cd.Origin, 80), vp.Origin)
	}
	if cd.CrossOrigin != nil && *cd.CrossOrigin {
		return refuse(nonce, "signed inside a cross-origin frame")
	}
	// (c) rpIdHash, (d) user present and user verified.
	if len(authData) < 37 {
		return refuse(nonce, "authenticatorData is too short")
	}
	rp := sha256.Sum256([]byte(vp.RPID))
	if subtle.ConstantTimeCompare(authData[:32], rp[:]) != 1 {
		return refuse(nonce, "signed for another site (rpIdHash is not sha256(%q))", vp.RPID)
	}
	flags := authData[32]
	if flags&flagUP == 0 {
		return refuse(nonce, "the passkey did not report user presence (UP)")
	}
	if flags&flagUV == 0 {
		return refuse(nonce, "the passkey did not verify the user (UV): a PIN or biometric is required")
	}
	counter := binary.BigEndian.Uint32(authData[33:37])
	// (e) The signature over authenticatorData || sha256(clientDataJSON).
	cdHash := sha256.Sum256(clientData)
	msg := append(append([]byte{}, authData...), cdHash[:]...)
	if !verifySignature(*key, msg, sig) {
		return refuse(nonce, "signature is not valid for the pinned key")
	}
	// (f) For this server, and still fresh.
	if pol.ServerID != vp.ServerID {
		return refuse(nonce, "policy is for another server")
	}
	issued, _ := parseStamp(pol.IssuedAt)
	expires, _ := parseStamp(pol.ExpiresAt)
	if !vp.Now.Before(expires) {
		return refuse(nonce, "policy expired at %s", pol.ExpiresAt)
	}
	if vp.Now.Add(policyMaxSkew).Before(issued) {
		return refuse(nonce, "policy is issued in the future (check the server clock)")
	}
	return &Verified{Policy: pol, Key: *key, Counter: counter}, nil
}

func verifySignature(k OwnerKey, msg, sig []byte) bool {
	switch pub := k.pub.(type) {
	case *ecdsa.PublicKey:
		h := sha256.Sum256(msg)
		return ecdsa.VerifyASN1(pub, h[:], sig)
	case ed25519.PublicKey:
		return ed25519.Verify(pub, msg, sig)
	case *rsa.PublicKey:
		h := sha256.Sum256(msg)
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig) == nil
	}
	return false
}

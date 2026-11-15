package main

// Signed policies (D-014). The dashboard builds a small policy object, the owner signs sha256 of its canonical
// JSON with a passkey (WebAuthn), and the agent verifies the signature itself against keys pinned on this
// server. The platform only carries the envelope; it can't forge, change or replay one.
//
// Canonical JSON: keys sorted, no whitespace, only integers and strings from a small safe alphabet (so there is
// nothing to escape), arrays of objects for keys. src/lib/switches/policy.ts builds the same bytes; both sides
// test against the same fixed vector.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	policyMaxLife  = 10 * time.Minute
	policyMaxSkew  = 2 * time.Minute
	maxPolicyBytes = 16 << 10
	maxPolicyKeys  = 10
)

type Policy struct {
	V         int         `json:"v"`
	Type      string      `json:"type"` // switch | switches | confirm | keys
	ServerID  string      `json:"server_id"`
	Switch    string      `json:"switch,omitempty"`
	Switches  []string    `json:"switches,omitempty"` // switches: several switches under one passkey tap (D-090)
	Confirms  string      `json:"confirms,omitempty"` // confirm: the nonce of the switch policy it confirms
	Keys      []PolicyKey `json:"keys,omitempty"`     // keys: the new pinned set
	Nonce     string      `json:"nonce"`
	IssuedAt  string      `json:"issued_at"`
	ExpiresAt string      `json:"expires_at"`
}

type PolicyKey struct {
	ID   string `json:"id"`   // credential id, base64url
	SPKI string `json:"spki"` // SubjectPublicKeyInfo DER, standard base64 (the body of a PEM)
}

var (
	uuidRE    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	nonceRE   = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`) // 16 random bytes, base64url
	stampRE   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)
	credIDRE  = regexp.MustCompile(`^[A-Za-z0-9_-]{16,1000}$`)
	spkiB64RE = regexp.MustCompile(`^[A-Za-z0-9+/]{40,1000}={0,2}$`)
	// safeRE is every character a canonical string may hold: nothing JSON would escape.
	safeRE = regexp.MustCompile(`^[A-Za-z0-9._:+/=-]*$`)
)

func q(s string) string { return `"` + s + `"` }

// canonicalPolicy encodes p as canonical JSON. It refuses strings outside safeRE.
func canonicalPolicy(p Policy) ([]byte, error) {
	fields := map[string]string{"v": strconv.Itoa(p.V)}
	for k, v := range map[string]string{
		"type": p.Type, "server_id": p.ServerID, "switch": p.Switch, "confirms": p.Confirms,
		"nonce": p.Nonce, "issued_at": p.IssuedAt, "expires_at": p.ExpiresAt,
	} {
		if v == "" && (k == "switch" || k == "confirms") {
			continue
		}
		if !safeRE.MatchString(v) {
			return nil, fmt.Errorf("policy %s has characters outside the canonical set", k)
		}
		fields[k] = q(v)
	}
	if len(p.Keys) > 0 {
		parts := make([]string, len(p.Keys))
		for i, k := range p.Keys {
			if !safeRE.MatchString(k.ID) || !safeRE.MatchString(k.SPKI) {
				return nil, errors.New("policy key has characters outside the canonical set")
			}
			parts[i] = `{"id":` + q(k.ID) + `,"spki":` + q(k.SPKI) + `}`
		}
		fields["keys"] = "[" + strings.Join(parts, ",") + "]"
	}
	if len(p.Switches) > 0 {
		parts := make([]string, len(p.Switches))
		for i, n := range p.Switches {
			if !safeRE.MatchString(n) {
				return nil, errors.New("policy switches has characters outside the canonical set")
			}
			parts[i] = q(n)
		}
		fields["switches"] = "[" + strings.Join(parts, ",") + "]"
	}
	names := make([]string, 0, len(fields))
	for k := range fields {
		names = append(names, k)
	}
	sort.Strings(names)
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(q(k) + ":" + fields[k])
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func parseStamp(s string) (time.Time, error) {
	if !stampRE.MatchString(s) {
		return time.Time{}, fmt.Errorf("%q is not a UTC time like 2026-11-08T10:00:00Z", s)
	}
	return time.Parse(time.RFC3339, s)
}

// parsePolicy reads a policy and requires that it is exactly its own canonical form, so the bytes that were
// signed are the bytes that are read (no duplicate keys, no extra fields, no second encoding).
func parsePolicy(raw string) (Policy, error) {
	var p Policy
	if len(raw) == 0 || len(raw) > maxPolicyBytes {
		return p, errors.New("policy is empty or too large")
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, fmt.Errorf("policy is not valid: %v", err)
	}
	if dec.More() {
		return p, errors.New("policy has trailing data")
	}
	if err := checkPolicy(p); err != nil {
		return p, err
	}
	c, err := canonicalPolicy(p)
	if err != nil {
		return p, err
	}
	if string(c) != raw {
		return p, errors.New("policy is not in canonical form")
	}
	return p, nil
}

// checkPolicy checks the shape. Expiry against the clock, the server id and the nonce are checked by the caller.
func checkPolicy(p Policy) error {
	if p.V != 1 {
		return errors.New("unsupported policy version")
	}
	if !uuidRE.MatchString(p.ServerID) {
		return errors.New("policy server_id is not a server id")
	}
	if !nonceRE.MatchString(p.Nonce) {
		return errors.New("policy nonce must be 16 random bytes, base64url")
	}
	issued, err := parseStamp(p.IssuedAt)
	if err != nil {
		return fmt.Errorf("issued_at: %w", err)
	}
	expires, err := parseStamp(p.ExpiresAt)
	if err != nil {
		return fmt.Errorf("expires_at: %w", err)
	}
	if !expires.After(issued) || expires.Sub(issued) > policyMaxLife {
		return errors.New("policy must expire within 10 minutes of being issued")
	}
	switch p.Type {
	case "switch":
		if !knownSwitch(p.Switch) || p.Confirms != "" || len(p.Keys) > 0 || len(p.Switches) > 0 {
			return fmt.Errorf("unknown switch %q", p.Switch)
		}
	case "switches":
		// One passkey tap for several switches (D-090): 2 or more known switches, sorted and each once, so the
		// canonical form stays unique. The agent runs them in its own fixed order (engine.go batchOrder).
		if p.Switch != "" || p.Confirms != "" || len(p.Keys) > 0 || len(p.Switches) < 2 || len(p.Switches) > len(switchNames) {
			return fmt.Errorf("a switches policy needs 2 to %d switches", len(switchNames))
		}
		for i, n := range p.Switches {
			if !knownSwitch(n) {
				return fmt.Errorf("unknown switch %q", n)
			}
			if i > 0 && p.Switches[i-1] >= n {
				return errors.New("policy switches must be sorted, each once")
			}
		}
	case "confirm":
		// "Undo this session": confirms names the AI session checkpoint to restore (session.go).
		if len(p.Switches) > 0 {
			return errors.New("confirm policy names one switch")
		}
		if p.Switch == sessionUndoSwitch {
			if !checkpointIDRE.MatchString(p.Confirms) || len(p.Keys) > 0 {
				return errors.New("session undo needs the checkpoint id it restores")
			}
			break
		}
		if !knownSwitch(p.Switch) || !nonceRE.MatchString(p.Confirms) || len(p.Keys) > 0 {
			return errors.New("confirm policy needs a switch and the nonce it confirms")
		}
	case "keys":
		if p.Switch != "" || p.Confirms != "" || len(p.Switches) > 0 || len(p.Keys) == 0 || len(p.Keys) > maxPolicyKeys {
			return fmt.Errorf("keys policy needs 1 to %d keys", maxPolicyKeys)
		}
		for _, k := range p.Keys {
			if !credIDRE.MatchString(k.ID) || !spkiB64RE.MatchString(k.SPKI) {
				return errors.New("keys policy has a malformed key")
			}
		}
	default:
		return fmt.Errorf("unknown policy type %q", p.Type)
	}
	return nil
}

package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

const (
	defaultConfigPath = "/etc/securemyserver/agent.conf"
	// legacyConfigPath is the config name from before D-028 (compatibility, read for one release).
	legacyConfigPath = "/etc/securemyserver/smsd.conf"
)

// resolveConfigPath picks the config file: --config if given, else agent.conf, else the old smsd.conf with a
// deprecation note to log.
func resolveConfigPath(flagValue string, exists func(string) bool) (string, string) {
	if flagValue != "" {
		return flagValue, ""
	}
	if !exists(defaultConfigPath) && exists(legacyConfigPath) {
		return legacyConfigPath, fmt.Sprintf("deprecated: reading %s; rename it to %s", legacyConfigPath, defaultConfigPath)
	}
	return defaultConfigPath, ""
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

type Config struct {
	Endpoint string // https://ingest.securemyserver.com/v1/report
	Token    string
	// AllowHTTP permits a plain http:// endpoint and origin. Only for local development.
	AllowHTTP bool
	// Signed switches (D-014). Off unless server_id and at least one owner_key are set.
	ServerID  string     // this server's id on the platform; every signed policy must name it
	Origin    string     // the dashboard origin passkeys sign on (default https://securemyserver.com)
	RPID      string     // the WebAuthn RP id (default: the origin's host name)
	OwnerKeys []OwnerKey // owner_key lines: the account's passkey public keys at enrollment
	// The signed blocklist (D-041). Applied only when root also ran `securemyserver allow blocklist`.
	BlocklistKeys     []ed25519.PublicKey // blocklist_key lines: the platform's blocklist signing keys
	BlocklistEndpoint string              // default: the endpoint with /v1/report replaced by /v1/blocklist
}

const maxBlocklistKeys = 4

// blocklistURL is where the signed blocklist is pulled from.
func (c Config) blocklistURL() (string, error) {
	if c.BlocklistEndpoint != "" {
		return c.BlocklistEndpoint, nil
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil || !strings.HasSuffix(u.Path, "/v1/report") {
		return "", errors.New("endpoint does not end in /v1/report; set blocklist_endpoint in agent.conf")
	}
	u.Path = strings.TrimSuffix(u.Path, "/v1/report") + "/v1/blocklist"
	u.RawQuery = ""
	return u.String(), nil
}

const defaultOrigin = "https://securemyserver.com"

// switchesOff says why signed switches are off with this config, or "" when they can run.
func (c Config) switchesOff() string {
	switch {
	case c.ServerID == "":
		return "agent.conf has no server_id"
	case len(c.OwnerKeys) == 0:
		return "agent.conf has no owner_key"
	}
	return ""
}

// loadConfig reads "key = value" lines. Unknown keys are an error, so typos do not pass silently.
func loadConfig(path string) (Config, []string, error) {
	var warnings []string
	st, err := os.Stat(path)
	if err != nil {
		return Config{}, nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		warnings = append(warnings, fmt.Sprintf("%s is readable by other users; run chmod 600 %s", path, path))
	}
	b, err := readCapped(path, 64<<10)
	if err != nil {
		return Config{}, warnings, err
	}
	cfg, err := parseConfig(b)
	return cfg, warnings, err
}

func parseConfig(b []byte) (Config, error) {
	var cfg Config
	sc := bufio.NewScanner(bytes.NewReader(b))
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return cfg, fmt.Errorf("line %d: expected key = value", n)
		}
		k, v = strings.TrimSpace(strings.ToLower(k)), strings.Trim(strings.TrimSpace(v), `"`)
		switch k {
		case "endpoint":
			cfg.Endpoint = v
		case "token":
			cfg.Token = v
		case "allow_http":
			cfg.AllowHTTP = v == "true" || v == "yes" || v == "1"
		case "server_id":
			if !uuidRE.MatchString(v) {
				return cfg, fmt.Errorf("line %d: server_id must be the server's id from the dashboard", n)
			}
			cfg.ServerID = v
		case "origin":
			cfg.Origin = strings.TrimRight(v, "/")
		case "rp_id":
			cfg.RPID = v
		case "owner_key":
			// owner_key = <credential id, base64url> <public key: SPKI DER, base64>
			f := strings.Fields(v)
			if len(f) != 2 {
				return cfg, fmt.Errorf("line %d: owner_key needs a credential id and a public key", n)
			}
			k, err := parseOwnerKey(f[0], f[1])
			if err != nil {
				return cfg, fmt.Errorf("line %d: owner_key: %v", n, err)
			}
			if len(cfg.OwnerKeys) >= maxPolicyKeys {
				return cfg, fmt.Errorf("line %d: more than %d owner_key lines", n, maxPolicyKeys)
			}
			cfg.OwnerKeys = append(cfg.OwnerKeys, k)
		case "blocklist_key":
			// blocklist_key = <raw Ed25519 public key, 32 bytes, base64>
			raw, err := base64.StdEncoding.DecodeString(v)
			if err != nil || len(raw) != ed25519.PublicKeySize {
				return cfg, fmt.Errorf("line %d: blocklist_key must be a 32-byte Ed25519 public key, base64", n)
			}
			if len(cfg.BlocklistKeys) >= maxBlocklistKeys {
				return cfg, fmt.Errorf("line %d: more than %d blocklist_key lines", n, maxBlocklistKeys)
			}
			cfg.BlocklistKeys = append(cfg.BlocklistKeys, ed25519.PublicKey(raw))
		case "blocklist_endpoint":
			cfg.BlocklistEndpoint = v
		default:
			return cfg, fmt.Errorf("line %d: unknown key %q", n, k)
		}
	}
	if cfg.Endpoint == "" {
		return cfg, errors.New("endpoint is not set")
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Host == "" {
		return cfg, fmt.Errorf("endpoint %q is not a URL", cfg.Endpoint)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && cfg.AllowHTTP) {
		return cfg, fmt.Errorf("endpoint must use https (set allow_http = true only for local development)")
	}
	if cfg.Token == "" {
		return cfg, errors.New("token is not set")
	}
	if cfg.Origin == "" {
		cfg.Origin = defaultOrigin
	}
	o, err := url.Parse(cfg.Origin)
	if err != nil || o.Host == "" || o.Path != "" || (o.Scheme != "https" && !(o.Scheme == "http" && cfg.AllowHTTP)) {
		return cfg, fmt.Errorf("origin %q must be an https origin like %s", cfg.Origin, defaultOrigin)
	}
	if cfg.RPID == "" {
		cfg.RPID = o.Hostname()
	}
	if cfg.RPID != o.Hostname() && !strings.HasSuffix(o.Hostname(), "."+cfg.RPID) {
		return cfg, fmt.Errorf("rp_id %q must be the origin's host or a parent domain of it", cfg.RPID)
	}
	if strings.ContainsAny(cfg.Token, " \t\r\n") {
		return cfg, errors.New("token contains whitespace")
	}
	if cfg.BlocklistEndpoint != "" {
		b, err := url.Parse(cfg.BlocklistEndpoint)
		if err != nil || b.Host == "" || (b.Scheme != "https" && !(b.Scheme == "http" && cfg.AllowHTTP)) {
			return cfg, fmt.Errorf("blocklist_endpoint %q must be an https URL", cfg.BlocklistEndpoint)
		}
	}
	return cfg, nil
}

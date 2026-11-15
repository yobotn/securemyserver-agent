package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// machineIDPrefix salts the machine-id hash for this platform only (D-066), so the value we receive cannot be matched
// against a plain sha256 of the same machine-id seen anywhere else. Changing it changes every server's hash.
const machineIDPrefix = "securemyserver-machine-v1:"

// collectMachineIDHash returns sha256(prefix + machine-id) in hex, or "" when there is no usable machine-id. The raw
// id never leaves the server. It is used only for the one-free-slot-per-server rule (D-066).
func collectMachineIDHash() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := readCapped(p, 256); err == nil {
			if h := machineIDHash(string(b)); h != "" {
				return h
			}
		}
	}
	return ""
}

// machineIDHash hashes one machine-id file's contents: 32 lower-case hex characters (systemd's format). An empty,
// "uninitialized" or malformed id gives "".
func machineIDHash(raw string) string {
	id := strings.ToLower(strings.TrimSpace(raw))
	if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" || strings.Trim(id, "0") == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(machineIDPrefix + id))
	return hex.EncodeToString(sum[:])
}

package main

// Files the write path keeps on disk. Everything lives under /var/lib/securemyserver (0700, root) or
// /etc/securemyserver (root). fsRoot lets the unit tests run the same code inside a temp dir.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

var fsRoot = "" // "" on a real server; a temp dir in tests

const (
	stateDir      = "/var/lib/securemyserver"
	checkpointDir = stateDir + "/checkpoints"
	switchState   = stateDir + "/switches.json"
	lockFile      = stateDir + "/lock"
	allowDir      = "/etc/securemyserver/allow.d"
	// Signed reports (D-043): this server's Ed25519 key (a base64 seed, 0600) and the statement that the old key
	// signed it, sent with every report after `securemyserver rotate-key`.
	reportKeyFile      = stateDir + "/report_key"
	reportRotationFile = stateDir + "/report_key.rotation"
	// The signed blocklist (D-041): what was applied, and the nft file it was applied from.
	blocklistStateFile = stateDir + "/blocklist.json"
	blocklistNftFile   = stateDir + "/blocklist.nft"
)

// rp maps an absolute server path into fsRoot.
func rp(path string) string { return fsRoot + path }

var errNotRoot = errors.New("run this as root (sudo)")

// requireRoot is a variable so tests can run the CLI without root.
var requireRoot = func() error {
	if os.Geteuid() != 0 {
		return errNotRoot
	}
	return nil
}

// withLock serializes the agent loop, the CLI and the systemd backup timer, which may all try to restore or
// confirm the same checkpoint at the same moment.
func withLock(fn func() error) error {
	if err := os.MkdirAll(rp(stateDir), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(rp(lockFile), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock %s: %w", lockFile, err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN) //nolint:errcheck
	return fn()
}

// writeFileAtomic writes to a temp file in the same directory, syncs it and renames it into place.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".smstmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(path, append(b, '\n'), 0o600)
}

func readJSON(path string, v any) error {
	b, err := readCapped(path, 8<<20)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// isSystemd reports whether systemd is PID 1 (the same test sd_booted() uses).
var isSystemd = func() bool {
	st, err := os.Stat("/run/systemd/system")
	return err == nil && st.IsDir()
}

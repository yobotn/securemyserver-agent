package main

// The server-side key of the two-key rule (D-014): a switch signed in the dashboard only runs when root on this
// server allowed it first with `securemyserver allow <switch>`. Each allowed switch is an empty root-owned file
// in /etc/securemyserver/allow.d/. If that directory (or a file in it) is writable by anyone but root, nothing
// counts as allowed.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"syscall"
)

// switchNames is the whole list. Every name maps to fixed Go code in switches.go; there are no parameters and
// no "off" switches.
var switchNames = []string{
	"ssh.password_auth_off",
	"ssh.root_login_off",
	"ssh.max_auth_tries_3",
	"updates.security_now",
	"updates.unattended_on",
	"firewall.on_keep_ssh",
}

func knownSwitch(name string) bool { return has(switchNames, name) }

// blocklistAllow is the server-side key for the signed blocklist (D-041). It is not a switch: no policy can name
// it, and it takes no passkey tap. Root allowing it is the consent to apply lists the platform signed.
const blocklistAllow = "blocklist"

// sessionUndoAllow (session.go) is the server-side key for "Undo this session": the owner's signed undo of an AI
// session only runs after root ran `securemyserver allow session-undo`.
func knownAllow(name string) bool {
	return knownSwitch(name) || name == blocklistAllow || name == sessionUndoAllow
}

func allowNames() string {
	return strings.Join(append(append([]string{}, switchNames...), blocklistAllow, sessionUndoAllow), ", ")
}

// allowedName: root allowed this name (a switch, the blocklist or session-undo).
func allowedName(name string) bool {
	all, err := allowedAll()
	return err == nil && has(all, name)
}

// rootOnly: owned by root, not writable by group or others.
func rootOnly(st fs.FileInfo) bool {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return sys.Uid == 0 && st.Mode().Perm()&0o022 == 0
}

// allowedSwitches lists the switches root allowed on this server.
func allowedSwitches() ([]string, error) {
	all, err := allowedAll()
	out := []string{}
	for _, n := range all {
		if knownSwitch(n) {
			out = append(out, n)
		}
	}
	return out, err
}

// blocklistAllowed: root ran `securemyserver allow blocklist`.
func blocklistAllowed() bool {
	all, err := allowedAll()
	return err == nil && has(all, blocklistAllow)
}

// allowedAll lists everything root allowed: switches and the blocklist.
func allowedAll() ([]string, error) {
	for _, d := range []string{"/etc/securemyserver", allowDir} {
		st, err := os.Lstat(rp(d))
		if errors.Is(err, fs.ErrNotExist) {
			return []string{}, nil
		}
		if err != nil {
			return []string{}, err
		}
		if !st.IsDir() || !rootOnly(st) {
			return []string{}, fmt.Errorf("%s must be a directory owned by root and writable only by root; no switch counts as allowed", d)
		}
	}
	ents, err := os.ReadDir(rp(allowDir))
	if err != nil {
		return []string{}, err
	}
	out := []string{}
	for _, e := range ents {
		if !knownAllow(e.Name()) {
			continue
		}
		st, err := os.Lstat(rp(allowDir + "/" + e.Name()))
		if err != nil || !st.Mode().IsRegular() || !rootOnly(st) {
			continue
		}
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out, nil
}

func switchAllowed(name string) bool {
	list, err := allowedSwitches()
	return err == nil && has(list, name)
}

func allowSwitch(name string) error {
	if !knownAllow(name) {
		return fmt.Errorf("unknown switch %q. You can allow: %s", name, allowNames())
	}
	if err := os.MkdirAll(rp("/etc/securemyserver"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(rp(allowDir), 0o700); err != nil {
		return err
	}
	if err := os.Chmod(rp(allowDir), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(rp(allowDir+"/"+name), nil, 0o600)
}

func disallowSwitch(name string) error {
	if !knownAllow(name) {
		return fmt.Errorf("unknown switch %q. You can allow: %s", name, allowNames())
	}
	err := os.Remove(rp(allowDir + "/" + name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

package main

import (
	"bufio"
	"bytes"
	"os"
	"sort"
	"strings"
	"time"
)

// collectUpdates simulates an upgrade (apt-get -s never changes the system) and reads the reboot flag.
func collectUpdates() (Updates, error) {
	u := Updates{Source: "none", SecurityPackages: []string{}, RebootPackages: []string{}, Unattended: "unknown"}
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		u.RebootRequired = true
		if b, err := readCapped("/var/run/reboot-required.pkgs", 64<<10); err == nil {
			u.RebootPackages = uniqueLines(b, 50)
		}
	}
	if _, err := lookPath("apt-get"); err != nil {
		return u, nil
	}
	out, _, err := run(2*time.Minute, "apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade")
	if err != nil {
		return u, err
	}
	u.Source = "apt-get"
	u.Pending, u.Security, u.SecurityPackages = parseAptSimulate(out)
	u.Unattended = unattendedState()
	return u, nil
}

// unattendedState: is unattended-upgrades installed (dpkg-query), and does apt run it (apt-config dump)?
func unattendedState() string {
	if _, err := lookPath("dpkg-query"); err != nil {
		return "unknown"
	}
	st, _, _ := run(15*time.Second, "dpkg-query", "-W", "-f=${Status}", "unattended-upgrades")
	if !strings.Contains(string(st), "install ok installed") {
		return "absent"
	}
	out, _, err := run(15*time.Second, "apt-config", "dump")
	if err != nil {
		return "unknown"
	}
	if aptPeriodicOn(out, "APT::Periodic::Unattended-Upgrade") {
		return "on"
	}
	return "off"
}

// aptPeriodicOn reads `apt-config dump` lines like `APT::Periodic::Unattended-Upgrade "1";`. Any value other
// than 0 (or empty) runs it. The last line wins, as in apt.
func aptPeriodicOn(dump []byte, key string) bool {
	on := false
	for _, l := range strings.Split(string(dump), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), " ")
		if !ok || !strings.EqualFold(k, key) {
			continue
		}
		v = strings.Trim(strings.TrimSuffix(strings.TrimSpace(v), ";"), `"`)
		on = v != "" && v != "0" && !strings.EqualFold(v, "false")
	}
	return on
}

// parseAptSimulate reads `apt-get -s upgrade` output. A package counts as a security update when
// any of its target suites is a -security pocket, e.g.
// Inst openssl [3.0.13-0ubuntu3.1] (3.0.13-0ubuntu3.4 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
func parseAptSimulate(b []byte) (pending, security int, secPkgs []string) {
	secPkgs = []string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		pending++
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		open := strings.Index(line, "(")
		if open >= 0 && strings.Contains(line[open:], "-security") {
			security++
			if len(secPkgs) < 50 {
				secPkgs = append(secPkgs, fields[1])
			}
		}
	}
	sort.Strings(secPkgs)
	return pending, security, secPkgs
}

func uniqueLines(b []byte, max int) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || seen[l] || len(out) >= max {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	return out
}

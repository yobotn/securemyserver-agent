package main

import (
	"bufio"
	"bytes"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

var noLoginShells = map[string]bool{
	"": true, "/usr/sbin/nologin": true, "/sbin/nologin": true, "/bin/false": true, "/usr/bin/false": true,
	"/bin/sync": true, "/usr/bin/sync": true, "/sbin/shutdown": true, "/sbin/halt": true,
}

// collectUsers lists accounts with a login shell, whether they are in sudo/wheel/admin, and how many
// keys their authorized_keys files hold. It counts keys; it never sends key material.
func collectUsers() ([]User, error) {
	pw, err := readCapped("/etc/passwd", 4<<20)
	if err != nil {
		return []User{}, err
	}
	grp, _ := readCapped("/etc/group", 4<<20)
	sudoers := parseSudoMembers(grp)
	users := parsePasswd(pw)
	for i := range users {
		u := &users[i]
		u.Sudo = sudoers[u.Name] || u.UID == 0
		u.AuthorizedKeys = countKeys(filepath.Join(u.Home, ".ssh", "authorized_keys")) +
			countKeys(filepath.Join(u.Home, ".ssh", "authorized_keys2"))
	}
	return users, nil
}

func parsePasswd(b []byte) []User {
	out := []User{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Split(sc.Text(), ":")
		if len(f) < 7 || strings.HasPrefix(f[0], "#") {
			continue
		}
		shell := strings.TrimSpace(f[6])
		if noLoginShells[shell] {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		if len(out) < 500 {
			out = append(out, User{Name: f[0], UID: uid, Home: f[5], Shell: shell})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out
}

// parseSudoMembers returns the members of the sudo, wheel and admin groups in /etc/group.
func parseSudoMembers(b []byte) map[string]bool {
	out := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Split(sc.Text(), ":")
		if len(f) < 4 {
			continue
		}
		switch f[0] {
		case "sudo", "wheel", "admin":
			for _, m := range strings.Split(f[3], ",") {
				if m = strings.TrimSpace(m); m != "" {
					out[m] = true
				}
			}
		}
	}
	return out
}

func countKeys(path string) int {
	b, err := readCapped(path, 1<<20)
	if err != nil {
		return 0
	}
	return countKeyLines(b)
}

func countKeyLines(b []byte) int {
	n := 0
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			n++
		}
	}
	return n
}

package main

import (
	"bufio"
	"bytes"
	"runtime"
	"strings"
)

func collectOS() (OSInfo, error) {
	info := OSInfo{Arch: runtime.GOARCH}
	b, err := readCapped("/etc/os-release", 64<<10)
	if err != nil {
		b, err = readCapped("/usr/lib/os-release", 64<<10)
	}
	if err == nil {
		kv := parseOSRelease(b)
		info.ID, info.VersionID, info.PrettyName = kv["ID"], kv["VERSION_ID"], kv["PRETTY_NAME"]
	}
	if k, kerr := readCapped("/proc/sys/kernel/osrelease", 256); kerr == nil {
		info.Kernel = strings.TrimSpace(string(k))
	}
	if a, aerr := readCapped("/proc/sys/kernel/arch", 64); aerr == nil && len(bytes.TrimSpace(a)) > 0 {
		info.Arch = strings.TrimSpace(string(a))
	}
	return info, err
}

// parseOSRelease parses KEY=value lines, with optional single or double quotes.
func parseOSRelease(b []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[strings.TrimSpace(k)] = strings.ReplaceAll(v, `\"`, `"`)
	}
	return out
}

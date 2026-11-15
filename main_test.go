package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestSubcommands(t *testing.T) {
	var out, errb bytes.Buffer
	if code := dispatch([]string{"allow"}, &out, &errb); code == 0 {
		t.Fatal("allow without a switch name")
	}
	if code := dispatch([]string{"help"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "checkpoint") {
		t.Fatalf("help: %q", out.String())
	}
	if code := dispatch(nil, &out, &errb); code != 2 || !strings.Contains(errb.String(), "usage: securemyserver") {
		t.Fatalf("no args: code %d", code)
	}
	if code := dispatch([]string{"version"}, &out, &errb); code != 0 || !strings.Contains(out.String(), agentVersion) {
		t.Fatalf("version: code %d out %q", code, out.String())
	}
}

func TestResolveConfigPath(t *testing.T) {
	only := func(paths ...string) func(string) bool {
		return func(p string) bool {
			for _, x := range paths {
				if x == p {
					return true
				}
			}
			return false
		}
	}
	if p, n := resolveConfigPath("/tmp/x.conf", only(legacyConfigPath)); p != "/tmp/x.conf" || n != "" {
		t.Fatalf("flag: %s %q", p, n)
	}
	if p, n := resolveConfigPath("", only(defaultConfigPath, legacyConfigPath)); p != defaultConfigPath || n != "" {
		t.Fatalf("both: %s %q", p, n)
	}
	if p, n := resolveConfigPath("", only(legacyConfigPath)); p != legacyConfigPath || !strings.Contains(n, "deprecated") {
		t.Fatalf("legacy: %s %q", p, n)
	}
	if p, _ := resolveConfigPath("", only()); p != defaultConfigPath {
		t.Fatalf("none: %s", p)
	}
}

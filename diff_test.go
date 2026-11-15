package main

import (
	"strings"
	"testing"
)

func TestUnifiedDiff(t *testing.T) {
	a := strings.Split("a\nb\nc\nd\ne\nf\ng\nh\ni\nj", "\n")
	b := strings.Split("a\nb\nc\nD\ne\nf\ng\nh\ni\nj\nk", "\n")
	got := unifiedDiff(a, b, "a/x", "b/x")
	want := "--- a/x\n+++ b/x\n@@ -1,7 +1,7 @@\n a\n b\n c\n-d\n+D\n e\n f\n g\n@@ -8,3 +8,4 @@\n h\n i\n j\n+k\n"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	if unifiedDiff(a, a, "a", "b") != "" {
		t.Fatal("equal files have no diff")
	}
	if got := unifiedDiff(nil, []string{"x"}, "/dev/null", "b/x"); got != "--- /dev/null\n+++ b/x\n@@ -0,0 +1 @@\n+x\n" {
		t.Fatalf("added: %q", got)
	}
	if got := unifiedDiff([]string{"x", "y"}, nil, "a/x", "/dev/null"); got != "--- a/x\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-x\n-y\n" {
		t.Fatalf("removed: %q", got)
	}
}

func TestRedactAndSkip(t *testing.T) {
	for in, want := range map[string]string{
		"PasswordAuthentication no":                   "PasswordAuthentication no",
		"PasswordAuthentication=yes":                  "PasswordAuthentication=yes",
		"Environment=API_TOKEN=abc123":                "Environment=API_TOKEN=[redacted]",
		`Environment="DB_PASSWORD=hunter2"`:           `Environment="DB_PASSWORD=[redacted]`,
		"deb https://user:s3cret@repo.example/ubuntu": "deb https://[redacted]@repo.example/ubuntu",
		"client_secret: xyz":                          "client_secret: [redacted]",
		"ExecStart=/usr/bin/app --port 3000":          "ExecStart=/usr/bin/app --port 3000",
	} {
		if got, _ := redactLine(in); !strings.HasPrefix(got, want) || strings.Contains(got, "hunter2") {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
	for _, p := range []string{"/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_rsa_key.pub", "/etc/apt/trusted.gpg.d/x.gpg", "/etc/systemd/system/app.secret", "/etc/shadow"} {
		if !secretName(p) {
			t.Errorf("%s must be listed without content", p)
		}
	}
	if secretName("/etc/ssh/sshd_config.d/50-cloud-init.conf") || secretName("/etc/sudoers.d/securemyserver-ai") {
		t.Error("config files are diffed")
	}
	if _, why := textLines([]byte("x\x00y")); why != "binary" {
		t.Errorf("binary: %q", why)
	}
	if _, why := textLines([]byte("-----BEGIN RSA PRIVATE KEY-----\n")); why != "secret" {
		t.Errorf("private key content: %q", why)
	}
	if _, why := textLines(make([]byte, maxDiffFileBytes+1)); why != "too_large" {
		t.Errorf("big: %q", why)
	}
}

func TestStripOwnTable(t *testing.T) {
	in := "table inet filter {\n\tchain input {\n\t}\n}\ntable inet securemyserver {\n\tset securemyserver_block {\n\t}\n}\ntable ip nat {\n}"
	if got := stripOwnTable(in); got != "table inet filter {\n\tchain input {\n\t}\n}\ntable ip nat {\n}" {
		t.Fatalf("%q", got)
	}
}

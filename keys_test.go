package main

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Vectors generated with ssh-keygen (OpenSSH 9.6p1, Ubuntu 24.04); FP is `ssh-keygen -lf` output.
var keyVectors = []struct {
	pub, typ, fp string
	bits         int
}{
	{"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCgtMOkFoeKxzEmnEhdwyV2LPg1f7ZXKprCr44t9j2TALXfkBY53cd29gr9rb48Ccv+spMZbfuNy8Saz4wqWi2twdxk1TdTH/P0Ff728UXhj58uW8LzzuxtnvCYo98Q4/qPyG1KWLCysJNrzMpBQoEAQKBwBfR2DhjEUhMM5OEE2/npreR2tDeZpqkAdSZQpRA28TWg8eIHdGy0laBdz2DStnpO0b1ktXeX3jl+raI82+VjQ7DeMjnBq4eBzHHWonBXWLP/D7amEm2ncHQ1WTjc/XLzF2IC863mxsbP283FkuugX2c+rdwsc2dTCHVxtOZfMt4oNYojDSixuwV+9kkV old laptop",
		"ssh-rsa", "SHA256:ccFXlb0kya2aSNhTwM74XlnwBVOMXLT51zqvfIHqmJ0", 2048},
	{"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCLryTe7Ks2IDz67cR9vOZJ2hGK6tROpDRQvm52KnVw3WeAgCnM88eT93qLi5MMLtsHR3mmm96WG91gfyDo4RYgYJJPpydHgp1kKmV7UQeTN1OiW+Bbb3b+xEXtbkmFjZmu3YO0h6TNMmrWvuaj2cB4RWkjVVeZggu5YPiOusf+06reGtOl/WGjNfn+FwoilnnR7mCA0gM4cxO0x2l267aCzL/RXwY3bm2sHGnBvXO/siiYV9BL7/9CUmsxZVYCpIDwy/235rdETYgSCoq127Par+SI2DBx0/LttdNT8mCSzYcWQ6X4zj2HriAZ++ooy6EWvVk+uaej53qYYXBUgLrkIPiR4DXYKrU/MzsHhEkYTvP5XheMdz+Ooar+dwaeSZ3V+czE0mSRh1/dLt10qksEO5Svo9liwMXsAflBl0TW3bGfQXi0P1YCyHyzjV2phNiCVdWSUFih0LyprkfbmmQDB2h4Osm7gWPQYVkTNKlib002GXlljhZuY1iXuz3mKdc= ci@build",
		"ssh-rsa", "SHA256:bq5aSNoTu0NR0ZeLxu3pjPXnxsusdAHT/TJ2fsWq064", 3072},
	{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIWgBgWLxexovnlAJd9L2+ovSLY823bMUpiQrN9jnDFm yb@laptop",
		"ssh-ed25519", "SHA256:16zpKIJLpvoGi1bN7gEd/y+iwDSqOo5T566rezQ89do", 256},
	{"ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBAFFJrstw27kHwaQlB6FCgnUOP7mhKg0MIYn8hJKyU6lwbOt3X413vWRAcQvlt3hK+zyV1zN2ASRlF05wJPxHl46OJNUoJbcNTbOSjahgsnBb0be8hStpOoxcxnYw5ZkXg== ",
		"ecdsa-sha2-nistp384", "SHA256:1jibO1J/wZ60wx15BLMeJ520MiAyumOEKszf4oOfc2c", 384},
	{"ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAFOoHKgQ+xIW2SJP1QgVpFqavqGFhKB8w4LrRHvK/ev0K3zPY4CbEbJmviFFvKTXNKz0kQ3Nxd2E+j1XSP8xFFvnAFVRAYSxgAZyRqHfLr70x4jG/zPGV2tV5OdXM3RYvBPntXPvCYYXch0+Ia5VvTp/hpJK14q/g8rCWBhRxbhcYygTg== e521",
		"ecdsa-sha2-nistp521", "SHA256:AP4hKx4qJdmOetfuQlFfKuM3cakRWasmtQfErKsW81c", 521},
	{"ssh-dss AAAAB3NzaC1kc3MAAACBAKgREdCC5DP/wKIWS9thNgCEJk/ldSItdueVrGEp9TIpeYgCM/aVvFYjiAxcAvTKs2+UDUHk5ik54VK5QkuamlEE5HhTEP9WiXBsRxMuDRl5sIe/MhIHgPrg8CMLpN1D8kpGXhBH17q2ANrY1YUaUFqdtqLip+K/e7k1bUUNCcf/AAAAFQDHlo7acN2+bZv3YTr6L8yF7cFLFQAAAIEAom6R+piIs3g7BPMqPAr1p2GOyu2rNx7TuVPbOSdgP9DaIH6h8dtt6ZL02694+R9xY3lkraks/PlrrT3368vwVxSzkQtl2ibBbnWfcUYfIw5l+K7HJsuhROtNAZho1KTlv+xeABIQakN63p0XdA4RnsM82i4t9/6NkDbaF4GB+L8AAACATr0ld7voqVhVhRlYcbVAnGRF3a0M2o3QeUbmc2q7GfCTatd/gbJ/gDGP7L79MV92m+2vbsE94UkOmJTs7E8D1NRWD7Uag6kda5w0YC8Hi1XMoNa2GppIzxybaEj6wog+gPf7cl8pP61AC4hjyTLHKujmAXF3VSwV7Y9YDlzOx0o= ancient",
		"ssh-dss", "SHA256:s38nXokC/8V1vuK/pPXQN3zx1PtxDuwrZbkwTblEhNk", 1024},
}

func TestKeyFingerprintsMatchSSHKeygen(t *testing.T) {
	for _, v := range keyVectors {
		k, ok := parseKeyLine(v.pub)
		if !ok {
			t.Fatalf("did not parse %.40s", v.pub)
		}
		if k.Type != v.typ || k.Fingerprint != v.fp || k.Bits != v.bits {
			t.Errorf("%s: got %s %s %d, want %s %d", v.typ, k.Type, k.Fingerprint, k.Bits, v.fp, v.bits)
		}
	}
}

func TestParseKeyOptions(t *testing.T) {
	ed := keyVectors[2].pub
	line := `restrict,from="203.0.113.7,10.0.0.0/8",expiry-time="20270206",command="/usr/lib/securemyserver/securemyserver-gate",no-touch-required,verify-required,permitopen="host:22",environment="TOKEN=secret" ` + ed
	k, ok := parseKeyLine(line)
	if !ok {
		t.Fatal("did not parse")
	}
	o := k.Options
	if !o.Restrict || !o.VerifyRequired || !o.NoTouchRequired || o.Command != "/usr/lib/securemyserver/securemyserver-gate" {
		t.Fatalf("options %+v", o)
	}
	if strings.Join(o.From, "|") != "203.0.113.7|10.0.0.0/8" || o.ExpiryTime != "20270206" || o.ExpiresAt == "" {
		t.Fatalf("from/expiry %+v", o)
	}
	if strings.Join(o.Other, ",") != "permitopen,environment" || strings.Contains(strings.Join(o.Other, ","), "secret") {
		t.Fatalf("other %v (values must not be sent)", o.Other)
	}
	if k.Comment != "yb@laptop" || k.Fingerprint != keyVectors[2].fp {
		t.Fatalf("key %+v", k)
	}

	// Quoted values may contain spaces and escaped quotes.
	k, ok = parseKeyLine(`command="echo \"hi there\"",no-pty ` + ed)
	if !ok || k.Options.Command != `echo "hi there"` || k.Options.Other[0] != "no-pty" {
		t.Fatalf("quoted %+v %v", k.Options, ok)
	}
	if t2, ok := parseExpiryTime("202702061530Z", time.Local); !ok || !t2.Equal(time.Date(2027, 2, 6, 15, 30, 0, 0, time.UTC)) {
		t.Fatalf("expiry %v", t2)
	}
}

func TestParseKeyLineRejects(t *testing.T) {
	ed := keyVectors[2].pub
	for _, bad := range []string{
		"",
		"# comment " + ed,
		"ssh-ed25519 not-base64!!",
		`from="1.2.3.4 ` + ed,              // unterminated quote
		"ssh-rsa " + strings.Fields(ed)[1], // blob type does not match the line
		"root:x:0:0:root:/root:/bin/bash",  // a file that is not authorized_keys
	} {
		if k, ok := parseKeyLine(bad); ok {
			t.Errorf("parsed %q as %+v", bad, k)
		}
	}
}

func TestCommentSanitized(t *testing.T) {
	k, ok := parseKeyLine(keyVectors[2].pub[:strings.LastIndex(keyVectors[2].pub, " ")] + " evil\x1b[31m\u202eredgnits " + strings.Repeat("a", 300))
	if !ok {
		t.Fatal("did not parse")
	}
	if strings.ContainsAny(k.Comment, "\x1b\u202e") || len(k.Comment) > maxCommentLen {
		t.Fatalf("comment %q", k.Comment)
	}
}

func TestParseAuthorizedKeysFile(t *testing.T) {
	file := "# keys\n\n" + keyVectors[0].pub + "\ngarbage line\n" + keyVectors[2].pub + "\n"
	keys := parseAuthorizedKeys([]byte(file))
	if len(keys) != 2 || keys[0].Line != 3 || keys[1].Line != 5 {
		t.Fatalf("got %+v", keys)
	}
}

func TestKeyFilePaths(t *testing.T) {
	o := keyOwner{Name: "deploy", UID: 1000, Home: "/home/deploy"}
	got := strings.Join(keyFilePaths("", o), " ")
	if got != "/home/deploy/.ssh/authorized_keys /home/deploy/.ssh/authorized_keys2" {
		t.Fatalf("default %q", got)
	}
	got = strings.Join(keyFilePaths("/etc/ssh/keys/%u %h/.ssh/authorized_keys /etc/ssh/keys/%u", o), " ")
	if got != "/etc/ssh/keys/deploy /home/deploy/.ssh/authorized_keys" {
		t.Fatalf("custom %q", got)
	}
	if keyFilePaths("none", o) != nil || len(keyFilePaths("%x/keys", o)) != 0 {
		t.Fatal("none / unknown token")
	}
}

func TestKeyOwners(t *testing.T) {
	pw := "root:x:0:0:root:/root:/usr/sbin/nologin\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\ndeploy:x:1000:1000::/home/deploy:/bin/bash\n"
	o := keyOwnersFrom([]byte(pw))
	if len(o) != 2 || o[0].Name != "root" || o[1].Name != "deploy" {
		t.Fatalf("owners %+v (root is always included)", o)
	}
}

func TestKeyUsageFromJournal(t *testing.T) {
	m := map[string]keyUse{}
	fp := "SHA256:16zpKIJLpvoGi1bN7gEd/y+iwDSqOo5T566rezQ89do"
	out := `{"__REALTIME_TIMESTAMP":"1762596000123456","_UID":"0","_COMM":"sshd-session","MESSAGE":"Accepted publickey for deploy from 203.0.113.7 port 51234 ssh2: ED25519 ` + fp + `"}
{"__REALTIME_TIMESTAMP":"1762590000000000","_UID":"0","_COMM":"sshd-session","MESSAGE":"Accepted publickey for deploy from 198.51.100.1 port 1 ssh2: ED25519 ` + fp + `"}
{"__REALTIME_TIMESTAMP":"1762596000000000","_UID":"0","_COMM":"sshd-session","MESSAGE":"Accepted password for deploy from 203.0.113.7 port 51234 ssh2"}
{"__REALTIME_TIMESTAMP":"1762599999000000","_UID":"1000","_COMM":"logger","MESSAGE":"Accepted publickey for deploy from 198.51.100.9 port 1 ssh2: ED25519 ` + fp + `"}
`
	ev, rejected := parseJournalCapped([]byte(out), time.Unix(0, 0), 1<<30)
	noteKeyEvents(m, ev)
	u, ok := m["deploy\x00"+fp]
	if len(m) != 1 || !ok || rejected != 1 || u.IP != "203.0.113.7" || u.TS.Unix() != 1762596000 {
		t.Fatalf("usage %+v rejected %d", m, rejected)
	}
}

// Without a journal, auth.log and its rotated copies are read newest first, .gz included, and a rotated file older
// than the scan window stops the scan.
func TestKeyUsageFromRotatedSyslog(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "auth.log")
	fp := "SHA256:16zpKIJLpvoGi1bN7gEd/y+iwDSqOo5T566rezQ89do"
	line := func(ts, ip string) string {
		return ts + " web-1 sshd[1]: Accepted publickey for deploy from " + ip + " port 1 ssh2: ED25519 " + fp + "\n"
	}
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	write := func(name, body string, gz bool, mod time.Time) {
		p := base + name
		b := []byte(body)
		if gz {
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			zw.Write(b)
			zw.Close()
			b = buf.Bytes()
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		os.Chtimes(p, mod, mod)
	}
	write("", "2026-11-08T10:00:00Z web-1 sshd[1]: Server listening\n", false, now)
	write(".1", line("2026-11-01T10:00:00Z", "203.0.113.1"), false, now.AddDate(0, 0, -7))
	write(".2.gz", line("2026-10-20T10:00:00Z", "203.0.113.2"), true, now.AddDate(0, 0, -14))
	write(".3.gz", line("2026-11-07T10:00:00Z", "203.0.113.4"), true, now.AddDate(0, -6, 0)) // too old to open
	write(".bak", line("2026-11-07T10:00:00Z", "203.0.113.5"), false, now)                   // not a rotation name
	files := rotatedLogs(base)
	if len(files) != 4 || files[0].path != base || files[1].path != base+".1" || files[3].path != base+".3.gz" {
		t.Fatalf("files %+v", files)
	}
	m := map[string]keyUse{}
	scanSyslogFiles(m, files, now.AddDate(0, 0, -keyUsageDays), now)
	if u := m["deploy\x00"+fp]; len(m) != 1 || u.IP != "203.0.113.1" {
		t.Fatalf("usage %+v", m)
	}
	// The gzip file was read: on its own it gives its line.
	m = map[string]keyUse{}
	scanSyslogFiles(m, files[2:3], now.AddDate(0, 0, -keyUsageDays), now)
	if u := m["deploy\x00"+fp]; u.IP != "203.0.113.2" {
		t.Fatalf("gzip usage %+v", m)
	}
	if b, _ := keepTail(strings.NewReader("0123456789"), 4); string(b) != "6789" {
		t.Fatalf("tail %q", b)
	}
}

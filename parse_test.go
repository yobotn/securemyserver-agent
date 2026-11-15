package main

import (
	"strings"
	"testing"
	"time"
)

func TestParseOSRelease(t *testing.T) {
	kv := parseOSRelease([]byte("PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\n# comment\n"))
	if kv["PRETTY_NAME"] != "Ubuntu 24.04.1 LTS" || kv["ID"] != "ubuntu" || kv["VERSION_ID"] != "24.04" {
		t.Fatalf("got %v", kv)
	}
}

func TestParseAptSimulate(t *testing.T) {
	out := `Reading package lists...
Building dependency tree...
The following packages will be upgraded:
  libc6 openssl tzdata
3 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
Inst libc6 [2.39-0ubuntu8.3] (2.39-0ubuntu8.4 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst openssl [3.0.13-0ubuntu3.1] (3.0.13-0ubuntu3.4 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst tzdata [2024a-2ubuntu1] (2024b-0ubuntu0.24.04 Ubuntu:24.04/noble-updates [all])
Conf libc6 (2.39-0ubuntu8.4 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
`
	pending, sec, pkgs := parseAptSimulate([]byte(out))
	if pending != 3 || sec != 2 || strings.Join(pkgs, ",") != "libc6,openssl" {
		t.Fatalf("pending=%d sec=%d pkgs=%v", pending, sec, pkgs)
	}
}

func TestParseSSHDT(t *testing.T) {
	out := "port 22\nport 2222\nPasswordAuthentication yes\npermitrootlogin without-password\nmaxauthtries 6\n"
	m := parseSSHDT([]byte(out))
	if m["port"] != "22,2222" || m["passwordauthentication"] != "yes" || m["permitrootlogin"] != "without-password" || m["maxauthtries"] != "6" {
		t.Fatalf("got %v", m)
	}
	if v := parseSSHVersion([]byte("unknown option -- V\nOpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024\n")); v != "OpenSSH_9.6p1" {
		t.Fatalf("version %q", v)
	}
}

func TestParseProcNetTCP(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1002 1 0000000000000000 100 0 0 10 0
   2: 0A00000A:0016 0B00000A:D431 01 00000000:00000000 02:000A7B0F 00000000     0        0 1003 4 0000000000000000 20 4 30 10 -1
`
	ports := parseProcNetTCP([]byte(tcp), "tcp")
	if len(ports) != 2 {
		t.Fatalf("want 2 listeners, got %d", len(ports))
	}
	if ports[0].p.Addr != "0.0.0.0" || ports[0].p.Port != 22 || ports[0].inode != "1001" {
		t.Fatalf("got %+v", ports[0])
	}
	if ports[1].p.Addr != "127.0.0.1" || ports[1].p.Port != 5432 {
		t.Fatalf("got %+v", ports[1])
	}
	tcp6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2001 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:0BB8 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2002 1 0000000000000000 100 0 0 10 0
`
	p6 := parseProcNetTCP([]byte(tcp6), "tcp6")
	if len(p6) != 2 || p6[0].p.Addr != "::" || p6[1].p.Addr != "::1" || p6[1].p.Port != 3000 {
		t.Fatalf("got %+v", p6)
	}
}

func TestParseFirewall(t *testing.T) {
	if parseUFWStatus([]byte("Status: active\n\nTo Action From\n")) != "active" {
		t.Fatal("ufw active")
	}
	if parseUFWStatus([]byte("Status: inactive\n")) != "inactive" {
		t.Fatal("ufw inactive")
	}
	rules, drop := parseNftRuleset([]byte(`table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		tcp dport 22 accept
	}
}
`))
	if rules != 2 || !drop {
		t.Fatalf("rules=%d drop=%v", rules, drop)
	}
	rules, drop = parseNftRuleset([]byte(`table ip nat {
	chain POSTROUTING {
		type nat hook postrouting priority srcnat; policy accept;
		oifname != "docker0" ip saddr 172.17.0.0/16 masquerade
	}
}
`))
	if rules != 1 || drop {
		t.Fatalf("nat only: rules=%d drop=%v", rules, drop)
	}
}

func TestParseUsers(t *testing.T) {
	pw := "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\ndeploy:x:1000:1000::/home/deploy:/bin/bash\nsync:x:4:65534:sync:/bin:/bin/sync\n"
	users := parsePasswd([]byte(pw))
	if len(users) != 2 || users[0].Name != "root" || users[1].Name != "deploy" {
		t.Fatalf("got %+v", users)
	}
	sudo := parseSudoMembers([]byte("sudo:x:27:deploy,alice\nwheel:x:10:\nusers:x:100:bob\n"))
	if !sudo["deploy"] || !sudo["alice"] || sudo["bob"] {
		t.Fatalf("got %v", sudo)
	}
	if n := countKeyLines([]byte("# comment\nssh-ed25519 AAAA one\n\nssh-rsa AAAA two\n")); n != 2 {
		t.Fatalf("keys %d", n)
	}
}

func TestParseSyslog(t *testing.T) {
	log := `2026-11-08T10:00:01.000001+00:00 web sshd[101]: Invalid user admin from 203.0.113.5 port 50000
2026-11-08T10:00:02.000002+00:00 web sshd[101]: Failed password for invalid user admin from 203.0.113.5 port 50000 ssh2
2026-11-08T10:00:03.000003+00:00 web sshd[102]: Failed password for root from 198.51.100.7 port 50001 ssh2
2026-11-08T10:00:04.000004+00:00 web sshd[103]: Accepted publickey for deploy from 192.0.2.44 port 50002 ssh2: ED25519 SHA256:Qm4xAbc
2026-11-08T10:00:05.000005+00:00 web sshd[104]: Connection closed by 203.0.113.5 port 50003 [preauth]
2026-11-08T10:00:06.000006+00:00 web CRON[105]: pam_unix(cron:session): session opened for user root
2026-11-08T09:00:00.000000+00:00 web sshd[99]: Failed password for root from 198.51.100.7 port 49999 ssh2
`
	since := time.Date(2026, 11, 8, 9, 30, 0, 0, time.UTC)
	ev := parseSyslog([]byte(log), since, since)
	if len(ev) != 4 {
		t.Fatalf("want 4 events, got %d: %+v", len(ev), ev)
	}
	if ev[0].Result != "failed" || ev[0].Method != "none" || !ev[0].InvalidUser || ev[0].User != "admin" || ev[0].IP != "203.0.113.5" {
		t.Fatalf("invalid user: %+v", ev[0])
	}
	if ev[1].Method != "password" || !ev[1].InvalidUser {
		t.Fatalf("failed invalid: %+v", ev[1])
	}
	if ev[2].User != "root" || ev[2].InvalidUser || ev[2].IP != "198.51.100.7" {
		t.Fatalf("failed root: %+v", ev[2])
	}
	if ev[3].Result != "ok" || ev[3].Method != "publickey" || ev[3].KeyFP != "SHA256:Qm4xAbc" || ev[3].User != "deploy" {
		t.Fatalf("accepted: %+v", ev[3])
	}
	if ev[0].ID == "" || ev[0].ID == ev[1].ID {
		t.Fatal("ids must be set and distinct")
	}

	bsd := "Nov  8 10:00:01 web sshd[101]: Failed password for invalid user test from 192.0.2.9 port 4242 ssh2\n"
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.Local)
	ev = parseSyslog([]byte(bsd), now.Add(-24*time.Hour), now)
	if len(ev) != 1 || ev[0].User != "test" || ev[0].IP != "192.0.2.9" {
		t.Fatalf("bsd: %+v", ev)
	}
}

func TestParseJournal(t *testing.T) {
	j := `{"__REALTIME_TIMESTAMP":"1794132000000000","_UID":"0","_COMM":"sshd","MESSAGE":"Failed password for invalid user oracle from 203.0.113.9 port 4000 ssh2"}
{"__REALTIME_TIMESTAMP":"1794132001000000","_UID":"0","_COMM":"sshd","MESSAGE":"Server listening on 0.0.0.0 port 22."}
{"__REALTIME_TIMESTAMP":"1794132002000000","_UID":"0","_COMM":"sshd-session","MESSAGE":[73,110,118,97,108,105,100,32,117,115,101,114,32,120,32,102,114,111,109,32,49,57,50,46,48,46,50,46,49,32,112,111,114,116,32,49]}
`
	ev, rejected := parseJournal([]byte(j), time.Unix(0, 0))
	if len(ev) != 2 || rejected != 0 || ev[0].User != "oracle" || ev[1].User != "x" || ev[1].IP != "192.0.2.1" {
		t.Fatalf("got %+v rejected %d", ev, rejected)
	}
}

// Only lines journald attributes to root's sshd count. `logger -t sshd` by a user has the identifier but not the
// trusted fields; root running another program, a duplicated _UID, or a missing _COMM are refused too.
func TestParseJournalTrustedFields(t *testing.T) {
	msg := `"MESSAGE":"Accepted publickey for root from 203.0.113.9 port 1 ssh2: ED25519 SHA256:16zpKIJLpvoGi1bN7gEd/y+iwDSqOo5T566rezQ89do"`
	j := `{"__REALTIME_TIMESTAMP":"1794132000000000","SYSLOG_IDENTIFIER":"sshd","_UID":"1000","_COMM":"logger",` + msg + `}
{"__REALTIME_TIMESTAMP":"1794132000000001","SYSLOG_IDENTIFIER":"sshd","_UID":"1000","_COMM":"sshd",` + msg + `}
{"__REALTIME_TIMESTAMP":"1794132000000002","SYSLOG_IDENTIFIER":"sshd","_UID":"0","_COMM":"logger",` + msg + `}
{"__REALTIME_TIMESTAMP":"1794132000000003","SYSLOG_IDENTIFIER":"sshd","_UID":["0","1000"],"_COMM":"sshd",` + msg + `}
{"__REALTIME_TIMESTAMP":"1794132000000004","SYSLOG_IDENTIFIER":"sshd","_UID":"0",` + msg + `}
{"__REALTIME_TIMESTAMP":"1794132000000005","SYSLOG_IDENTIFIER":"sshd","_UID":"0","_COMM":"sshd-session",` + msg + `}
`
	ev, rejected := parseJournal([]byte(j), time.Unix(0, 0))
	if len(ev) != 1 || rejected != 5 || ev[0].KeyFP == "" {
		t.Fatalf("events %+v rejected %d", ev, rejected)
	}
}

func TestParseConfig(t *testing.T) {
	cfg, err := parseConfig([]byte("# securemyserver agent\nendpoint = https://ingest.securemyserver.com/v1/report\ntoken = sms_abc\n"))
	if err != nil || cfg.Token != "sms_abc" {
		t.Fatalf("cfg=%+v err=%v", cfg, err)
	}
	if _, err := parseConfig([]byte("endpoint = http://x/v1/report\ntoken = a\n")); err == nil {
		t.Fatal("plain http must be refused by default")
	}
	if _, err := parseConfig([]byte("endpoint = http://x/v1/report\ntoken = a\nallow_http = true\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := parseConfig([]byte("endpoint = https://x/\ntoken = a\ncommand = rm\n")); err == nil {
		t.Fatal("unknown keys must be refused")
	}
}

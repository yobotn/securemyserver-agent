package main

import (
	"strings"
	"testing"
	"time"
)

func TestParseGateLog(t *testing.T) {
	id1, id2, id3 := strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32)
	sess := strings.Repeat("1", 16)
	log := `{"v":1,"ev":"start","id":"` + id1 + `","ts":"2026-11-08T10:00:00.5Z","session":"` + sess + `","from_ip":"203.0.113.7","user":"securemyserver-ai","uid":999,"cmd":"uname -a","cmd_len":8}
{"v":1,"ev":"end","id":"` + id1 + `","ts":"2026-11-08T10:00:01Z","session":"` + sess + `","uid":999,"exit":0,"duration_ms":12,"bytes_out":90}
{"v":1,"ev":"refused","id":"` + id2 + `","ts":"2026-11-08T10:01:00Z","session":"` + sess + `","uid":999,"cmd":"x","cmd_len":6001,"reason":"too_long"}
not json
{"v":1,"ev":"start","id":"short","ts":"2026-11-08T10:02:00Z","session":"` + sess + `"}
{"v":1,"ev":"start","id":"` + id3 + `","ts":"2026-11-08T10:03:00Z","session":"` + sess + `","from_ip":"not-an-ip"}
{"v":1,"ev":"start","id":"` + id3 + `","ts":"2026-11-08T09:00:00Z","session":"` + sess + `","cmd":"evil \u001b[2J"}
`
	cmds, bad := parseGateLog([]byte(log), time.Date(2026, 11, 8, 9, 30, 0, 0, time.UTC))
	if bad != 3 {
		t.Fatalf("bad %d", bad)
	}
	if len(cmds) != 2 {
		t.Fatalf("cmds %+v", cmds)
	}
	c := cmds[0]
	if c.ID != id1 || !c.Ended || c.Exit == nil || *c.Exit != 0 || c.Command != "uname -a" || c.FromIP != "203.0.113.7" || c.DurationMS != 12 {
		t.Fatalf("first %+v", c)
	}
	if cmds[1].Refused != "too_long" || cmds[1].CmdLen != 6001 {
		t.Fatalf("second %+v", cmds[1])
	}
	// The 09:00 line is outside the window; with an older window its control chars come back escaped.
	cmds, _ = parseGateLog([]byte(log), time.Time{})
	if len(cmds) != 3 || cmds[0].Command != `evil \x1b[2J` {
		t.Fatalf("all %+v", cmds)
	}
}

func TestLookupUser(t *testing.T) {
	pw := []byte("root:x:0:0::/root:/bin/bash\nsecuremyserver-ai:x:998:997::/home/securemyserver-ai:/bin/sh\n")
	gr := []byte("securemyserver-ai:x:997:\nadm:x:4:securemyserver-ai,syslog\n")
	uid, gids, ok := lookupUser(pw, gr, "securemyserver-ai")
	if !ok || uid != 998 || !gids[997] || !gids[4] || gids[0] {
		t.Fatalf("uid %d gids %v", uid, gids)
	}
	if _, _, ok := lookupUser(pw, gr, "nobody"); ok {
		t.Fatal("found nobody")
	}
}

// Only entries journald received over its native socket from securemyserver-ai running the gate binary are read.
// The same JSON sent with logger, from another program, as another user or with a forged _EXE in the message
// fields counts as forged.
func TestTrustedGateLines(t *testing.T) {
	id := strings.Repeat("d", 32)
	sess := strings.Repeat("2", 16)
	line := `{\"v\":1,\"ev\":\"start\",\"id\":\"` + id + `\",\"ts\":\"2026-11-08T10:00:00Z\",\"session\":\"` + sess + `\",\"cmd\":\"uptime\",\"cmd_len\":6}`
	entry := func(extra string) string {
		return `{"SYSLOG_IDENTIFIER":"securemyserver-gate","MESSAGE":"` + line + `",` + extra + `}` + "\n"
	}
	gate := `"_EXE":"/usr/lib/securemyserver/securemyserver-gate"`
	j := entry(`"_TRANSPORT":"journal","_UID":"998",`+gate) +
		entry(`"_TRANSPORT":"syslog","_UID":"998","_EXE":"/usr/bin/logger"`) + // logger -t securemyserver-gate
		entry(`"_TRANSPORT":"journal","_UID":"998","_EXE":"/usr/bin/python3"`) + // its own native client
		entry(`"_TRANSPORT":"journal","_UID":"1000",`+gate) + // another user
		entry(`"_TRANSPORT":"journal","_UID":"998"`) + // no _EXE
		`{"SYSLOG_IDENTIFIER":"other","MESSAGE":"x","_TRANSPORT":"journal","_UID":"998",` + gate + `}` + "\n"
	lines, forged := trustedGateLines([]byte(j), 998, "/usr/lib/securemyserver/securemyserver-gate")
	if forged != 4 {
		t.Fatalf("forged %d", forged)
	}
	cmds, bad := parseGateLog(lines, time.Time{})
	if bad != 0 || len(cmds) != 1 || cmds[0].Command != "uptime" {
		t.Fatalf("cmds %+v bad %d", cmds, bad)
	}
}

func TestSuppressedFor(t *testing.T) {
	j := `{"_TRANSPORT":"driver","MESSAGE":"Suppressed 120 messages from /user.slice/user-998.slice/session-4.scope"}
{"_TRANSPORT":"driver","MESSAGE":"Suppressed 7 messages from /system.slice/ssh.service"}
{"_TRANSPORT":"driver","MESSAGE":"Suppressed 9 messages from /system.slice/cron.service"}
{"_TRANSPORT":"journal","MESSAGE":"Suppressed 1000 messages from /user.slice/user-998.slice/session-4.scope"}
`
	if n := suppressedFor([]byte(j), 998); n != 127 {
		t.Fatalf("suppressed %d", n)
	}
}

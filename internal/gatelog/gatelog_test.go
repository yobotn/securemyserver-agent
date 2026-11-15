package gatelog

import "testing"

func TestJournalMessage(t *testing.T) {
	got := string(JournalMessage([][2]string{{"MESSAGE", `{"v":1}`}, {"SYSLOG_IDENTIFIER", Identifier}, {"X", "a\nb"}}))
	want := "MESSAGE={\"v\":1}\nSYSLOG_IDENTIFIER=securemyserver-gate\nX\n\x03\x00\x00\x00\x00\x00\x00\x00a\nb\n"
	if got != want {
		t.Fatalf("got %q", got)
	}
}

package main

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestAllowSeveralAtOnce(t *testing.T) {
	newSandbox(t)
	var out, errb bytes.Buffer
	if code := dispatch([]string{"allow", "ssh.max_auth_tries_3", "nope", "blocklist"}, &out, &errb); code != 1 {
		t.Fatalf("a bad name: code %d", code)
	}
	if !strings.Contains(errb.String(), "Nothing was changed") {
		t.Fatalf("stderr %q", errb.String())
	}
	if all, _ := allowedAll(); len(all) != 0 {
		t.Fatalf("nothing may be allowed after a typo: %v", all)
	}
	out.Reset()
	if code := dispatch([]string{"allow", "ssh.max_auth_tries_3", "ssh.root_login_off", "session-undo", "ssh.max_auth_tries_3"}, &out, &errb); code != 0 {
		t.Fatalf("allow: code %d: %s", code, errb.String())
	}
	all, _ := allowedAll()
	if strings.Join(all, ",") != "session-undo,ssh.max_auth_tries_3,ssh.root_login_off" {
		t.Fatalf("allowed %v", all)
	}
	if n := strings.Count(out.String(), "Allowed "); n != 3 {
		t.Fatalf("one line per switch, duplicates once: %q", out.String())
	}
	if code := dispatch([]string{"disallow", "ssh.max_auth_tries_3", "session-undo"}, &out, &errb); code != 0 {
		t.Fatalf("disallow: code %d", code)
	}
	if all, _ := allowedAll(); strings.Join(all, ",") != "ssh.root_login_off" {
		t.Fatalf("after disallow %v", all)
	}
}

const testServerID = "0b6c1d2e-3f40-4a5b-8c6d-7e8f90a1b2c3"

// fakePlatform plays /v1/report: the enrollment token works once, after that only X-SMS-Server with a signature.
type fakePlatform struct {
	srv      *httptest.Server
	token    string
	used     bool
	requests []string
}

func newFakePlatform(t *testing.T, token string) *fakePlatform {
	p := &fakePlatform{token: token}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, via := r.Header.Get("Authorization"), r.Header.Get("X-SMS-Server")
		if r.Header.Get("X-SMS-Signature") == "" {
			http.Error(w, `{"error":"unsigned"}`, http.StatusUnauthorized)
			return
		}
		switch {
		case auth == "Bearer "+p.token && !p.used:
			p.used = true
			p.requests = append(p.requests, "token")
			w.Write([]byte(`{"ok":true,"enrolled":true,"server_id":"` + testServerID + `","summary":{"open":4,"critical":1,"verified":2,"switches_waiting":0},"envelopes":[],"ignored":{"x":1}}`))
		case auth != "":
			p.requests = append(p.requests, "dead-token")
			http.Error(w, `{"error":"this enrollment token was already used"}`, http.StatusUnauthorized)
		case via == testServerID && p.used:
			p.requests = append(p.requests, "key")
			w.Write([]byte(`{"ok":true,"summary":{"open":3,"critical":0,"verified":3,"switches_waiting":1},"envelopes":[]}`))
		default:
			p.requests = append(p.requests, "other")
			http.Error(w, `{"error":"no"}`, http.StatusUnauthorized)
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func TestEnrollmentTokenIsUsedOnce(t *testing.T) {
	newSandbox(t)
	token := "sms_enroll_" + strings.Repeat("a", 43)
	p := newFakePlatform(t, token)
	cfg := Config{Endpoint: p.srv.URL + "/v1/report", Token: token, AllowHTTP: true}
	key := signingKey()
	if key == nil {
		t.Fatal("no report key")
	}
	r1, err := post(p.srv.Client(), cfg, key, Report{})
	if err != nil {
		t.Fatal(err)
	}
	if !r1.Enrolled || r1.Summary == nil || r1.Summary.Open != 4 {
		t.Fatalf("first reply %+v", r1)
	}
	if enrolledServer(cfg) != testServerID {
		t.Fatal("enrollment not recorded")
	}
	r2, err := post(p.srv.Client(), cfg, key, Report{})
	if err != nil {
		t.Fatal(err)
	}
	if r2.Summary.SwitchesWaiting != 1 {
		t.Fatalf("second reply %+v", r2)
	}
	if strings.Join(p.requests, ",") != "token,key" {
		t.Fatalf("the dead token must never be sent again: %v", p.requests)
	}

	// A new token in agent.conf (reissued in the dashboard) is sent as a bearer again.
	cfg2 := cfg
	cfg2.Token = "sms_enroll_" + strings.Repeat("b", 43)
	if enrolledServer(cfg2) != "" {
		t.Fatal("a different token is not enrolled yet")
	}
	// An old sms_ token always stays a bearer token.
	if enrolledServer(Config{Token: "sms_" + strings.Repeat("c", 43)}) != "" {
		t.Fatal("legacy token")
	}
}

func TestEnrollmentStateLostFallsBackToServerID(t *testing.T) {
	newSandbox(t)
	token := "sms_enroll_" + strings.Repeat("d", 43)
	p := newFakePlatform(t, token)
	p.used = true // enrolled earlier; the state file is gone
	cfg := Config{Endpoint: p.srv.URL + "/v1/report", Token: token, ServerID: testServerID, AllowHTTP: true}
	if _, err := post(p.srv.Client(), cfg, signingKey(), Report{}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.requests, ",") != "dead-token,key" || enrolledServer(cfg) != testServerID {
		t.Fatalf("requests %v", p.requests)
	}
}

func TestCheckSummaryAndStatus(t *testing.T) {
	newSandbox(t)
	oldState := serviceState
	t.Cleanup(func() { serviceState = oldState })
	serviceState = func() string { return "active" }
	cfg := Config{Endpoint: "https://ingest.securemyserver.com/v1/report", Token: "sms_enroll_x", ServerID: testServerID, Origin: "https://securemyserver.com"}
	saveLastReport(lastReport{At: "2026-11-08T10:00:00Z", OK: true, Summary: &replySummary{Open: 5, Critical: 2, Verified: 3, SwitchesWaiting: 1}, Envelopes: 1})
	s := checkSummary(cfg, loadLastReport(), nil)
	for _, want := range []string{
		"Report sent to ingest.securemyserver.com.",
		"Checklist: 5 open (2 critical), 3 verified.",
		"Switches: 1 signed request(s) ran now; 1 signed in the dashboard, waiting for this server.",
		"Blocklist: ",
		"Dashboard: https://securemyserver.com/app/servers/" + testServerID,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("summary lacks %q:\n%s", want, s)
		}
	}
	bad := checkSummary(cfg, nil, errors.New(`send report: HTTP 401: {"error":"this enrollment token was already used"}`))
	if !strings.Contains(bad, "Report NOT sent") || !strings.Contains(bad, "new enrollment token") {
		t.Fatalf("failure summary:\n%s", bad)
	}

	conf := writeTestConf(t, "endpoint = https://ingest.securemyserver.com/v1/report\ntoken = sms_enroll_x\n")
	var out, errb bytes.Buffer
	if code := dispatch([]string{"status", "--config", conf}, &out, &errb); code != 0 {
		t.Fatalf("status: %d %s", code, errb.String())
	}
	for _, want := range []string{
		"Service: securemyserver.service active",
		"reports to ingest.securemyserver.com",
		"Enrollment: not yet",
		"Last report: 2026-11-08T10:00:00Z ok (5 open, 2 critical, 3 verified)",
		"Allowed switches: none",
		"Waiting checkpoint: none",
		"Report key: none yet",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("status lacks %q:\n%s", want, out.String())
		}
	}
}

func writeTestConf(t *testing.T, body string) string {
	t.Helper()
	p := t.TempDir() + "/agent.conf"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

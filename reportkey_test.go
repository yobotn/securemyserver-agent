package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestReportKeySignAndRotate(t *testing.T) {
	s := newSandbox(t)
	if _, err := loadReportKey(false); err == nil {
		t.Fatal("no key yet, and create is off")
	}
	k, err := loadReportKey(true)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(rp(reportKeyFile))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode: %v %v", st.Mode(), err)
	}
	again, _ := loadReportKey(true)
	if again.public() != k.public() {
		t.Fatal("the key must stay the same across runs")
	}

	body := []byte(`{"version":1}`)
	req, _ := http.NewRequest(http.MethodPost, "https://ingest.securemyserver.com/v1/report", bytes.NewReader(body))
	k.signRequest(req, body, s.now)
	pub, _ := base64.StdEncoding.DecodeString(req.Header.Get("X-SMS-Key"))
	sig, _ := base64.StdEncoding.DecodeString(req.Header.Get("X-SMS-Signature"))
	msg := []byte(requestPrefix + req.Header.Get("X-SMS-Timestamp") + "\nPOST /v1/report\n" + string(body))
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("the platform could not verify the request")
	}
	if req.Header.Get("X-SMS-Key-Rotation") != "" {
		t.Error("no rotation header before rotate-key")
	}

	var out, errb bytes.Buffer
	if code := cmdRotateKey(nil, &out, &errb); code != 0 {
		t.Fatalf("rotate-key: %d %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "New report key SHA256:") {
		t.Errorf("rotate-key output: %s", out.String())
	}
	n, err := loadReportKey(false)
	if err != nil || n.public() == k.public() {
		t.Fatalf("rotated key: %v", err)
	}
	f := strings.Fields(n.rotation)
	if len(f) != 5 || f[1] != k.public() || f[2] != n.public() {
		t.Fatalf("rotation statement: %q", n.rotation)
	}
	oldSig, _ := base64.StdEncoding.DecodeString(f[4])
	if !ed25519.Verify(pub, []byte(rotatePrefix+f[1]+"\n"+f[2]+"\n"+f[3]), oldSig) {
		t.Fatal("the old key did not sign the new one")
	}
	req2, _ := http.NewRequest(http.MethodGet, "https://ingest.securemyserver.com/v1/blocklist", nil)
	n.signRequest(req2, nil, s.now)
	if req2.Header.Get("X-SMS-Key-Rotation") != n.rotation {
		t.Error("the rotation statement rides with every request")
	}

	// A key file anyone can read is refused.
	_ = os.Chmod(rp(reportKeyFile), 0o644)
	if _, err := loadReportKey(true); err == nil {
		t.Error("a world-readable key was used")
	}
}

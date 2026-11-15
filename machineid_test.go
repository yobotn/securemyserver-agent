package main

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestMachineIDHash(t *testing.T) {
	id := "0123456789abcdef0123456789abcdef"
	want := sha256.Sum256([]byte("securemyserver-machine-v1:" + id))
	if got := machineIDHash(id + "\n"); got != hex.EncodeToString(want[:]) {
		t.Fatalf("hash = %q", got)
	}
	if got := machineIDHash("0123456789ABCDEF0123456789ABCDEF"); got != hex.EncodeToString(want[:]) {
		t.Fatalf("upper case not normalized: %q", got)
	}
	plain := sha256.Sum256([]byte(id))
	if machineIDHash(id) == hex.EncodeToString(plain[:]) {
		t.Fatal("hash must carry the platform prefix")
	}
	for _, bad := range []string{"", "uninitialized\n", "00000000000000000000000000000000", "xyz", id + "00"} {
		if got := machineIDHash(bad); got != "" {
			t.Fatalf("machineIDHash(%q) = %q, want empty", bad, got)
		}
	}
}

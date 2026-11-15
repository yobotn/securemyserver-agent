package main

// Signed reports (D-043). On its first run the agent makes an Ed25519 key in /var/lib/securemyserver/report_key
// (0600, root only). Every request to the platform carries:
//
//	X-SMS-Timestamp: <unix seconds>
//	X-SMS-Key:       <raw public key, base64>
//	X-SMS-Signature: <signature, base64> over "securemyserver-request-v1\n<ts>\n<METHOD> <path>\n" + body
//
// The platform registers the key with the first signed report (trust on first use, under the enrollment token)
// and from then on refuses unsigned or wrongly signed requests, and timestamps more than 5 minutes off. The token
// alone is no longer enough to send reports in this server's name. `securemyserver rotate-key` makes a new key
// and a statement signed by the old one, sent with every later request:
//
//	X-SMS-Key-Rotation: v1 <old key> <new key> <unix seconds> <signature by the old key>
//	over "securemyserver-rotate-v1\n<old key>\n<new key>\n<unix seconds>"

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	requestPrefix = "securemyserver-request-v1\n"
	rotatePrefix  = "securemyserver-rotate-v1\n"
)

type reportKey struct {
	priv     ed25519.PrivateKey
	rotation string // the X-SMS-Key-Rotation value, when this key came from rotate-key
}

func (k *reportKey) public() string {
	return base64.StdEncoding.EncodeToString(k.priv.Public().(ed25519.PublicKey))
}

// keyFingerprint is SHA256:<base64, no padding>, the way ssh-keygen prints fingerprints.
func keyFingerprint(pub ed25519.PublicKey) string {
	s := sha256.Sum256(pub)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(s[:])
}

func readSeed(path string) (ed25519.PrivateKey, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s must be a regular file readable by root only (0600)", path)
	}
	b, err := readCapped(path, 256)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s is not an Ed25519 seed", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func writeSeed(path string, priv ed25519.PrivateKey) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(path, []byte(base64.StdEncoding.EncodeToString(priv.Seed())+"\n"), 0o600)
}

// loadReportKey reads this server's key, making one first when create is set. Call with the lock held.
func loadReportKey(create bool) (*reportKey, error) {
	priv, err := readSeed(rp(reportKeyFile))
	if errors.Is(err, fs.ErrNotExist) && create {
		_, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		if err := writeSeed(rp(reportKeyFile), priv); err != nil {
			return nil, fmt.Errorf("save %s: %w", reportKeyFile, err)
		}
	}
	if err != nil {
		return nil, err
	}
	k := &reportKey{priv: priv}
	// The rotation statement only counts for the key it names as new.
	if b, err := readCapped(rp(reportRotationFile), 1024); err == nil {
		f := strings.Fields(string(b))
		if len(f) == 5 && f[0] == "v1" && f[2] == k.public() {
			k.rotation = strings.Join(f, " ")
		}
	}
	return k, nil
}

// signRequest adds the signature headers. body is exactly what is sent.
func (k *reportKey) signRequest(req *http.Request, body []byte, now time.Time) {
	ts := strconv.FormatInt(now.Unix(), 10)
	msg := append([]byte(requestPrefix+ts+"\n"+req.Method+" "+req.URL.Path+"\n"), body...)
	req.Header.Set("X-SMS-Timestamp", ts)
	req.Header.Set("X-SMS-Key", k.public())
	req.Header.Set("X-SMS-Signature", base64.StdEncoding.EncodeToString(ed25519.Sign(k.priv, msg)))
	if k.rotation != "" {
		req.Header.Set("X-SMS-Key-Rotation", k.rotation)
	}
}

// rotationStatement is the old key signing the new one.
func rotationStatement(old, next ed25519.PrivateKey, now time.Time) string {
	o := base64.StdEncoding.EncodeToString(old.Public().(ed25519.PublicKey))
	n := base64.StdEncoding.EncodeToString(next.Public().(ed25519.PublicKey))
	at := strconv.FormatInt(now.Unix(), 10)
	sig := ed25519.Sign(old, []byte(rotatePrefix+o+"\n"+n+"\n"+at))
	return strings.Join([]string{"v1", o, n, at, base64.StdEncoding.EncodeToString(sig)}, " ")
}

// rotateReportKey makes a new key signed by the old one. The statement is written first, so a crash leaves
// either the old key (and a statement nothing uses) or the new key with its statement. Call with the lock held.
func rotateReportKey(now time.Time) (oldPub, newPub ed25519.PublicKey, err error) {
	old, err := readSeed(rp(reportKeyFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, errors.New("this server has no report key yet: the agent makes one with its first report")
	}
	if err != nil {
		return nil, nil, err
	}
	_, next, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if err := writeFileAtomic(rp(reportRotationFile), []byte(rotationStatement(old, next, now)+"\n"), 0o600); err != nil {
		return nil, nil, err
	}
	if err := writeSeed(rp(reportKeyFile), next); err != nil {
		return nil, nil, err
	}
	return old.Public().(ed25519.PublicKey), next.Public().(ed25519.PublicKey), nil
}

func cmdRotateKey(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		fmt.Fprintln(stderr, "usage: sudo securemyserver rotate-key")
		return 2
	}
	if err := requireRoot(); err != nil {
		fmt.Fprintln(stderr, "securemyserver rotate-key:", err)
		return 1
	}
	var oldPub, newPub ed25519.PublicKey
	err := withLock(func() error {
		var err error
		oldPub, newPub, err = rotateReportKey(nowFn())
		return err
	})
	if err != nil {
		fmt.Fprintln(stderr, "securemyserver rotate-key:", err)
		return 1
	}
	fmt.Fprintf(stdout, "New report key %s (was %s).\n", keyFingerprint(newPub), keyFingerprint(oldPub))
	fmt.Fprintln(stdout, "The next report carries the new key, signed by the old one; the dashboard shows the new fingerprint after it.")
	return 0
}

// reportKeyInfo is for `securemyserver status`.
func reportKeyInfo() string {
	priv, err := readSeed(rp(reportKeyFile))
	if err != nil {
		return "none yet (made by the first report)"
	}
	return keyFingerprint(priv.Public().(ed25519.PublicKey))
}

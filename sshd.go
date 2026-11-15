package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func collectSSH() (SSHInfo, error) {
	info := SSHInfo{Effective: map[string]string{}}
	info.ConfigSHA256 = configHash("/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf")
	// `sshd -V` is not an option on older OpenSSH, but every version prints its banner on stderr.
	_, verr, _ := run(10*time.Second, "sshd", "-V")
	info.Version = parseSSHVersion(verr)
	out, _, err := run(20*time.Second, "sshd", "-T")
	if err != nil {
		return info, err
	}
	info.Effective = parseSSHDT(out)
	return info, nil
}

var sshVersionRE = regexp.MustCompile(`OpenSSH_[0-9A-Za-z.]+`)

func parseSSHVersion(b []byte) string {
	return sshVersionRE.FindString(string(b))
}

// parseSSHDT reads `sshd -T` lines ("passwordauthentication yes"). Repeated keys (port, listenaddress,
// hostkey...) are joined with commas.
func parseSSHDT(b []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		k, v, _ := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		k = strings.ToLower(k)
		if k == "" || len(out) >= 400 {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) > 1000 {
			v = v[:1000]
		}
		if prev, ok := out[k]; ok {
			if len(prev)+len(v) < 1000 {
				out[k] = prev + "," + v
			}
			continue
		}
		out[k] = v
	}
	return out
}

// configHash is the sha256 of sshd_config plus its drop-ins, each prefixed by its path, so an edit to
// /etc/ssh/sshd_config.d/50-cloud-init.conf counts as drift too. Empty if sshd_config is unreadable.
func configHash(main, dropins string) string {
	b, err := readCapped(main, 1<<20)
	if err != nil {
		return ""
	}
	h := sha256.New()
	h.Write([]byte(main + "\n"))
	h.Write(b)
	files, _ := filepath.Glob(dropins) // Glob returns names in lexical order, like sshd's Include
	for _, f := range files {
		if d, err := readCapped(f, 1<<20); err == nil {
			h.Write([]byte("\n" + f + "\n"))
			h.Write(d)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

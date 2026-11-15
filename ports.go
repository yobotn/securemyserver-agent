package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// collectPorts lists listening TCP sockets from /proc/net/tcp and /proc/net/tcp6 and maps them to
// processes by scanning /proc/<pid>/fd. Read-only.
func collectPorts() ([]Port, error) {
	var ports []procPort
	var firstErr error
	for _, f := range []struct{ path, proto string }{{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp6"}} {
		b, err := readCapped(f.path, 16<<20)
		if err != nil {
			if firstErr == nil && f.proto == "tcp" {
				firstErr = err
			}
			continue
		}
		ports = append(ports, parseProcNetTCP(b, f.proto)...)
	}
	owners := socketOwners()
	tools := map[int]string{}
	for i := range ports {
		if o, ok := owners[ports[i].inode]; ok {
			ports[i].p.PID, ports[i].p.Process = o.pid, o.comm
			t, seen := tools[o.pid]
			if !seen {
				t = toolOf(o.pid, o.comm)
				tools[o.pid] = t
			}
			ports[i].p.Tool = t
		}
	}
	sort.Slice(ports, func(i, j int) bool {
		a, b := ports[i].p, ports[j].p
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Addr < b.Addr
	})
	out := make([]Port, 0, len(ports))
	seen := map[string]bool{}
	for _, pp := range ports {
		p := pp.p
		key := fmt.Sprintf("%s|%s|%d", p.Proto, p.Addr, p.Port)
		if seen[key] || len(out) >= 500 {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	return out, firstErr
}

type procPort struct {
	p     Port
	inode string
}

// parseProcNetTCP returns sockets in state 0A (LISTEN).
func parseProcNetTCP(b []byte, proto string) []procPort {
	var out []procPort
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[3] != "0A" {
			continue
		}
		hexAddr, hexPort, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(hexPort, 16, 16)
		if err != nil {
			continue
		}
		ip, err := decodeProcAddr(hexAddr)
		if err != nil {
			continue
		}
		out = append(out, procPort{p: Port{Proto: proto, Addr: ip.String(), Port: int(port)}, inode: f[9]})
	}
	return out
}

// decodeProcAddr decodes the kernel's hex address: 32-bit words in host (little-endian) order.
func decodeProcAddr(s string) (net.IP, error) {
	raw, err := hex.DecodeString(s)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return nil, fmt.Errorf("bad address %q", s)
	}
	ip := make(net.IP, len(raw))
	for w := 0; w < len(raw); w += 4 {
		ip[w], ip[w+1], ip[w+2], ip[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	if len(ip) == 16 {
		if v4 := ip.To4(); v4 != nil && !ip.Equal(net.IPv6zero) {
			return v4, nil
		}
	}
	return ip, nil
}

type owner struct {
	pid  int
	comm string
}

func socketOwners() map[string]owner {
	out := map[string]owner{}
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		pid, err := strconv.Atoi(filepath.Base(d))
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(d + "/fd")
		if err != nil {
			continue
		}
		var comm string
		for _, fd := range fds {
			link, err := os.Readlink(d + "/fd/" + fd.Name())
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			if _, ok := out[inode]; ok {
				continue
			}
			if comm == "" {
				c, _ := readCapped(d+"/comm", 64)
				comm = strings.TrimSpace(string(c))
			}
			out[inode] = owner{pid: pid, comm: comm}
		}
	}
	return out
}

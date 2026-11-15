package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// collectDocker finds out whether Docker runs and which ports it publishes on the host. Ports Docker publishes
// are DNAT rules in its own iptables/nftables chains, which run before ufw's INPUT rules: a firewall that looks
// closed still lets them through. Read-only: `docker ps` (only when the docker CLI is installed), else Docker's
// DOCKER chain from the nft listing collectFirewall already made, else `iptables -t nat -S DOCKER`.
func collectDocker(nft nftSummary) *Docker {
	d := &Docker{Running: processRunning("dockerd"), Source: "none", Published: []DockerPort{}}
	if !d.Running {
		return d
	}
	d.UserRules = nft.dockerUserRules
	if _, err := lookPath("docker"); err == nil {
		out, _, err := run(15*time.Second, "docker", "ps", "--format", "{{.Names}}\t{{.Ports}}")
		if err == nil {
			d.Source = "docker ps"
			d.Published = parseDockerPs(out)
		}
	}
	if d.Source == "none" && nft.ok && len(nft.dockerPorts) > 0 {
		d.Source = "nft"
		d.Published = nft.dockerPorts
	}
	if d.Source == "none" {
		for _, bin := range []string{"iptables", "ip6tables"} {
			if _, err := lookPath(bin); err != nil {
				continue
			}
			out, _, err := run(15*time.Second, bin, "-t", "nat", "-S", "DOCKER")
			if err != nil {
				continue
			}
			d.Source = "iptables"
			d.Published = append(d.Published, parseIptablesDocker(out, bin == "ip6tables")...)
		}
	}
	if !nft.ok || nft.dockerUserRules == 0 {
		if _, err := lookPath("iptables"); err == nil {
			if out, _, err := run(15*time.Second, "iptables", "-S", "DOCKER-USER"); err == nil {
				d.UserRules = max(d.UserRules, countIptablesUserRules(out))
			}
		}
	}
	if len(d.Published) > 200 {
		d.Published = d.Published[:200]
	}
	return d
}

// processRunning reports whether a process with this exact name (/proc/<pid>/comm) runs.
func processRunning(name string) bool {
	dirs, _ := filepath.Glob("/proc/[0-9]*/comm")
	for _, p := range dirs {
		b, err := os.ReadFile(p)
		if err == nil && strings.TrimSpace(string(b)) == name {
			return true
		}
	}
	return false
}

// "0.0.0.0:6379->6379/tcp", "[::]:8080-8081->80-81/tcp", ":::5432->5432/tcp". A port without "->" is exposed
// to other containers only and is not published on the host.
var dockerPortRe = regexp.MustCompile(`^(.*):(\d{1,5})(?:-(\d{1,5}))?->\d{1,5}(?:-\d{1,5})?/(tcp|udp|sctp)$`)

// parseDockerPs reads `docker ps --format '{{.Names}}\t{{.Ports}}'`.
func parseDockerPs(b []byte) []DockerPort {
	var out []DockerPort
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		name, ports, ok := strings.Cut(sc.Text(), "\t")
		if !ok {
			continue
		}
		name = cleanText(name, 64)
		for _, p := range strings.Split(ports, ",") {
			m := dockerPortRe.FindStringSubmatch(strings.TrimSpace(p))
			if m == nil {
				continue
			}
			addr := strings.Trim(m[1], "[]")
			if addr == "" || addr == ":" {
				addr = "::"
			}
			from, _ := strconv.Atoi(m[2])
			to := from
			if m[3] != "" {
				to, _ = strconv.Atoi(m[3])
			}
			for port := from; port <= to && port-from < 20 && port <= 65535; port++ {
				if port > 0 && len(out) < 200 {
					out = append(out, DockerPort{Addr: addr, Port: port, Proto: m[4], Container: name})
				}
			}
		}
	}
	return out
}

// parseIptablesDocker reads `iptables -t nat -S DOCKER`:
// -A DOCKER -d 127.0.0.1/32 ! -i docker0 -p tcp -m tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80
func parseIptablesDocker(b []byte, v6 bool) []DockerPort {
	var out []DockerPort
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || f[0] != "-A" || f[1] != "DOCKER" || !strings.Contains(sc.Text(), "-j DNAT") {
			continue
		}
		p := DockerPort{Addr: "0.0.0.0", Proto: "tcp"}
		if v6 {
			p.Addr = "::"
		}
		for i := 2; i+1 < len(f); i++ {
			switch f[i] {
			case "-d":
				p.Addr = strings.TrimSuffix(strings.TrimSuffix(f[i+1], "/32"), "/128")
			case "-p":
				p.Proto = f[i+1]
			case "--dport":
				p.Port, _ = strconv.Atoi(strings.SplitN(f[i+1], ":", 2)[0])
			}
		}
		if p.Port > 0 && p.Port <= 65535 && len(out) < 200 {
			out = append(out, p)
		}
	}
	return out
}

// countIptablesUserRules counts DOCKER-USER rules other than Docker's own "-j RETURN".
func countIptablesUserRules(b []byte) int {
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "-A DOCKER-USER") && line != "-A DOCKER-USER -j RETURN" {
			n++
		}
	}
	return n
}

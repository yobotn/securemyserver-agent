package main

import (
	"bufio"
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// collectFirewall only lists rules (nft list ruleset, ufw status) and reads /etc/default/ufw and
// /proc/net/if_inet6. It never changes anything. The parsed nft listing is returned too, so the Docker check can
// read Docker's own chains from it without listing the ruleset twice.
func collectFirewall() (Firewall, nftSummary) {
	fw := Firewall{UFW: "absent", Nftables: "absent"}
	var sum nftSummary
	if _, err := lookPath("ufw"); err == nil {
		out, _, err := run(15*time.Second, "ufw", "status")
		switch {
		case err != nil && len(out) == 0:
			fw.UFW = "unknown"
		default:
			fw.UFW = parseUFWStatus(out)
		}
		fw.UFWIPv6 = "unknown"
		if b, err := readCapped("/etc/default/ufw", 64<<10); err == nil {
			fw.UFWIPv6 = parseUFWDefaultIPv6(b)
		}
	}
	if _, err := lookPath("nft"); err == nil {
		out, _, err := run(15*time.Second, "nft", "list", "ruleset")
		if err != nil {
			fw.Nftables = "unknown"
		} else {
			sum = parseNft(out)
			sum.ok = true
			fw.NftRules, fw.NftDropIn, fw.NftDropIn6 = sum.rules, sum.drop4 || sum.drop6, sum.drop6
			if fw.NftRules > 0 || fw.NftDropIn {
				fw.Nftables = "present"
			} else {
				fw.Nftables = "empty"
			}
		}
	}
	// Hosts on legacy iptables show nothing in nft: ask iptables and ip6tables for the INPUT chain too. (ufw with
	// IPV6=no sets the ip6tables INPUT policy to DROP, which this sees; a gap is a policy left on ACCEPT.)
	drop4, drop6 := sum.drop4, sum.drop6
	if !drop4 {
		drop4 = iptablesInputDrops("iptables")
	}
	if !drop6 {
		drop6 = iptablesInputDrops("ip6tables")
	}
	fw.Active = fw.UFW == "active" || fw.NftDropIn
	fw.IPv4Filtered = fw.UFW == "active" || drop4
	fw.IPv6Filtered = (fw.UFW == "active" && fw.UFWIPv6 == "yes") || drop6
	if b, err := readCapped("/proc/net/if_inet6", 1<<20); err == nil {
		fw.IPv6Global = countGlobalIPv6(b)
	}
	return fw, sum
}

// iptablesInputDrops lists the INPUT chain (iptables -S INPUT, read-only) and reports a DROP or REJECT policy or rule.
func iptablesInputDrops(bin string) bool {
	if _, err := lookPath(bin); err != nil {
		return false
	}
	out, _, err := run(15*time.Second, bin, "-S", "INPUT")
	return err == nil && parseIptablesInput(out)
}

func parseIptablesInput(b []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "-P INPUT DROP" || line == "-P INPUT REJECT" {
			return true
		}
		if strings.HasPrefix(line, "-A INPUT ") && (strings.HasSuffix(line, "-j DROP") || strings.Contains(line, "-j REJECT")) {
			return true
		}
	}
	return false
}

func parseUFWStatus(b []byte) string {
	s := strings.ToLower(string(b))
	switch {
	case strings.Contains(s, "status: active"):
		return "active"
	case strings.Contains(s, "status: inactive"):
		return "inactive"
	}
	return "unknown"
}

// parseUFWDefaultIPv6 reads IPV6= from /etc/default/ufw: yes, no, or unknown when it is not set.
func parseUFWDefaultIPv6(b []byte) string {
	v := "unknown"
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, val, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || strings.TrimSpace(k) != "IPV6" {
			continue
		}
		switch strings.ToLower(strings.Trim(strings.TrimSpace(val), `"'`)) {
		case "yes":
			v = "yes"
		case "no":
			v = "no"
		}
	}
	return v
}

// countGlobalIPv6 counts addresses with global scope in /proc/net/if_inet6 ("<32 hex> <ifindex> <prefix> <scope>
// <flags> <name>", scope 00 = global). Unique local addresses (fc00::/7) do not count: they are not reachable from
// the internet. Only the count is reported, never the addresses.
func countGlobalIPv6(b []byte) int {
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 6 || len(f[0]) != 32 || f[3] != "00" {
			continue
		}
		if p := strings.ToLower(f[0][:2]); p == "fc" || p == "fd" {
			continue
		}
		n++
	}
	return n
}

// nftSummary is what the checks need from `nft list ruleset`.
type nftSummary struct {
	ok              bool
	rules           int
	drop4, drop6    bool         // an input-hook chain for that family drops by default or has a drop/reject rule
	dockerPorts     []DockerPort // DNAT rules in Docker's DOCKER chain (nat tables)
	dockerUserRules int          // rules in DOCKER-USER besides a plain return
}

// parseNftRuleset counts rule lines and reports whether an input-hook chain drops by default or has a drop/reject
// rule, for any family. Docker-only NAT rules and the agent's own blocklist table do not count as a firewall.
func parseNftRuleset(b []byte) (rules int, inputDrop bool) {
	s := parseNft(b)
	return s.rules, s.drop4 || s.drop6
}

var (
	nftDport   = regexp.MustCompile(`\b(tcp|udp|sctp) dport (\d{1,5})\b`)
	nftDaddr4  = regexp.MustCompile(`\bip daddr (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/32)?\b`)
	nftDaddr6  = regexp.MustCompile(`\bip6 daddr ([0-9a-fA-F:]*:[0-9a-fA-F:]*)(?:/128)?`)
	nftReturns = regexp.MustCompile(`^(counter( packets \d+ bytes \d+)? )?return$`)
)

// parseNft walks the ruleset by braces: a table at depth 0, a chain or set at depth 1, rules inside a chain at
// depth 2. Set and map bodies (elements spread over many lines) are skipped.
func parseNft(b []byte) nftSummary {
	var s nftSummary
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	depth := 0
	var family, table, chain string
	inChain, inInput, skipTable := false, false, false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		open, closing := strings.Count(line, "{"), strings.Count(line, "}")
		switch {
		case depth == 0 && strings.HasPrefix(line, "table "):
			f := strings.Fields(line)
			family, table = "", ""
			if len(f) >= 3 {
				family, table = f[1], f[2]
			}
			// The agent's own blocklist table only drops listed sources; it is not a firewall (D-042).
			skipTable = family == "inet" && table == "securemyserver"
		case depth == 1 && strings.HasPrefix(line, "chain "):
			inChain, inInput = true, false
			chain = strings.Trim(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "chain "), "{")), `"`)
		case depth == 1:
			inChain = false
		case depth == 2 && inChain && !skipTable:
			s.ruleLine(line, family, table, chain, &inInput)
		}
		depth += open - closing
		if depth < 0 {
			depth = 0
		}
		if depth <= 1 {
			inChain = false
		}
	}
	return s
}

func (s *nftSummary) ruleLine(line, family, table, chain string, inInput *bool) {
	v4 := family == "ip" || family == "inet"
	v6 := family == "ip6" || family == "inet"
	drop := func() {
		s.drop4 = s.drop4 || v4
		s.drop6 = s.drop6 || v6
	}
	switch {
	case strings.HasPrefix(line, "type filter hook input"):
		*inInput = true
		if strings.Contains(line, "policy drop") || strings.Contains(line, "policy reject") {
			drop()
		}
		return
	case line == "" || line == "}" || strings.HasPrefix(line, "type ") || strings.HasPrefix(line, "policy ") ||
		strings.HasPrefix(line, "#") || strings.HasPrefix(line, "comment "):
		return
	}
	s.rules++
	if *inInput && (strings.HasSuffix(line, " drop") || line == "drop" || strings.Contains(line, " reject")) {
		drop()
	}
	if chain == "DOCKER" && table == "nat" && strings.Contains(line, "dnat to") {
		m := nftDport.FindStringSubmatch(line)
		if m == nil {
			return
		}
		port, _ := strconv.Atoi(m[2])
		addr := "0.0.0.0"
		if family == "ip6" {
			addr = "::"
		}
		if a := nftDaddr4.FindStringSubmatch(line); a != nil {
			addr = a[1]
		} else if a := nftDaddr6.FindStringSubmatch(line); a != nil {
			addr = a[1]
		}
		if port > 0 && port <= 65535 && len(s.dockerPorts) < 200 {
			s.dockerPorts = append(s.dockerPorts, DockerPort{Addr: addr, Port: port, Proto: m[1]})
		}
	}
	if chain == "DOCKER-USER" && !nftReturns.MatchString(line) {
		s.dockerUserRules++
	}
}

package main

import (
	"reflect"
	"testing"
)

func TestParseNftFamilies(t *testing.T) {
	// ufw with IPV6=no on iptables-nft: only the ip table has an input policy.
	s := parseNft([]byte(`table ip filter {
	chain INPUT {
		type filter hook input priority filter; policy drop;
		counter packets 10 bytes 600 jump ufw-before-input
	}
	chain ufw-user-input {
		tcp dport 22 counter packets 0 bytes 0 accept
	}
}
table ip6 filter {
	chain FORWARD {
		type filter hook forward priority filter; policy drop;
	}
}
`))
	if !s.drop4 || s.drop6 || s.rules != 2 {
		t.Fatalf("ufw v4 only: %+v", s)
	}
	s = parseNft([]byte(`table inet filter {
	chain input {
		type filter hook input priority filter; policy accept;
		ct state established,related accept
		tcp dport 22 accept
		counter drop
	}
}
`))
	if !s.drop4 || !s.drop6 {
		t.Fatalf("inet table covers both: %+v", s)
	}
}

func TestParseNftSkipsOwnBlocklistTableAndSets(t *testing.T) {
	s := parseNft([]byte(`table inet securemyserver {
	set securemyserver_block {
		type ipv4_addr
		flags interval
		auto-merge
		elements = { 203.0.113.0/24, 198.51.100.7,
			     192.0.2.9 }
	}
	chain input {
		type filter hook input priority -10; policy accept;
		iifname "lo" accept
		ip saddr @securemyserver_block counter packets 0 bytes 0 drop
	}
}
`))
	if s.drop4 || s.drop6 || s.rules != 0 {
		t.Fatalf("the agent's own table is not a firewall: %+v", s)
	}
}

func TestParseNftDockerChains(t *testing.T) {
	s := parseNft([]byte(`table ip nat {
	chain DOCKER {
		iifname "docker0" counter packets 0 bytes 0 return
		iifname != "docker0" meta l4proto tcp tcp dport 6379 counter packets 0 bytes 0 dnat to 172.17.0.2:6379
		ip daddr 127.0.0.1 iifname != "docker0" tcp dport 8080 counter packets 0 bytes 0 dnat to 172.17.0.3:80
	}
}
table ip6 nat {
	chain DOCKER {
		iifname != "docker0" meta l4proto tcp tcp dport 6379 counter packets 0 bytes 0 dnat to [fd00::2]:6379
	}
}
table ip filter {
	chain DOCKER-USER {
		counter packets 5 bytes 300 return
	}
}
`))
	want := []DockerPort{{Addr: "0.0.0.0", Port: 6379, Proto: "tcp"}, {Addr: "127.0.0.1", Port: 8080, Proto: "tcp"}, {Addr: "::", Port: 6379, Proto: "tcp"}}
	if !reflect.DeepEqual(s.dockerPorts, want) {
		t.Fatalf("got %+v", s.dockerPorts)
	}
	if s.dockerUserRules != 0 {
		t.Fatalf("a plain return is not a user rule: %d", s.dockerUserRules)
	}
	s = parseNft([]byte("table ip filter {\n\tchain DOCKER-USER {\n\t\tiifname \"eth0\" tcp dport 6379 drop\n\t\treturn\n\t}\n}\n"))
	if s.dockerUserRules != 1 {
		t.Fatalf("user rules %d", s.dockerUserRules)
	}
}

func TestParseIptablesInput(t *testing.T) {
	if !parseIptablesInput([]byte("-P INPUT DROP\n-P FORWARD DROP\n-A INPUT -i lo -j ACCEPT\n")) {
		t.Fatal("ufw with IPV6=no drops IPv6 by policy")
	}
	if parseIptablesInput([]byte("-P INPUT ACCEPT\n-A INPUT -i lo -j ACCEPT\n-A INPUT -j ufw6-before-input\n")) {
		t.Fatal("ACCEPT policy without a drop rule is open")
	}
	if !parseIptablesInput([]byte("-P INPUT ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -j REJECT --reject-with icmp6-port-unreachable\n")) {
		t.Fatal("a final REJECT rule filters")
	}
}

func TestParseUFWDefaultAndIPv6(t *testing.T) {
	if v := parseUFWDefaultIPv6([]byte("# comment\nIPV6=no\nDEFAULT_INPUT_POLICY=\"DROP\"\n")); v != "no" {
		t.Fatal(v)
	}
	if v := parseUFWDefaultIPv6([]byte("IPV6=\"yes\"\n")); v != "yes" {
		t.Fatal(v)
	}
	if v := parseUFWDefaultIPv6([]byte("")); v != "unknown" {
		t.Fatal(v)
	}
	inet6 := `00000000000000000000000000000001 01 80 10 80       lo
20010db8000000000000000000000010 02 40 00 80     eth0
fd000000000000000000000000000001 02 40 00 80     eth0
fe800000000000000042acfffe110002 02 40 20 80     eth0
`
	if n := countGlobalIPv6([]byte(inet6)); n != 1 {
		t.Fatalf("global v6 %d", n)
	}
}

func TestParseDockerPs(t *testing.T) {
	out := "redis\t0.0.0.0:6379->6379/tcp, [::]:6379->6379/tcp\nweb\t127.0.0.1:8080->80/tcp\nworker\t5000/tcp\nold\t:::5432->5432/tcp\nrange\t0.0.0.0:8000-8001->8000-8001/udp\n"
	got := parseDockerPs([]byte(out))
	want := []DockerPort{
		{Addr: "0.0.0.0", Port: 6379, Proto: "tcp", Container: "redis"},
		{Addr: "::", Port: 6379, Proto: "tcp", Container: "redis"},
		{Addr: "127.0.0.1", Port: 8080, Proto: "tcp", Container: "web"},
		{Addr: "::", Port: 5432, Proto: "tcp", Container: "old"},
		{Addr: "0.0.0.0", Port: 8000, Proto: "udp", Container: "range"},
		{Addr: "0.0.0.0", Port: 8001, Proto: "udp", Container: "range"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
	if p := parseDockerPs([]byte("evil\x1b[31m\t0.0.0.0:1->1/tcp\n")); p[0].Container != "evil [31m" {
		t.Fatalf("control characters are cleaned: %q", p[0].Container)
	}
}

func TestParseIptablesDocker(t *testing.T) {
	out := `-N DOCKER
-A DOCKER -i docker0 -j RETURN
-A DOCKER ! -i docker0 -p tcp -m tcp --dport 6379 -j DNAT --to-destination 172.17.0.2:6379
-A DOCKER -d 127.0.0.1/32 ! -i docker0 -p tcp -m tcp --dport 8080 -j DNAT --to-destination 172.17.0.3:80
`
	got := parseIptablesDocker([]byte(out), false)
	want := []DockerPort{{Addr: "0.0.0.0", Port: 6379, Proto: "tcp"}, {Addr: "127.0.0.1", Port: 8080, Proto: "tcp"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
	if n := countIptablesUserRules([]byte("-N DOCKER-USER\n-A DOCKER-USER -j RETURN\n")); n != 0 {
		t.Fatal(n)
	}
	if n := countIptablesUserRules([]byte("-N DOCKER-USER\n-A DOCKER-USER -i eth0 -p tcp -m conntrack --ctorigdstport 6379 -j DROP\n-A DOCKER-USER -j RETURN\n")); n != 1 {
		t.Fatal(n)
	}
}

func TestClassifyTool(t *testing.T) {
	cases := []struct {
		comm         string
		args, parent []string
		want         string
	}{
		{"redis-server", []string{"/usr/bin/redis-server *:6379"}, nil, "redis"},
		{"postgres", []string{"/usr/lib/postgresql/16/bin/postgres", "-D", "/var/lib/postgresql/16/main"}, nil, "postgres"},
		{"mariadbd", nil, nil, "mysql"},
		{"java", []string{"/usr/share/elasticsearch/jdk/bin/java", "-Xms1g", "org.elasticsearch.bootstrap.Elasticsearch"}, nil, "elasticsearch"},
		{"clickhouse-serv", nil, nil, "clickhouse"},
		{"jupyter-lab", nil, nil, "jupyter"},
		{"python3", []string{"/usr/bin/python3", "/usr/local/bin/jupyter-lab", "--ip=0.0.0.0"}, nil, "jupyter"},
		{"python3", []string{"/usr/bin/python3", "-m", "jupyter", "notebook"}, nil, "jupyter"},
		{"node", []string{"/usr/lib/code-server/lib/node", "/usr/lib/code-server"}, nil, "code-server"},
		{"node", []string{"node", "/app/node_modules/.bin/vite", "--host"}, nil, "vite"},
		{"ollama", []string{"/usr/local/bin/ollama", "serve"}, nil, "ollama"},
		{"python3", []string{"python3", "/opt/ComfyUI/main.py", "--listen"}, nil, "comfyui"},
		{"open-webui", []string{"/usr/bin/python3", "/usr/local/bin/open-webui", "serve"}, nil, "open-webui"},
		{"node", []string{"node", "/usr/lib/node_modules/openclaw/openclaw.mjs", "gateway"}, nil, "openclaw"},
		{"next-server (v1", []string{"next-server (v16.4.5)"}, []string{"node", "/app/node_modules/.bin/next", "dev", "-H", "0.0.0.0"}, "next-dev"},
		{"next-server (v1", []string{"next-server (v16.4.5)"}, []string{"node", "/app/node_modules/.bin/next", "start"}, ""},
		{"node", []string{"node", "server.js"}, nil, ""},
		{"nginx", nil, nil, ""},
	}
	for _, c := range cases {
		if got := classifyTool(c.comm, c.args, c.parent); got != c.want {
			t.Errorf("%s %v: got %q, want %q", c.comm, c.args, got, c.want)
		}
	}
}

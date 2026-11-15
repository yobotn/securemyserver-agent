package main

// Report is the JSON body POSTed to /v1/report. Keep it in sync with src/lib/report/validate.ts.
type Report struct {
	Version       int                   `json:"version"`
	AgentVersion  string                `json:"agent_version"`
	Hostname      string                `json:"hostname"`
	MachineIDHash string                `json:"machine_id_hash,omitempty"` // sha256 of a platform prefix plus /etc/machine-id, never the raw id (D-066)
	CollectedAt   string                `json:"collected_at"`              // RFC 3339
	OS            OSInfo                `json:"os"`
	Updates       Updates               `json:"updates"`
	SSH           SSHInfo               `json:"ssh"`
	Ports         []Port                `json:"ports"`
	Firewall      Firewall              `json:"firewall"`
	Users         []User                `json:"users"`
	AuthEvents    []AuthEvent           `json:"auth_events"`
	AuthSource    string                `json:"auth_source"`        // journal | /var/log/auth.log | /var/log/secure | none
	AuthVerified  bool                  `json:"auth_verified"`      // true only for the journal, where _UID and _COMM prove root's sshd wrote each line
	AuthRejected  int                   `json:"auth_rejected"`      // journal lines that looked like sshd logins but sshd did not write (e.g. logger -t sshd)
	SSHKeys       *SSHKeys              `json:"ssh_keys,omitempty"` // nil when /etc/passwd could not be read
	Gate          *Gate                 `json:"gate,omitempty"`
	Switches      *Switches             `json:"switches,omitempty"`  // signed switches: what is allowed and what happened
	Blocklist     *BlocklistInfo        `json:"blocklist,omitempty"` // the signed blocklist in nftables
	Docker        *Docker               `json:"docker,omitempty"`    // whether Docker runs and the host ports it publishes
	AISessions    []AISessionCheckpoint `json:"ai_sessions"`         // checkpoints before AI sessions' first sudo, and their diffs (session.go)
	Errors        []string              `json:"errors"`
}

// Switches is the state of the signed safe switches on this server (D-014).
type Switches struct {
	Enabled    bool            `json:"enabled"`
	Off        string          `json:"off,omitempty"` // why switches cannot run, e.g. no owner_key in agent.conf
	Allowed    []string        `json:"allowed"`       // switches root allowed with `securemyserver allow`
	OwnerKeys  []string        `json:"owner_keys"`    // credential ids of the pinned passkeys (ids only)
	Seen       []string        `json:"seen"`          // policy nonces this agent used in the last 24 hours
	Ops        []SwitchOp      `json:"ops"`
	Refused    []Refusal       `json:"refused"`
	Checkpoint *CheckpointInfo `json:"checkpoint,omitempty"` // the checkpoint waiting for a confirm, if any
}

type SwitchOp struct {
	Nonce      string `json:"nonce"`
	Switch     string `json:"switch"`
	State      string `json:"state"` // applied | confirmed | rolled_back | refused
	Reason     string `json:"reason"`
	At         string `json:"at"` // last change, RFC 3339
	AppliedAt  string `json:"applied_at,omitempty"`
	Deadline   string `json:"deadline,omitempty"`
	Checkpoint string `json:"checkpoint,omitempty"`
	NeedsLogin bool   `json:"needs_login"`
	// Proof is what kept a confirmed switch (D-090): login (a new SSH key login the journal attests), owner (your
	// signed "It works, keep it"), server (root ran securemyserver confirm) or verified (it needs no login).
	Proof string       `json:"proof,omitempty"`
	Batch int          `json:"batch,omitempty"` // how many switches the passkey tap covered, when more than one
	Steps []SwitchStep `json:"steps"`
}

type SwitchStep struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

type Refusal struct {
	Nonce  string `json:"nonce,omitempty"`
	Reason string `json:"reason"`
	At     string `json:"at"`
}

type CheckpointInfo struct {
	ID       string   `json:"id"`
	Deadline string   `json:"deadline"`
	Targets  []string `json:"targets"`
	Reason   string   `json:"reason"`
}

type OSInfo struct {
	ID         string `json:"id"`
	VersionID  string `json:"version_id"`
	PrettyName string `json:"pretty_name"`
	Kernel     string `json:"kernel"`
	Arch       string `json:"arch"`
}

type Updates struct {
	Source           string   `json:"source"` // apt-get | none
	Pending          int      `json:"pending"`
	Security         int      `json:"security"`
	SecurityPackages []string `json:"security_packages"`
	RebootRequired   bool     `json:"reboot_required"`
	RebootPackages   []string `json:"reboot_packages"`
	Unattended       string   `json:"unattended"` // unattended-upgrades: on | off | absent | unknown
}

type SSHInfo struct {
	Version      string            `json:"version"`
	Effective    map[string]string `json:"effective"` // sshd -T, keys lower case
	ConfigSHA256 string            `json:"config_sha256"`
}

type Port struct {
	Proto   string `json:"proto"` // tcp | tcp6
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	Process string `json:"process,omitempty"`
	PID     int    `json:"pid,omitempty"`
	Tool    string `json:"tool,omitempty"` // a database or dev/AI tool from a fixed list (tools.go), named from the process name and command line read on the server; the command line itself is never sent
}

type Firewall struct {
	Active    bool   `json:"active"`
	UFW       string `json:"ufw"`      // active | inactive | absent | unknown
	Nftables  string `json:"nftables"` // present | empty | absent | unknown
	NftRules  int    `json:"nft_rules"`
	NftDropIn bool   `json:"nft_input_drop"`
	// IPv4Filtered and IPv6Filtered: incoming traffic of that family is filtered (ufw active, for IPv6 only with
	// IPV6=yes; or an nftables input chain that drops). The agent's own blocklist table does not count.
	IPv4Filtered bool   `json:"ipv4_filtered"`
	IPv6Filtered bool   `json:"ipv6_filtered"`
	UFWIPv6      string `json:"ufw_ipv6,omitempty"` // IPV6= in /etc/default/ufw: yes | no | unknown; empty without ufw
	NftDropIn6   bool   `json:"nft_input_drop6"`    // an nftables input chain for IPv6 (ip6 or inet table) drops
	IPv6Global   int    `json:"ipv6_global"`        // global IPv6 addresses on this server (a count, never the addresses)
}

// Docker is whether Docker runs and which host ports it publishes. Published ports skip ufw's INPUT rules.
type Docker struct {
	Running   bool         `json:"running"`    // a dockerd process runs
	Source    string       `json:"source"`     // where published ports were read: docker ps | nft | iptables | none
	Published []DockerPort `json:"published"`  // at most 200
	UserRules int          `json:"user_rules"` // rules in the DOCKER-USER chain besides Docker's own return
}

type DockerPort struct {
	Addr      string `json:"addr"` // host address: 0.0.0.0 or :: for every interface, or one address
	Port      int    `json:"port"`
	Proto     string `json:"proto"`
	Container string `json:"container,omitempty"` // container name (from docker ps), cleaned, 64 bytes at most
}

type User struct {
	Name           string `json:"name"`
	UID            int    `json:"uid"`
	Shell          string `json:"shell"`
	Home           string `json:"home"`
	Sudo           bool   `json:"sudo"`
	AuthorizedKeys int    `json:"authorized_keys"`
}

type AuthEvent struct {
	ID          string `json:"id"` // sha256(ts|line)[:32], for server-side dedupe
	TS          string `json:"ts"` // RFC 3339
	IP          string `json:"ip"`
	User        string `json:"user"`
	Result      string `json:"result"` // ok | failed
	Method      string `json:"method"` // publickey | password | keyboard-interactive | none
	InvalidUser bool   `json:"invalid_user"`
	KeyFP       string `json:"key_fp,omitempty"`
}

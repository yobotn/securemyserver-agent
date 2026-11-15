# securemyserver

The SecureMyServer binary. One static Linux binary, `securemyserver`. `securemyserver agent` reads the
state of your server and POSTs a JSON report to `https://ingest.securemyserver.com/v1/report` every 5 minutes.

## Read-only, except switches you sign

- `securemyserver agent` reads files and runs read-only commands. On its own it does not edit config, install
  packages, touch the firewall, add users or restart services.
- The one exception is the six **signed safe switches** below. Each runs only with two keys: root allowed it on this
  server (`securemyserver allow`), and you signed it with your passkey in the dashboard. The agent checks that
  signature itself. Each switch saves a checkpoint first and undoes itself unless a new login proves it works.
- And "Undo this session" for an AI session (below), only after `sudo securemyserver allow session-undo` and a
  passkey-signed request: it restores the checkpoint saved before the AI's first sudo.
- And, only after `sudo securemyserver allow blocklist`, the **signed blocklist** (below): a list of addresses to
  drop, signed by the platform, kept in the agent's own nftables table `inet securemyserver`. It can only drop
  inbound packets from listed sources; it never touches your allowlist, anyone who ever signed in here, or an open
  SSH session.
- It never listens on a port. It only makes outgoing HTTPS requests. (Our honeypot sensors listen, but they are a
  separate program that runs only on VPSs we own, never on your server: see "Honeypot sensors" at the end.)
- It never runs commands it receives. The only part of the platform's reply it reads is `envelopes` (signed
  switch requests), and it verifies each one before anything happens. The blocklist is data, verified the same way
  before it is used. Data flows up (D-005).
- Every request it makes is signed with this server's own key (below), so the token alone can't report in its name.
- Commands run by absolute path from `/usr/sbin`, `/usr/bin`, `/sbin`, `/bin`, with fixed arguments,
  a clean environment and a timeout. No shell, and no input from the network. A switch name maps to fixed Go code;
  nothing from a policy reaches a command.
- It runs as root so it can read `sshd -T`, `/etc/ssh`, `/var/log/auth.log`, other users'
  `authorized_keys` and the securemyserver-gate log, and so the switches can write their config. For keys it sends
  the fingerprint, type, size, options and a cleaned comment, never the key itself. It never sends private keys,
  file contents or shell history; the one exception to file contents is the diff of config files your AI changed in
  a session (below), with secret files left out and secret-looking values redacted on the server. It reads a listening program's command line only to name it from a fixed list of databases and
  dev tools (`tools.go`), and never sends it.

## Signed safe switches (the write path)

| Switch | What it does | Refused when |
|---|---|---|
| `ssh.password_auth_off` | `PasswordAuthentication no` (and `KbdInteractiveAuthentication no` when `UsePAM yes`, since PAM still takes passwords that way) | already off; `PubkeyAuthentication` is not `yes`; nobody logged in with a key in the last 7 days |
| `ssh.root_login_off` | `PermitRootLogin no`, or `prohibit-password` when root is the only user with a key | already that strict; no sudo user and no root with a key |
| `ssh.max_auth_tries_3` | `MaxAuthTries 3` | already 3 or less |
| `updates.security_now` | `unattended-upgrade` (security origins only), else `apt-get install --only-upgrade` of the packages apt lists from a `-security` pocket, with `--force-confold`. Never reboots | no security updates; not apt; `sshd -t` fails before |
| `updates.unattended_on` | writes `/etc/apt/apt.conf.d/52securemyserver-auto-upgrades` (`APT::Periodic::Unattended-Upgrade "1"`) | unattended-upgrades is not installed (a switch never installs software) |
| `firewall.on_keep_ssh` | `ufw allow` every SSH port from `sshd -T` first (and 80/443 if they listen), then `default deny incoming`, `ufw enable` | ufw is not installed; already active; other ports listen on every interface (choose those with Fix with AI) |

There is no "off" switch. Passwords back on, root login back on and firewall off are only done on the server.
SSH settings go into `/etc/ssh/sshd_config.d/00-securemyserver.conf` (read first, so it wins); a switch is refused
when `sshd_config` does not `Include /etc/ssh/sshd_config.d/*.conf`.

**How one runs.** The dashboard builds a policy
`{v:1, type:"switch", server_id, switch, nonce (16 random bytes), issued_at, expires_at (at most 10 minutes later)}`,
encodes it as canonical JSON (sorted keys, no whitespace, a small safe alphabet so nothing needs escaping) and asks
your passkey for an assertion over `sha256(policy)` with user verification required. The platform stores
`{policy, credential_id, authenticator_data, client_data_json, signature}` and hands it to the agent in the reply
to its next report (why the reply and not a separate `GET /v1/policy`: one request per cycle, the same bearer
token, no new endpoint; the agent trusts nothing in the reply anyway). The agent then checks, itself:

1. the signing credential is one of the passkeys pinned on this server;
2. `clientDataJSON` has `type` `webauthn.get`, `challenge` = base64url(sha256(policy)), `origin` = the configured
   origin, and is not cross-origin;
3. `rpIdHash` = sha256(rp id);
4. the user-present and user-verified flags are set;
5. the signature over `authenticatorData || sha256(clientDataJSON)` (ES256 P-256, EdDSA Ed25519 or RS256 2048+);
6. the policy names this server, has not expired, its nonce was never used (kept in
   `/var/lib/securemyserver/switches.json`), and the passkey's sign counter went up when it counts;
7. the switch is allowed on this server (`/etc/securemyserver/allow.d/<switch>`, root-owned, not group or world
   writable, or nothing counts as allowed);
8. no other signed change ran in the last 10 minutes (a batch counts as one), and no checkpoint is waiting.

Then: pre-checks (table above), a checkpoint with a 10-minute deadline, the change, `sshd -t` (or the ufw/apt
check), a reload that keeps open sessions (`systemctl reload ssh`, else SIGHUP to `/run/sshd.pid`), and a verify:
the live value from `sshd -T` and an SSH banner on the SSH port. If any step fails, the checkpoint goes back at
once. SSH and firewall switches then wait: a **new** successful public key login after the change confirms it on
its own, but only when the systemd journal attests it (root's sshd wrote the line, D-069). A confirm you sign in the
dashboard ("It works, keep it") is the optional early confirm, and `sudo securemyserver confirm` from a new SSH
session works too. With none of them before the deadline, it rolls back. On a server without a journal a login
read from auth.log never confirms (any local user can write such a line), so there it is your confirm or the
rollback. The update switches are confirmed as soon as they verify (installed packages are not rolled back; the
checkpoint covers the SSH config). Each step's result (applied, confirmed, rolled back, refused, with the reason)
goes into the next report, with `proof` on a confirmed one: `login`, `owner` (your passkey confirm), `server`
(`securemyserver confirm`) or `verified` (needs no login). A change sends a report at once.

**Several switches, one passkey tap (D-090).** "Turn on N recommended fixes" signs one policy
`{v:1, type:"switches", server_id, switches:[...], nonce, issued_at, expires_at}`: 2 to 6 known switches, sorted
and each once, so the canonical form stays unique. The agent verifies it exactly like a single switch, then runs
the switches one by one in its own order (the update switches first, so an apt run can't eat the login window,
then SSH, then the firewall). Each one still needs its own allow file, runs its own pre-checks, saves its own
checkpoint, and is changed and verified on its own; a switch that is refused or fails puts back only its own
checkpoint and is reported with its reason, while the others carry on. The report has one op per switch under the
policy's nonce (`batch` says how many). The checkpoints of the switches that wait for a login stack in order
(`batch` and `seq` in the manifest) and share the first one's deadline: one new login, or your confirm for any of
them, keeps them all, and at the deadline they all go back, newest first. Restoring one by hand restores those
saved after it first, so nothing is put back out of order.

**Pinned keys.** Add server writes your account's passkey public keys into `agent.conf` as
`owner_key = <credential id> <SubjectPublicKeyInfo DER, base64>` (the body of a PEM). Later changes ("Update keys on
my servers" on the Account page) are a `type:"keys"` policy signed by a passkey the server already pins, verified
the same way, so a compromised platform can't add its own key. Editing the `owner_key` lines in `agent.conf` as root
always wins over a signed update. New passkeys are created as ES256, EdDSA or RS256 only, so the agent can check
them with Go's standard library.

**Limits, honestly.**
- `sshd -T` shows the global settings. A `Match` block can still allow passwords for some users.
- A new key login read from `/var/log/auth.log` can be forged by a local user with `logger`, so since 0.9.0 it
  never confirms a switch. Only the journal source (which can't be forged that way) confirms on its own.
- The banner check connects from the server itself; it proves sshd answers, not that your network path is open.
  The new-login confirm is what proves that.
- `updates.security_now` runs apt as its own `systemd-run` unit (outside the agent's sandbox, the way
  `apt-daily-upgrade.service` does), up to 45 minutes. Packages are not downgraded on rollback.
- The firewall switch handles ufw only. Docker-published ports skip ufw rules; the `docker.port.<n>` item flags them
  (below).

## The undo net: checkpoint, confirm, undo

Fix prompts (on agents 0.2.0 and later) and every switch use the same CLI. All of it is root only.

```sh
C=$(sudo securemyserver checkpoint --minutes 15 ssh)   # saves, prints the folder; restores itself at the deadline
# ... change things, test a NEW login ...
ssh -t my-server sudo securemyserver confirm          # from the NEW session: keep the change
sudo securemyserver undo                              # or put it back now
sudo securemyserver status                            # service, last report, checkpoints, allowed switches
```

- Targets: `ssh` (`/etc/ssh/sshd_config` and `sshd_config.d/`), `ufw` (`/etc/ufw/`, `/etc/default/ufw`, and whether
  ufw was active), `nft` (the live ruleset, restored atomically with `nft -f`), `apt` (`/etc/apt/apt.conf.d/`).
- A checkpoint is `/var/lib/securemyserver/checkpoints/<id>/` (0700): `manifest.json` with every file's path, mode,
  owner and sha256, and `files/` mirroring the real paths, so a by-hand restore is a `cp -a` away.
- Only one checkpoint waits at a time, except the stacked checkpoints of one switch batch (above). The deadline (default 5 minutes, 1 to 60) is enforced twice: by the agent
  loop (every 30 seconds) and by a `systemd-run --on-active=` transient timer that runs
  `securemyserver undo --if-pending <id>`. **Without systemd** (some containers) only a running agent restores it at
  the deadline; `checkpoint` says so.
- `confirm` refuses to run from the session that made the checkpoint (same kernel audit session id), because a new
  login is the proof. `--allow-same-session` overrides it.
- `undo` checks every saved copy against its sha256, makes the targets match the checkpoint exactly (files added
  since are removed), runs `sshd -t`, and only then reloads ssh or ufw. If the saved config itself fails `sshd -t`,
  it puts back what was there, changes nothing, and says so loudly (`restore_failed`).
- `allow <switch>...`, `disallow <switch>...`, `allowed`: the server-side key for switches (`/etc/securemyserver/allow.d/`,
  0700). `allow --all-safe` allows every safe switch this agent version knows in one go (the install prompt offers
  it): it means "accept each of these when my passkey signs it", so every switch still needs its own signed policy
  before it does anything. It never includes `blocklist` or `session-undo`, which stay their own consent
  (`allow --all-safe blocklist` does both). A switch added in a later agent version needs its own allow, or
  `--all-safe` again. `disallow --all-safe` takes them all back.

## The signed blocklist (D-013, D-041, D-042)

Off until root runs `sudo securemyserver allow blocklist`. Then, after each report, the agent pulls
`GET /v1/blocklist` (same host as the endpoint; `blocklist_endpoint` overrides it), with `If-None-Match: "<version>"`
so an unchanged list is a 304. The list is this server's own: the platform's active bans (single addresses and /24
rollups) minus your allowlist, minus Cloudflare's published ranges, minus every address that ever signed in
successfully on this server, newest first, at most 50,000 entries, plus those allow entries.

It is data, not a command, so the platform signs it with its own Ed25519 key, not your passkey. The agent checks,
itself, before anything changes:

1. the signature over `securemyserver-blocklist-v1\n` + the exact payload, against a `blocklist_key` in agent.conf
   (Add server writes it; up to 4 lines, for a key change);
2. the payload: this server's `server_id`, a version not older than the one applied, not expired (a list lives 24
   hours), no unknown fields, at most 50,000 block and 20,000 allow entries, canonical prefixes no wider than /16
   (IPv4) or /32 (IPv6), and at most 2^24 IPv4 addresses in all, or the whole list is refused and the applied one
   stays;
3. what it never blocks, whatever the list says: private, loopback, link-local and CGNAT ranges, anything that
   overlaps an allow entry, and the peer of every open connection to sshd (`/proc/net/tcp`, `/proc/net/tcp6`).

Then it writes `/var/lib/securemyserver/blocklist.nft` from parsed prefixes only (nothing from the network is
interpolated), checks it with `nft -c -f`, and loads it with `nft -f`, which replaces the table in one transaction:

```
table inet securemyserver {
	set securemyserver_allow  { type ipv4_addr; flags interval; auto-merge; }
	set securemyserver_allow6 { type ipv6_addr; flags interval; auto-merge; }
	set securemyserver_block  { type ipv4_addr; flags interval; auto-merge; }
	set securemyserver_block6 { type ipv6_addr; flags interval; auto-merge; }
	chain input {
		type filter hook input priority -10; policy accept;
		iifname "lo" accept
		ct state established,related accept
		ip saddr @securemyserver_allow accept
		ip6 saddr @securemyserver_allow6 accept
		ip saddr @securemyserver_block counter drop
		ip6 saddr @securemyserver_block6 counter drop
	}
}
```

- Its own table, before other filters (priority -10): it never edits ufw or your rules, and `accept` here only means
  "not dropped by us"; your own rules still apply after it.
- Established connections are accepted first, so an open session is never cut.
- No nftables: the report says `not applied: nftables not installed`, and nothing is done.
- If no newer list arrives before the applied one expires (the platform is down), the block sets are emptied.
- If the table disappears (a reboot, `nft flush ruleset`), the next pull applies the list again.
- `sudo securemyserver disallow blocklist` removes the table at once.
- `nft list set inet securemyserver securemyserver_block` shows what is blocked; the dashboard shows "Blocklist on
  this server: N entries, version X, applied 3 min ago" from the `blocklist` report field.

## Signed reports (D-043)

On its first run the agent makes an Ed25519 key, `/var/lib/securemyserver/report_key` (a base64 seed, 0600, root
only), and signs every request:

```
X-SMS-Timestamp: <unix seconds>
X-SMS-Key:       <raw public key, base64>
X-SMS-Signature: <Ed25519, base64> over "securemyserver-request-v1\n<ts>\n<METHOD> <path>\n" + body
```

The platform registers the key with the first signed report, under the enrollment token (trust on first use), and
shows its fingerprint on the server page. From then on it refuses unsigned or wrongly signed requests, timestamps
more than 5 minutes off, and timestamps older than the last one. So a leaked token alone can't report in this
server's name. Keep the clock right (`timedatectl`).

`sudo securemyserver rotate-key` makes a new key and a statement signed by the old one, sent with every later request
as `X-SMS-Key-Rotation: v1 <old> <new> <unix seconds> <signature by the old key>`; the next report switches the
platform over. Reinstalled the server (new key, old one lost)? Use **Forget report key** on the server page; the
next signed report registers the new key.

## What it reads

| What | From |
|---|---|
| OS and kernel | `/etc/os-release`, `/proc/sys/kernel/osrelease`, `/proc/sys/kernel/arch` |
| A one-way machine hash (`machine_id_hash`, agent 0.7.0): `sha256("securemyserver-machine-v1:" + machine-id)` in hex, never the id itself. The platform uses it, with the public address it sees the report come from, only for the one-free-slot-per-server rule (D-066). Left out when the file is missing, empty or `uninitialized` | `/etc/machine-id`, else `/var/lib/dbus/machine-id` |
| Pending and security updates | `apt-get -s upgrade` (a simulation; changes nothing) |
| Reboot required | `/var/run/reboot-required`, `/var/run/reboot-required.pkgs` |
| Effective SSH settings | `sshd -T`, version from `sshd -V` |
| SSH config drift | sha256 of `/etc/ssh/sshd_config` plus `/etc/ssh/sshd_config.d/*.conf` |
| Listening TCP ports and their process | `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/<pid>/fd`, `/proc/<pid>/comm` |
| Which known database or dev/AI tool a listener is (`ports[].tool`, an id from a fixed list; the command line is read here and never sent) | `/proc/<pid>/comm`, `/proc/<pid>/cmdline`, and for `next-server` the parent's (`/proc/<pid>/stat`) |
| Firewall state | `ufw status`, `nft list ruleset` (listing only) |
| IPv6 filtering: ufw's IPV6= setting, the IPv4 and IPv6 INPUT policy, the number of global IPv6 addresses (never the addresses) | `/etc/default/ufw`, `nft list ruleset`, `iptables -S INPUT`, `ip6tables -S INPUT`, `/proc/net/if_inet6` |
| Docker: whether it runs, the host ports it publishes, how many DOCKER-USER rules there are | `/proc/<pid>/comm` (dockerd); `docker ps --format '{{.Names}}\t{{.Ports}}'` when the docker CLI is installed, else the DOCKER chain in `nft list ruleset`, else `iptables -t nat -S DOCKER` and `ip6tables -t nat -S DOCKER`; `iptables -S DOCKER-USER` |
| Users with a login shell, sudo members | `/etc/passwd`, `/etc/group` (sudo, wheel, admin) |
| Number of `authorized_keys` lines per user | `~/.ssh/authorized_keys`, `~/.ssh/authorized_keys2` |
| Keys per user (login shell users and root): type, bits, SHA256 fingerprint, comment (control characters removed, 128 bytes max), options (`restrict`, `from=`, `expiry-time=`, `command=`, `verify-required`, `no-touch-required`, other option names without values) | the `AuthorizedKeysFile` paths from `sshd -T` (default `.ssh/authorized_keys .ssh/authorized_keys2`) |
| Key last used, per user and fingerprint | `Accepted publickey for <user> from <ip> port N ssh2: <TYPE> SHA256:<fp>` lines; 90 days back on the first report after start (`journalctl -o json`, trusted fields checked; or the auth log and its rotated copies, marked unverified), then from each report's events |
| AI session checkpoints and the diff of what changed (`ai_sessions`, agent 0.5.0) | `/var/lib/securemyserver/checkpoints/*/` and, for the diff, the current files under the checkpoint's targets (below) |
| securemyserver-gate commands and log health (`gate.source`, `gate.forged`, `gate.suppressed`, agent 0.8.0) | `journalctl -o json SYSLOG_IDENTIFIER=securemyserver-gate` and journald's "Suppressed" notices, or without journald `/var/log/securemyserver/gate.log` (read only); `/usr/lib/securemyserver/securemyserver-gate`, `/etc/passwd`, `/etc/group` |
| SSH logins (Accepted, Failed, Invalid user), `auth_verified`, `auth_rejected` (agent 0.8.0) | `journalctl -o json` for sshd's identifiers and units, keeping only `_UID=0` sshd lines; or `/var/log/auth.log` / `/var/log/secure` plus the previous rotated file |
| The blocklist it applied (version, counts, errors; only with `allow blocklist`) | `/var/lib/securemyserver/blocklist.json`, `nft list tables`; peers of open SSH connections from `/proc/net/tcp`, `/proc/net/tcp6` (used locally, never sent) |

Run `sudo securemyserver agent --once --dry-run` to print the exact report as JSON without sending it, and
`sudo securemyserver check` to send one now.

## Exposed databases, dev tools, Docker and IPv6 (D-045)

From these fields the dashboard raises four kinds of item, each with a Fix with AI prompt:

| Item | When | Severity |
|---|---|---|
| `db.port.<n>` | A database listens on anything but loopback | critical on every interface or a public address, should_do on a private one |
| `tool.port.<n>` | A dev or AI tool listens on every interface or a public address | critical when it has no login by default, else should_do |
| `docker.port.<n>` | Docker runs, the firewall filters IPv4, DOCKER-USER is empty, and a container publishes a port on 0.0.0.0, :: or a public address | critical for a database or no-login tool port, else should_do |
| `firewall.ipv6` | The server has a global IPv6 address, IPv4 is filtered and IPv6 is not | critical |

The known programs (src/lib/report/exposure.ts, ids in `tools.go`):

| Id | Program | Usual ports | Login by default |
|---|---|---|---|
| `postgres` | PostgreSQL | 5432 | yes |
| `mysql` | MySQL, MariaDB | 3306 | yes |
| `redis` | Redis | 6379 | no |
| `mongodb` | MongoDB | 27017 | no |
| `elasticsearch` | Elasticsearch | 9200, 9300 | yes (8.x) |
| `memcached` | Memcached | 11211 | no |
| `clickhouse` | ClickHouse | 8123, 9000 | no (empty default password) |
| `openclaw` | OpenClaw gateway | 18789 | treated as no: it runs commands for whoever controls it |
| `jupyter` | Jupyter | 8888 | yes (token) |
| `code-server` | code-server | 8080 | yes (password) |
| `vite` | Vite dev server | 5173 | no |
| `next-dev` | `next dev` | 3000 | no |
| `ollama` | Ollama | 11434 | no |
| `open-webui` | Open WebUI | 8080 | yes (the first sign-up becomes admin) |
| `comfyui` | ComfyUI | 8188 | no |

- A listener is named by `ports[].tool`, else by its process name, else by its usual port, but only when the process
  is unknown or `docker-proxy` and the port is not one that ordinary apps share (3000, 8080 and 9000 never match on
  the port alone). `next start` is not flagged: only a server whose parent runs `next dev`.
- One item per port: a known database or tool replaces the plain "open port" item, and a Docker-published port
  replaces both.
- Docker is simulated in the systemd test container by a process named `dockerd` and Docker's `DOCKER` chain in
  nftables (no docker-in-docker); real hosts are read through `docker ps`.
- IPv6: ufw 0.36 with `IPV6=no` sets the ip6tables INPUT policy to DROP, which blocks IPv6 entirely rather than leaving
  a gap, so the agent judges the live policy (nftables, then `ip6tables -S INPUT`), not the setting. The gap is a
  policy left on ACCEPT, or IPv4-only nftables or iptables rules. The fix prompt sets `IPV6=yes`, reloads ufw, then adds
  the IPv6 copy of each allow rule (before the reload, `ufw allow` fails for IPv6 with "problem running").

The fingerprint is computed like `ssh-keygen -lf`: base64 of the sha256 of the decoded key blob, without
padding.

### Which login lines are trusted (agent 0.8.0, D-AGENT)

Login events and key last-used times prefer the systemd journal. The agent asks `journalctl -o json` for lines that
claim to be sshd's (`SYSLOG_IDENTIFIER` sshd, sshd-session or sshd-auth) or come from `ssh.service`/`sshd.service`,
and keeps only those whose **trusted fields** show root's sshd wrote them: `_UID=0` and `_COMM` sshd, sshd-session
or sshd-auth. journald sets underscore fields itself, from the socket credentials and `/proc`; a sender cannot set
them, so `logger -t sshd "Accepted publickey ..."` run by a user (`_UID` theirs, `_COMM=logger`) is refused and
counted in `auth_rejected`. The report says `auth_verified: true` and `ssh_keys.usage_verified: true` only for this
source. Only root can forge a trusted line, and root owns the server anyway.

Without a journal the agent reads `/var/log/auth.log` (or `/var/log/secure`). Per report it reads the current file,
plus the previous one (`.1`) when it was rotated after the last report. The 90-day key scan on start reads the
rotated copies too, newest first: `auth.log.1`, `auth.log.2.gz` … (logrotate numbering) or `secure-20261101[.gz]`
(dateext), up to 20 files and 96 MB together, gzip decompressed with a 256 MB cap per file, stopping at the first
file last written before the 90 days. Any user can write such a line with `logger`, so these reports carry
`auth_verified: false` and `usage_verified: false`. A forged line can make a key look used, or confirm (keep) a
switch that is already safer; it cannot unlock anything.

## securemyserver-gate (the AI's forced command)

`securemyserver-gate` is a second static binary, `/usr/lib/securemyserver/securemyserver-gate` (root:root, 0755). Neither the agent nor the
platform runs it: **sshd runs it** for every connection made with the `securemyserver-ai` key, because the key line
forces it:

```
restrict,from="<laptop IP or CIDR>",expiry-time="<+90 days>",command="/usr/lib/securemyserver/securemyserver-gate" ssh-ed25519 AAAA... securemyserver-ai
```

What it does, per connection:

1. Reads `SSH_ORIGINAL_COMMAND`. If it is empty (an interactive login), it refuses: no shells in tier 1.
2. Refuses commands over **5,000 characters**.
3. Appends a `start` line to the audit log: time, session id (sha256 of `SSH_CONNECTION` and the parent
   pid, so one SSH connection is one session), client IP, user, the command (control characters, C1
   controls and bidi overrides become visible escapes such as `\x1b`), and its length.
   **Fail closed:** if that line cannot be written and synced, the command does not run.
4. **Before a command that uses sudo** (the word `sudo` or `sudoedit` anywhere in it), asks for the session
   checkpoint: `sudo -n /usr/local/sbin/securemyserver checkpoint --session <session id> --auto` (below). **Fail
   closed:** if that fails (no sudoers rule, the binary missing, a full disk), the command does not run and a
   `refused` line with reason `no_checkpoint` is logged.
5. Runs the command with `/bin/sh -c` in its own process group, with stdin passed through.
6. **60 s timeout:** the whole process group gets SIGKILL and the exit code is 124.
7. **1 MB output cap** (stdout and stderr together): the rest is dropped and counted, and a note goes to stderr.
8. Appends an `end` line: exit code, duration, bytes produced, truncated and timed-out flags.

The agent reads the log as root and sends new commands in each report (a week back after a restart; the
platform dedupes by id). The dashboard shows them on the server's "AI sessions" page. If the log is
missing or securemyserver-ai cannot append to it, the agent reports that and the dashboard shows an **audit gap**. It
also counts securemyserver-ai logins that sshd logged but securemyserver-gate did not, which catches a bypassed or broken gate.

**Where the log lives (agent 0.8.0, D-AGENT): the systemd journal.** When `/run/systemd/journal/socket` exists,
securemyserver-gate sends each line to journald over its native protocol (a unix datagram, standard library only):
`MESSAGE` is the JSON line, with `SYSLOG_IDENTIFIER=securemyserver-gate`, `SECUREMYSERVER_GATE_EV` and
`SECUREMYSERVER_GATE_ID`. It never writes `gate.log` then. If the send fails, the command does not run (fail closed,
as before). After sending it waits (at most 2 s) until journald has taken the datagram off the socket (`SIOCOUTQ`
reads 0) plus 20 ms, because journald reads `_EXE` from `/proc/<pid>` when it processes the entry: a gate that
exited first, after a fast command, would leave it out. The agent reads
`journalctl -o json SYSLOG_IDENTIFIER=securemyserver-gate` and accepts an entry only when journald's own fields say
`_TRANSPORT=journal`, `_UID` = the securemyserver-ai uid and `_EXE=/usr/lib/securemyserver/securemyserver-gate`.
Every other entry with that identifier (`logger -t securemyserver-gate`, a native client the AI wrote, another user)
is left out and counted in `gate.forged`, which the AI sessions page shows. `gate.source` says `journal`.

Why this holds:

- securemyserver-ai cannot delete or rewrite journal entries: the journal files belong to root (and the
  `systemd-journal` group), and a user can at most read their own per-user file.
- It can add entries, but not with the trusted fields of the gate: `_UID` comes from the kernel (`SO_PASSCRED`) and
  `_EXE` from `/proc`, both filled by journald. Running the gate binary itself is allowed and harmless: the gate then
  logs, and runs, a real command; only `SSH_CONNECTION` (session id and client IP of that entry) is its own.
- The command text, ids and times inside `MESSAGE` are still checked field by field (`parseGateLog`).

Known limits, shown rather than hidden:

- journald reads `_EXE` from `/proc` when the entry arrives, not atomically with the send. A process that sends a
  forged entry and then `exec`s the gate binary before journald reads `/proc` could in theory pass as the gate.
  Such a forgery can only **add** entries; it can never remove or change the gate's real ones.
- journald's rate limit (default 10,000 messages per 30 s per unit) can drop messages when the AI floods the journal
  from its own session, including the gate's. The gate cannot see that. The agent adds up journald's own
  "Suppressed N messages from …" notices (`MESSAGE_ID=a596d6fe7bfa4994828e72309e95d61e`, `_TRANSPORT=driver`) for the
  securemyserver-ai user's slice or `ssh.service`, and reports them as `gate.suppressed`; the page warns that commands
  may be missing. The "logins without a logged command" count catches the rest.
- With `Storage=volatile` (or no `/var/log/journal`), entries live in `/run` and are lost on reboot; the agent sends
  them every 5 minutes, so at most the last few minutes before a crash can be lost.

**Servers without journald** keep the file below. `gate.source` is then `file`, and the append-only flag matters.

**Permissions (file only).** securemyserver-ai can append to the log, but cannot read, create, rename or replace it:

```sh
sudo install -d -o root -g root -m 755 /var/log/securemyserver      # securemyserver-ai cannot add or delete files here
sudo install -o root -g securemyserver-ai -m 620 /dev/null /var/log/securemyserver/gate.log   # group write, no read
sudo chattr +a /var/log/securemyserver/gate.log                   # optional: append-only, even for writers
```

securemyserver-gate opens the log with `O_APPEND|O_NOFOLLOW` and never creates it. Without `chattr +a`, securemyserver-ai could
truncate the file with its write permission. With it, only root can (log rotation then needs a
`prerotate` `chattr -a` and a `postrotate` `chattr +a`; `copytruncate` does not work). securemyserver-ai can still
append fake lines: the agent checks every field, counts lines that do not parse (shown on the page), and
the platform keeps the first command stored for each id. The securemyserver-ai home directory and `.ssh` are owned
by root, so the AI cannot edit its own key line; the Keys page flags it if it can.

**It is not a sandbox.** The command runs as securemyserver-ai with everything that user may do, and a process
that calls `setsid` leaves the process group the timeout kills. The real boundary is the user itself:
no password, no shell without a command, and sudo limited to the presets in `/etc/sudoers.d/securemyserver-ai`
(never `NOPASSWD: ALL`; check with `visudo -c -f` before installing). The Keys page has a ready prompt
that sets all of this up ("Give my AI its own key").

Ask mode (tier 2) is not built yet.

## The checkpoint before the AI's first sudo, the diff, and Undo (D-053)

The sudoers preset (Keys page, "Give my AI its own key") has one rule for this, and allows only this exact form:

```
Cmnd_Alias SECUREMYSERVER_AI_CHECKPOINT = /usr/local/sbin/securemyserver ^checkpoint --session [0-9a-f]{16} --auto$
securemyserver-ai ALL=(root) NOPASSWD: SECUREMYSERVER_AI_UPDATES, SECUREMYSERVER_AI_CHECKPOINT
```

(the regex form needs sudo 1.9.10 or later, like the rest of the preset; the binary also checks the arguments
exactly, since a sudoers wildcard would match more than one word).

- **An AI session** is the run of sudo commands with less than 15 minutes between them, across SSH connections. The
  first sudo command saves a checkpoint; later ones only record that the session is still going.
- **What it saves** (a fixed list, nothing from the AI): all of `/etc/ssh` (`sshdir`), `/etc/ufw` and
  `/etc/default/ufw` and whether ufw was active (`ufw`), the live nft ruleset where nft is installed (`nft`),
  `/etc/apt/apt.conf.d` (`apt`), `/etc/apt/sources.list` and `sources.list.d` (`apt-sources`), `/etc/sudoers.d`
  (`sudoers`) and `/etc/systemd/system` (`systemd`). Same folder format as other checkpoints (0700, root only).
- It has **no deadline** and never restores itself; it does not block switches or fix prompts.
- **The diff.** Each report carries the newest session checkpoints of the last 48 hours as `ai_sessions`, with a
  unified diff of the text files that changed (added, removed, changed, plus mode and owner changes and the ruleset).
  Live while the session is open, frozen when it ends. Never in it, whatever they contain: files whose name looks
  like a key, secret, token, password or shadow file (SSH host keys included), files holding a private key, binary
  files and files over 256 KB (listed with the reason, no content). On the lines that are sent, a value assigned to a
  password, token, secret or key name (`API_TOKEN=...`, `password: ...`) and a password in a URL become `[redacted]`.
  At most 200 files, 32 KB per file and 128 KB per session; a diff goes again only when it changed.
- **Undo this session.** On the AI sessions page, a passkey tap signs
  `{type: "confirm", switch: "session.undo", confirms: "<checkpoint id>"}`. The agent checks it like every switch
  (pinned key, user verification, origin, nonce, expiry) and then also that: root ran
  `sudo securemyserver allow session-undo`; it is the newest session; its last sudo was less than 24 hours ago; no
  switch checkpoint is waiting; and the files are still exactly as the session left them (else: restore by hand).
  The restore checks the saved copy against its sha256, runs `sshd -t` and `visudo -c` (if either fails, the current
  files stay and it says so), reloads ssh, runs `systemctl daemon-reload`, and puts the ruleset back only if it
  differs (without the agent's own blocklist table, which the next pull adds again).
- By hand, root can always restore any of them: `sudo securemyserver undo <id>` (`securemyserver status` lists them).
- **Limits, honestly.** The sudo check is on the command text: a command that builds the word `sudo` at run time
  (a variable, an alias) runs without a checkpoint. It can't change root-owned files without sudo either way, and
  the presets stay the boundary. Changes outside the fixed list (a file in /opt, a database) are neither shown nor
  undone. Undo restores config files; it does not uninstall packages or restart services other than ssh.

## Install

The easy way: **Add server** in the dashboard gives you a **Copy prompt** for your AI (Claude Code, Cursor, Codex or
any chat). It carries this server's one-time enrollment token and does the steps below, showing you each command
before it runs. Nothing is piped into a shell: it downloads, verifies, then installs.

By hand:

1. Create the server in the dashboard: Servers, Add server (or `npm run enroll -- --name web-1 --account <id or name>`,
   which prints the same agent.conf with the account's passkeys and the blocklist key pinned; default account `dev`,
   which has no passkeys, so no switches; add `--prompt agent` or `--prompt chat` for the install prompt). The token
   is shown once.
2. Download the release for your architecture (`uname -m`: x86_64 is amd64, aarch64 is arm64) from the GitHub release
   `v<version>`: `securemyserver-linux-<arch>`, `securemyserver-gate-linux-<arch>`, `SHA256SUMS` and
   `SHA256SUMS.minisig`. Verify before installing (the public key is in the install prompt and on the release page):

   ```sh
   minisign -Vm SHA256SUMS -x SHA256SUMS.minisig -P <minisign public key>   # "Signature and comment signature verified"
   grep -E ' (securemyserver|securemyserver-gate)-linux-amd64$' SHA256SUMS | sha256sum -c -   # OK twice
   sudo install -o root -g root -m 755 securemyserver-linux-amd64 /usr/local/sbin/securemyserver
   sudo install -d -o root -g root -m 755 /usr/lib/securemyserver
   sudo install -o root -g root -m 755 securemyserver-gate-linux-amd64 /usr/lib/securemyserver/securemyserver-gate
   ```

   Without minisign, compare against the checksums the install prompt embeds (the platform took them from the signed
   release manifest, D-055).
3. Write `/etc/securemyserver/agent.conf`, root only (`sudo install -m 600 /dev/null` first, then fill it):

   ```
   endpoint = https://ingest.securemyserver.com/v1/report
   token = sms_enroll_...                    # one-time: the first report uses it up
   server_id = 0b6c...                       # this server's id (switches, the blocklist, and naming it after enrollment)
   origin = https://securemyserver.com       # the origin passkeys sign on (default)
   rp_id = securemyserver.com                # the WebAuthn RP id (default: the origin's host)
   owner_key = <credential id> <SPKI base64> # one line per pinned passkey; Add server writes these
   blocklist_key = <Ed25519 public key, base64>  # the platform's blocklist signing key; Add server writes it
   ```

   `allow_http = true` permits a plain `http://` endpoint and origin, for local development only. Without
   `server_id` and an `owner_key`, switches are off and signed requests are ignored. Without `server_id` and a
   `blocklist_key`, the blocklist stays off even when allowed.
4. Look at what it would send: `sudo securemyserver agent --once --dry-run` (prints the report, sends nothing).
5. Run it as a service, `/etc/systemd/system/securemyserver.service`, then
   `sudo systemctl daemon-reload && sudo systemctl enable --now securemyserver`:

   ```ini
   [Unit]
   Description=SecureMyServer agent (reporter; writes only for signed switches and the allowed blocklist)
   After=network-online.target
   Wants=network-online.target

   [Service]
   ExecStart=/usr/local/sbin/securemyserver agent
   Restart=always
   RestartSec=30
   NoNewPrivileges=yes
   ProtectSystem=strict
   ProtectHome=read-only
   PrivateTmp=yes
   # /var/lib/securemyserver: checkpoints, used nonces, report key, blocklist, last report.
   StateDirectory=securemyserver
   StateDirectoryMode=0700
   # Only what the switches and checkpoints write. The "-" skips paths that don't exist (no ufw).
   ReadWritePaths=/etc/ssh -/etc/ufw -/etc/default/ufw -/etc/apt -/etc/sudoers.d -/etc/systemd/system

   [Install]
   WantedBy=multi-user.target
   ```

   `ProtectSystem=strict` makes the whole filesystem read-only for the agent, except the paths the switches and
   checkpoints write. `updates.security_now` and the checkpoint backup timer run as their own `systemd-run`
   units, outside this sandbox. nftables is changed over netlink, which the sandbox allows (root keeps
   `CAP_NET_ADMIN`). `/etc/securemyserver/allow.d` stays read-only to the agent: only root at a shell allows
   switches and the blocklist. This unit was tested as is on Ubuntu 24.04 under systemd (`test/systemd`).
   Comments in a unit file go on their own line: systemd reads `StateDirectory=a # b` as several directory names.
6. `sudo securemyserver check` sends a report now and prints a short summary. `sudo securemyserver status` shows the
   local state at any time, without contacting the platform.

### The one-time enrollment token (D-054)

A new server gets an `sms_enroll_` token. It works for **one** report, within **15 minutes** of being made
(`SMS_ENROLL_TTL_MINUTES` on the platform). That first report must be signed (D-043, agent 0.6.0): it registers this
server's report key, and the platform marks the token used in the same transaction. The agent writes
`/var/lib/securemyserver/enrollment.json` and from then on sends `X-SMS-Server: <server id>` instead of the token;
the signature with the registered key is the only proof. A second use of the token is refused ("already used"), so a
leaked token is worthless once the server is enrolled, and an unused one dies after 15 minutes.

- Token expired before the first report? The server page has a button for a new token (or
  `npm run enroll -- --reissue <server id>`). Put the new `token = ` line in agent.conf and run `sudo securemyserver check`.
- Reinstalled the server (new key)? **Forget report key** on the server page, then get a new token the same way. A
  token can't be reissued while a report key is registered, so nobody can take over a running server with one.
- Servers enrolled with an older `sms_` token keep using it as a bearer token.
- The reply to a report also carries `summary` (open, critical and verified items, switches waiting), which `check`
  prints. Like everything else in the reply except the signed `envelopes`, the agent never acts on it.

## Commands

| Command | What it does |
|---|---|
| `securemyserver check` | Sends one report now and prints a short summary: checklist items open and verified, switches pending, the blocklist version. Exit code 1 if the report was not accepted, with a hint. `-v` shows the log lines. |
| `securemyserver status` | Local state, without contacting the platform: whether the service runs, the config, the enrollment, the last report's time and result, allowed switches, a waiting checkpoint, the blocklist and the report key fingerprint, then the last checkpoints. |
| `securemyserver agent` | The service: reads the server and sends a report every 5 minutes (flags below). `agent --once` still sends one report and exits. |
| `securemyserver version` | Prints the version. |
| `securemyserver checkpoint [--minutes 5] ssh|ufw|nft|apt...` | Saves the targets and prints the folder. Restores itself at the deadline unless confirmed. |
| `securemyserver confirm [id]` | Keeps the change. Run it from a NEW SSH session. |
| `securemyserver undo [id]` | Restores the last checkpoint (waiting or confirmed) now, validates, reloads. |
| `securemyserver allow <switch> [<switch>...]`, `allow --all-safe`, `disallow <switch>...`, `allowed` | The server-side key for signed switches, several at once (`allow ssh.password_auth_off ssh.root_login_off blocklist`), or every safe switch with `--all-safe` (agent 0.9.0; not the blocklist or session-undo). Every name is checked first; one unknown name changes nothing. Each switch still needs its own passkey-signed policy. |
| `securemyserver allow session-undo`, `disallow session-undo` | Lets the dashboard's passkey-signed "Undo this session" restore an AI session's checkpoint. |
| `securemyserver checkpoint --session <id> --auto` | Run by securemyserver-gate through sudo before the AI's sudo commands; nothing else should call it. |
| `securemyserver allow blocklist`, `disallow blocklist` | Turns the signed blocklist on or off on this server (off removes the nft table). |
| `securemyserver rotate-key` | A new report signing key, signed by the old one. |

`securemyserver-gate` is a separate binary (below), run only by sshd as the AI user's forced command.
Our honeypot sensor is a separate, private program (end of this file).

**Upgrading from smsd** (compatibility note): the old config path `/etc/securemyserver/smsd.conf` is still read,
with a deprecation line in the log, when `agent.conf` does not exist. Rename it. The report field `ai_gate` is
now `gate`; the platform accepts both for one release.

## Agent flags

| Flag | Default | Meaning |
|---|---|---|
| `--once` | off | Send one report and exit |
| `--dry-run` | off | With `--once`: print the report JSON, send nothing |
| `--interval` | `5m` | Time between reports |
| `--since` | `15m` | Auth log window for the first report (later reports continue from the last accepted one) |
| `--config` | `/etc/securemyserver/agent.conf` (falls back to the old `smsd.conf`) | Config file |
| `--version` | | Print the version |

## Build and test (Docker, no local Go needed)

From the repository root (Git Bash on Windows needs `MSYS_NO_PATHCONV=1` and `$(pwd -W)`):

```sh
docker run --rm -v "$PWD:/src" -w /src -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false golang:1.25.4-bookworm \
  sh -c 'go vet ./... && go test ./... && go build -trimpath -ldflags="-s -w" -o bin/securemyserver . \
         && go build -trimpath -ldflags="-s -w" -o bin/securemyserver-gate ./cmd/securemyserver-gate'
```


`test/Dockerfile` is an Ubuntu 24.04 image with openssh-server, rsyslog and sudo for end-to-end tests:

```sh
docker build -t securemyserver-sshd-test:24.04 test
docker run -d --name securemyserver-sshd-test --add-host host.docker.internal:host-gateway \
  -v "$PWD/bin/securemyserver:/usr/local/sbin/securemyserver:ro" securemyserver-sshd-test:24.04
# write /etc/securemyserver/agent.conf in the container with
#   endpoint = http://host.docker.internal:3000/v1/report, your token, allow_http = true
docker exec securemyserver-sshd-test securemyserver agent --once
```

`test/systemd/Dockerfile` is Ubuntu 24.04 (pinned by digest) with systemd as PID 1, openssh-server, ufw,
nftables and unattended-upgrades, for what needs a real init and a real netfilter: the `systemd-run` backup timer,
the firewall and update switches, and the blocklist in nftables. It runs privileged, in its own network namespace:

```sh
docker build -t securemyserver-systemd-test:24.04 test/systemd
docker run -d --name sms-systemd --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock \
  --add-host host.docker.internal:host-gateway \
  -v "$PWD/bin/securemyserver:/usr/local/sbin/securemyserver:ro" securemyserver-systemd-test:24.04
```

`journal-trust.sh` checks the trusted-field rules (D-AGENT) end to end: a real key login by root, `logger -t sshd`
forgeries by a user and by securemyserver-ai, a real gate command, and forged gate entries (`logger -t
securemyserver-gate` and `logger --journald`). It fails unless the report has the real login and command, neither
forgery, and counts them in `auth_rejected` and `gate.forged`. Start the container without the `-v` line, then:

```sh
docker exec sms-systemd mkdir -p /usr/lib/securemyserver
docker cp bin/securemyserver sms-systemd:/usr/local/sbin/securemyserver
docker cp bin/securemyserver-gate sms-systemd:/usr/lib/securemyserver/securemyserver-gate
docker cp test/systemd/journal-trust.sh sms-systemd:/root/ && docker exec sms-systemd sh /root/journal-trust.sh
```

## Honeypot sensors

Our honeypot sensors are a separate program that runs only on a few VPSs SecureMyServer owns. Customers never
run it, and its source is not published, so attackers can't study how to recognise our sensors.

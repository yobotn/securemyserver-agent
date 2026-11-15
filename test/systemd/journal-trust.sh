#!/bin/sh
# End-to-end check of D-AGENT inside the systemd test container (see Dockerfile): with journald running, the agent
# counts only sshd lines journald attributes to root's sshd, and only securemyserver-gate entries journald attributes
# to the gate binary running as securemyserver-ai. Forged lines from `logger` (as a user, and as the AI user) are
# rejected and counted.
#
#   docker exec sms-systemd mkdir -p /usr/lib/securemyserver
#   docker cp securemyserver sms-systemd:/usr/local/sbin/securemyserver
#   docker cp securemyserver-gate sms-systemd:/usr/lib/securemyserver/securemyserver-gate
#   docker cp daemon/test/systemd/journal-trust.sh sms-systemd:/root/ && docker exec sms-systemd sh /root/journal-trust.sh
set -eu
fail() { echo "FAIL: $*"; exit 1; }

chown root:root /usr/lib/securemyserver/securemyserver-gate /usr/local/sbin/securemyserver
chmod 755 /usr/lib/securemyserver/securemyserver-gate /usr/local/sbin/securemyserver
id securemyserver-ai >/dev/null 2>&1 || useradd --create-home --shell /bin/sh securemyserver-ai
systemctl is-active --quiet systemd-journald || fail "journald is not running"
systemctl start ssh.service

# A real key login by root, through sshd.
[ -f /root/.ssh/id_ed25519 ] || { mkdir -p /root/.ssh && ssh-keygen -q -t ed25519 -N "" -f /root/.ssh/id_ed25519; }
cat /root/.ssh/id_ed25519.pub > /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -i /root/.ssh/id_ed25519 root@127.0.0.1 true
REAL_FP=$(ssh-keygen -lf /root/.ssh/id_ed25519.pub | awk '{print $2}')

# Forged sshd lines: a normal user and the AI user, with the identifier sshd uses.
FAKE="Accepted publickey for root from 203.0.113.9 port 1 ssh2: ED25519 SHA256:16zpKIJLpvoGi1bN7gEd/y+iwDSqOo5T566rezQ89do"
su deploy -c "logger -t sshd '$FAKE'"
su -s /bin/sh securemyserver-ai -c "logger -t sshd-session '$FAKE'"

# A real gate command, and forged gate entries from the AI user: over syslog, and over journald's native protocol.
ID=$(printf 'f%.0s' $(seq 32)); SESS=$(printf '9%.0s' $(seq 16))
FORGED="{\"v\":1,\"ev\":\"start\",\"id\":\"$ID\",\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"session\":\"$SESS\",\"cmd\":\"forged-command\",\"cmd_len\":14}"
su -s /bin/sh securemyserver-ai -c "SSH_ORIGINAL_COMMAND='echo real-command' SSH_CONNECTION='203.0.113.7 1 10.0.0.2 22' /usr/lib/securemyserver/securemyserver-gate" | grep -q real-command \
  || fail "the gate did not run the real command"
su -s /bin/sh securemyserver-ai -c "logger -t securemyserver-gate '$FORGED'"
su -s /bin/sh securemyserver-ai -c "logger --journald" <<EOF
MESSAGE=$FORGED
SYSLOG_IDENTIFIER=securemyserver-gate
EOF
sleep 1

/usr/local/sbin/securemyserver agent --once --dry-run --since 10m > /tmp/report.json
J() { grep -o "\"$1\": [^,}]*" /tmp/report.json | head -1 | sed 's/.*: //'; }
echo "auth_source=$(J auth_source) auth_verified=$(J auth_verified) auth_rejected=$(J auth_rejected)"
echo "usage_source=$(J usage_source) usage_verified=$(J usage_verified)"
echo "gate source=$(J source) log=$(J log) forged=$(J forged) bad_lines=$(J bad_lines) suppressed=$(J suppressed)"

[ "$(J auth_source)" = '"journal"' ] || fail "auth source is not the journal"
[ "$(J auth_verified)" = true ] || fail "auth not verified"
[ "$(J auth_rejected)" -ge 2 ] || fail "the forged sshd lines were not rejected"
grep -q '203.0.113.9' /tmp/report.json && fail "a forged login (203.0.113.9) reached the report"
grep -q "\"key_fp\": \"$REAL_FP\"" /tmp/report.json || fail "the real key login is missing"
[ "$(J usage_verified)" = true ] || fail "key usage not verified"
grep -q '"source": "journal"' /tmp/report.json || fail "gate source is not the journal"
grep -q 'real-command' /tmp/report.json || fail "the real gate command is missing"
grep -q 'forged-command' /tmp/report.json && fail "a forged gate entry reached the report"
[ "$(J forged)" -ge 2 ] || fail "forged gate entries were not counted"
echo "PASS"

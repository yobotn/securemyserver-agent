# Ubuntu 24.04 with systemd as PID 1, for end-to-end tests of what needs a real init and a real kernel firewall:
# the systemd-run backup timer, ufw, nftables, apt security updates and unattended-upgrades. Not for production.
#
#   docker build -t securemyserver-systemd-test:24.04 daemon/test/systemd
#   docker run -d --name sms-systemd --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock \
#     --add-host host.docker.internal:host-gateway \
#     -v "$PWD/daemon/bin/securemyserver:/usr/local/sbin/securemyserver:ro" securemyserver-systemd-test:24.04
#
# --privileged gives systemd its cgroup tree and ufw/nft the netfilter capabilities; the container's own network
# namespace keeps the rules away from the host.
FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852
ENV DEBIAN_FRONTEND=noninteractive container=docker
RUN apt-get update && apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus openssh-server openssh-client ufw nftables iptables unattended-upgrades \
      sudo ca-certificates netcat-openbsd iproute2 \
    # unattended-upgrades starts "off", so updates.unattended_on has something to do.
    && rm -f /etc/apt/apt.conf.d/20auto-upgrades \
    && useradd -m -s /bin/bash -G sudo deploy \
    && install -d -o deploy -g deploy -m 700 /home/deploy/.ssh \
    && printf "PasswordAuthentication yes\nPermitRootLogin yes\n" > /etc/ssh/sshd_config.d/10-test.conf \
    && systemctl enable ssh.service \
    # Nothing else listens publicly (firewall.on_keep_ssh refuses then), and no apt job races the test.
    && systemctl mask systemd-resolved.service apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service \
         getty@tty1.service console-getty.service systemd-networkd-wait-online.service 2>/dev/null; true
# The apt lists stay in the image, so pending security updates show up for updates.security_now.
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]

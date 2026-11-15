# Ubuntu 24.04 with openssh-server, rsyslog and sudo (for the securemyserver-ai presets), for testing securemyserver end to end. Not for production.
FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server openssh-client rsyslog sshpass ca-certificates sudo e2fsprogs \
    && mkdir -p /run/sshd \
    && sed -i "/imklog/s/^/#/" /etc/rsyslog.conf \
    && useradd -m -s /bin/bash -G sudo deploy \
    && mkdir -p /home/deploy/.ssh && echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEKEYEXAMPLEKEYEXAMPLEKEYEXAMPLEKEY test" > /home/deploy/.ssh/authorized_keys \
    && printf "PasswordAuthentication yes\nPermitRootLogin yes\n" > /etc/ssh/sshd_config.d/10-test.conf
# apt lists stay in the image so the agent can simulate an upgrade.
CMD ["sh", "-c", "rsyslogd && exec /usr/sbin/sshd -D"]

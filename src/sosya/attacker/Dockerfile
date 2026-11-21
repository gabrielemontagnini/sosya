# The Sosya attacker box: the only container of a range that can reach the targets from
# outside, and the only one with internet access. A small, standard toolset: no exploit
# frameworks.
#
# Published for linux/amd64 and linux/arm64 as ghcr.io/gabrielemontagnini/sosya-attacker.
FROM kalilinux/kali-rolling@sha256:1ff4a2be3849333687b3ed2b31bb5af0cd1b7c0a11ec7713feb5abe5a6b2795c

LABEL org.opencontainers.image.title="sosya-attacker" \
      org.opencontainers.image.description="Attacker box for Sosya ranges" \
      org.opencontainers.image.source="https://github.com/gabrielemontagnini/sosya" \
      org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bind9-dnsutils \
      ca-certificates \
      curl \
      iproute2 \
      iputils-ping \
      less \
      mariadb-client \
      microsocks \
      ncat \
      netcat-openbsd \
      nmap \
      openssh-client \
      procps \
      python3 \
      python3-requests \
      redis-tools \
      smbclient \
      socat \
      vim-tiny \
      wget \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* \
 # Kali gives nmap file capabilities that include cap_net_admin, which Docker does not grant,
 # so exec fails with "Operation not permitted". The box runs as root and has NET_RAW.
 && setcap -r /usr/lib/nmap/nmap

# The localhost-only relay of `sosya up --proxy` and `--expose`.
COPY --chmod=0755 sosya-forward sosya-relay /usr/local/bin/

WORKDIR /root
CMD ["sleep", "infinity"]

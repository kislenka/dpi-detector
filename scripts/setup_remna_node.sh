#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root."
  exit 1
fi

INSTALL_FAIL2BAN=1
SSH_PORT="22"
NODE_USER=""
TIMEZONE=""

usage() {
  cat <<'EOF'
Usage:
  bash scripts/setup_remna_node.sh [options]

Options:
  --no-fail2ban       Skip fail2ban installation
  --ssh-port PORT     SSH port for fail2ban jail (default: 22)
  --node-user USER    Optional service user to add to systemd-journal group
  --timezone TZ       Optional timezone, for example Europe/Berlin
  -h, --help          Show help

What it does:
  - Updates Ubuntu packages
  - Installs useful network tools
  - Enables BBR + fq
  - Applies TCP/sysctl tuning for stable throughput
  - Raises file descriptor limits
  - Optionally installs and configures fail2ban
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-fail2ban)
      INSTALL_FAIL2BAN=0
      shift
      ;;
    --ssh-port)
      SSH_PORT="${2:?missing port}"
      shift 2
      ;;
    --node-user)
      NODE_USER="${2:?missing user}"
      shift 2
      ;;
    --timezone)
      TIMEZONE="${2:?missing timezone}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

echo "[1/7] apt update / upgrade"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -y upgrade

echo "[2/7] install base packages"
apt-get install -y \
  ca-certificates \
  curl \
  wget \
  git \
  jq \
  unzip \
  bash-completion \
  htop \
  iotop \
  iftop \
  nload \
  mtr-tiny \
  iperf3 \
  ethtool \
  net-tools \
  dnsutils \
  lsof \
  rsyslog

if [[ -n "${TIMEZONE}" ]]; then
  echo "[3/7] set timezone ${TIMEZONE}"
  timedatectl set-timezone "${TIMEZONE}"
else
  echo "[3/7] timezone skipped"
fi

echo "[4/7] apply sysctl tuning"
cat >/etc/sysctl.d/99-remna-network.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864

net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.ip_local_port_range=10240 65535

net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=15

net.netfilter.nf_conntrack_max=262144
EOF
sysctl --system >/tmp/remna-sysctl.log

echo "[5/7] raise file descriptor limits"
cat >/etc/security/limits.d/99-remna-limits.conf <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

cat >/etc/systemd/system.conf.d/99-remna-limits.conf <<'EOF'
[Manager]
DefaultLimitNOFILE=1048576
EOF

cat >/etc/systemd/user.conf.d/99-remna-limits.conf <<'EOF'
[Manager]
DefaultLimitNOFILE=1048576
EOF

systemctl daemon-reexec

if [[ "${INSTALL_FAIL2BAN}" -eq 1 ]]; then
  echo "[6/7] install fail2ban"
  apt-get install -y fail2ban
  cat >/etc/fail2ban/jail.d/remna.local <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd
banaction = iptables-multiport
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ${SSH_PORT}
logpath = %(sshd_log)s
EOF
  systemctl enable --now fail2ban
  fail2ban-client restart
else
  echo "[6/7] fail2ban skipped"
fi

if [[ -n "${NODE_USER}" ]] && id "${NODE_USER}" >/dev/null 2>&1; then
  echo "[7/7] add ${NODE_USER} to systemd-journal"
  usermod -aG systemd-journal "${NODE_USER}"
else
  echo "[7/7] node user step skipped"
fi

echo
echo "Done."
echo "Checks:"
sysctl net.ipv4.tcp_congestion_control
sysctl net.core.default_qdisc
ulimit -n || true
if command -v fail2ban-client >/dev/null 2>&1; then
  fail2ban-client status sshd || true
fi
echo
echo "Recommended reboot if this is a fresh node:"
echo "  reboot"

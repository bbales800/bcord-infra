#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# BCord host bootstrap helper
#
# Installs diagnostic tooling required by the on-call runbook and ensures the
# Redis recommendation `vm.overcommit_memory=1` is applied persistently.
# This script is idempotent and safe to re-run.
# -----------------------------------------------------------------------------

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "[ERROR] Please run as root (use sudo)." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  net-tools \
  lsof \
  curl \
  jq

SYSCTL_CONF="/etc/sysctl.conf"
if ! grep -q '^vm.overcommit_memory=1$' "${SYSCTL_CONF}"; then
  echo 'vm.overcommit_memory=1' >> "${SYSCTL_CONF}"
fi

sysctl -w vm.overcommit_memory=1 >/dev/null
sysctl -p >/dev/null

echo "Host bootstrap complete."

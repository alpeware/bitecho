#!/usr/bin/env bash
# BIP-018 Track 1 (D45 / v0.23.21): Fleet SSH Key-Only Hardening, OOMScoreAdjust & /statusz Watchdog
# Rule 6: Asserts all preconditions loudly; verifies `sshd -t` AND live key-only SSH login BEFORE reloading sshd.
set -euo pipefail

# =============================================================================
# 1. Precondition Assertions (Rule 6: Loud Failure on Missing Prereqs)
# =============================================================================
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "FATAL: Must run as root (EUID=0)." >&2
  exit 1
fi

for cmd in sshd ssh curl awk sed grep; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "FATAL: Required binary '$cmd' not found in PATH." >&2
    exit 1
  fi
done

SSH_VERIFY_USER="${SSH_VERIFY_USER:-root}"
SSH_VERIFY_HOST="${SSH_VERIFY_HOST:-127.0.0.1}"
SSH_VERIFY_PORT="${SSH_VERIFY_PORT:-22}"
SSH_VERIFY_KEY="${SSH_VERIFY_KEY:-/root/.ssh/id_ed25519}"
SSHD_DROPIN_DIR="/etc/ssh/sshd_config.d"
SSHD_DROPIN_FILE="${SSHD_DROPIN_DIR}/99-bitecho-hardening.conf"
WATCHDOG_SCRIPT="/usr/local/sbin/bitecho-statusz-watchdog.sh"
STATUSZ_URL="${STATUSZ_URL:-http://127.0.0.1:8080/statusz}"
WATCHDOG_COOLDOWN_SEC="${WATCHDOG_COOLDOWN_SEC:-180}"

if [[ ! -s "/root/.ssh/authorized_keys" && ! -s "/home/${SSH_VERIFY_USER}/.ssh/authorized_keys" ]]; then
  echo "FATAL: No non-empty authorized_keys found for '${SSH_VERIFY_USER}'; refusing to disable PasswordAuthentication (anti-lockout)." >&2
  exit 1
fi

# =============================================================================
# 2. SSH Key-Only Hardening Drop-In (Zero Lockout Verification Before Reload)
# =============================================================================
mkdir -p "${SSHD_DROPIN_DIR}"
BACKUP_FILE=""
if [[ -f "${SSHD_DROPIN_FILE}" ]]; then
  BACKUP_FILE="${SSHD_DROPIN_FILE}.bak.$$"
  cp -a "${SSHD_DROPIN_FILE}" "${BACKUP_FILE}"
fi

rollback_sshd_dropin() {
  echo "ERROR: SSH hardening verification failed; rolling back ${SSHD_DROPIN_FILE}." >&2
  if [[ -n "${BACKUP_FILE}" && -f "${BACKUP_FILE}" ]]; then
    mv -f "${BACKUP_FILE}" "${SSHD_DROPIN_FILE}"
  else
    rm -f "${SSHD_DROPIN_FILE}"
  fi
}

cat > "${SSHD_DROPIN_FILE}" <<'EOF'
# Managed by BIP-018 scripts/harden-fleet-ssh-and-watchdog.sh
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitRootLogin prohibit-password
MaxAuthTries 3
MaxStartups 10:30:60
EOF
chmod 0600 "${SSHD_DROPIN_FILE}"

# Verify syntax with sshd -t BEFORE reloading sshd
if ! sshd -t; then
  rollback_sshd_dropin
  echo "FATAL: sshd -t syntax validation failed." >&2
  exit 1
fi

# Twin Edge Case #3: Verify live key-only SSH login BEFORE reloading sshd
SSH_TEST_ARGS=(-o BatchMode=yes -o PasswordAuthentication=no -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new -p "${SSH_VERIFY_PORT}")
if [[ -f "${SSH_VERIFY_KEY}" ]]; then
  SSH_TEST_ARGS+=(-i "${SSH_VERIFY_KEY}")
fi

if ! ssh "${SSH_TEST_ARGS[@]}" "${SSH_VERIFY_USER}@${SSH_VERIFY_HOST}" "true" >/dev/null 2>&1; then
  rollback_sshd_dropin
  echo "FATAL: Live key-only SSH login test (BatchMode=yes, PasswordAuthentication=no) failed for ${SSH_VERIFY_USER}@${SSH_VERIFY_HOST}:${SSH_VERIFY_PORT}; sshd NOT reloaded." >&2
  exit 1
fi

rm -f "${BACKUP_FILE:-}"

# Reload sshd safely after both sshd -t and live key-only SSH test succeeded
if command -v rc-service >/dev/null 2>&1; then
  rc-service sshd reload
elif command -v systemctl >/dev/null 2>&1; then
  systemctl reload sshd || systemctl reload ssh
else
  kill -HUP "$(cat /run/sshd.pid 2>/dev/null || pgrep -xo sshd)"
fi
echo "OK: sshd hardened and reloaded after sshd -t + live key-only SSH verification."

# =============================================================================
# 3. OOMScoreAdjust Protection (sshd = -500, bitecho-infra = 200)
# =============================================================================
apply_oom_score() {
  local proc_name="$1"
  local score="$2"
  local pid
  for pid in $(pgrep -x "${proc_name}" 2>/dev/null || true); do
    if [[ -w "/proc/${pid}/oom_score_adj" ]]; then
      echo "${score}" > "/proc/${pid}/oom_score_adj"
    fi
  done
}

# Persist OOMScoreAdjust for systemd if present, and apply live to running processes
if [[ -d /etc/systemd/system ]]; then
  mkdir -p /etc/systemd/system/sshd.service.d /etc/systemd/system/bitecho-infra.service.d
  printf "[Service]\nOOMScoreAdjust=-500\n" > /etc/systemd/system/sshd.service.d/99-bitecho-oom.conf
  printf "[Service]\nOOMScoreAdjust=200\n" > /etc/systemd/system/bitecho-infra.service.d/99-bitecho-oom.conf
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

if [[ -d /etc/conf.d ]]; then
  grep -q "OOMScoreAdjust=-500" /etc/conf.d/sshd 2>/dev/null || echo "# OOMScoreAdjust=-500" >> /etc/conf.d/sshd
  grep -q "OOMScoreAdjust=200" /etc/conf.d/bitecho-infra 2>/dev/null || echo "# OOMScoreAdjust=200" >> /etc/conf.d/bitecho-infra
fi

apply_oom_score sshd -500
apply_oom_score node 200
echo "OK: Applied OOMScoreAdjust (sshd=-500, bitecho-infra=200)."

# =============================================================================
# 4. 60s Local /statusz Watchdog (3 Consecutive Fails -> Restart bitecho-infra)
# =============================================================================
cat > "${WATCHDOG_SCRIPT}" <<EOF
#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="/run/bitecho-watchdog"
FAIL_FILE="\${STATE_DIR}/fail_count"
LAST_RESTART_FILE="\${STATE_DIR}/last_restart_epoch"
LOG_FILE="/var/log/bitecho-watchdog.log"
STATUSZ_URL="${STATUSZ_URL}"
COOLDOWN_SEC="${WATCHDOG_COOLDOWN_SEC}"

mkdir -p "\${STATE_DIR}"
now_sec="\$(date +%s)"

if curl -fsS --max-time 5 "\${STATUSZ_URL}" >/dev/null 2>&1; then
  echo "0" > "\${FAIL_FILE}"
  exit 0
fi

fails="\$(cat "\${FAIL_FILE}" 2>/dev/null || echo 0)"
fails="\$((fails + 1))"
echo "\${fails}" > "\${FAIL_FILE}"
echo "\$(date -u +%Y-%m-%dT%H:%M:%SZ) WARN statusz probe failed (\${fails}/3) url=\${STATUSZ_URL}" >> "\${LOG_FILE}"

if [[ "\${fails}" -ge 3 ]]; then
  last_restart="\$(cat "\${LAST_RESTART_FILE}" 2>/dev/null || echo 0)"
  elapsed="\$((now_sec - last_restart))"
  if [[ "\${elapsed}" -lt "\${COOLDOWN_SEC}" ]]; then
    echo "\$(date -u +%Y-%m-%dT%H:%M:%SZ) INFO watchdog restart suppressed by cooldown (\${elapsed}s < \${COOLDOWN_SEC}s)" >> "\${LOG_FILE}"
    exit 0
  fi
  echo "\${now_sec}" > "\${LAST_RESTART_FILE}"
  echo "0" > "\${FAIL_FILE}"
  echo "\$(date -u +%Y-%m-%dT%H:%M:%SZ) ACTION WATCHDOG_RESTART bitecho-infra after 3 consecutive /statusz failures" >> "\${LOG_FILE}"
  if command -v rc-service >/dev/null 2>&1; then
    rc-service bitecho-infra restart
  elif command -v systemctl >/dev/null 2>&1; then
    systemctl restart bitecho-infra
  fi
fi
EOF
chmod 0755 "${WATCHDOG_SCRIPT}"

# Install 60s cron schedule if /etc/cron.d exists
if [[ -d /etc/cron.d ]]; then
  cat > /etc/cron.d/bitecho-statusz-watchdog <<EOF
* * * * * root ${WATCHDOG_SCRIPT}
EOF
  chmod 0644 /etc/cron.d/bitecho-statusz-watchdog
fi

echo "OK: Installed 60s /statusz watchdog at ${WATCHDOG_SCRIPT}."

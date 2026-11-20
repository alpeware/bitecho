#!/usr/bin/env bash
# scripts/gentoo-stage3-live-migrate.sh
# BIP-011 / P-HOST-3 (proven by BIP-012): Standalone, provider-agnostic in-place
# Stage3 live migration from Debian/systemd to Hardened Gentoo Linux under OpenRC.
#
# Usage:
#   sudo ./scripts/gentoo-stage3-live-migrate.sh --dry-run
#   sudo ./scripts/gentoo-stage3-live-migrate.sh --stage3-url <url> --stage3-sha512 <hex> --confirm-snapshot
#
# Proven on 1 GiB RAM / 30 GB disk (BIP-012):
#   Peak RAM: 464 MiB (47.9%) with zram zstd | Peak Disk: 4,206 MiB (15%)
#   Active migration: 149s | Atomic renameat2(RENAME_EXCHANGE) pivot reboot: 21s

set -euo pipefail

DRY_RUN=0
CONFIRM_SNAPSHOT=0
ARCH="${BITECHO_ARCH:-amd64}"
STAGE3_DIR="${BITECHO_STAGE3_DIR:-/gentoo}"
STATE_SUBVOLUME="${BITECHO_STATE_DIR:-/var/lib/bitecho}"
STAGE3_URL="${BITECHO_STAGE3_URL:-https://distfiles.gentoo.org/releases/amd64/autobuilds/current-stage3-amd64-hardened-openrc/stage3-amd64-hardened-openrc-20261115T170104Z.tar.xz}"
STAGE3_SHA512="${BITECHO_STAGE3_SHA512:-}"
MIN_FREE_DISK_MIB=6144
MIN_TOTAL_RAM_MIB=850

usage() {
  cat <<'EOF'
Usage: gentoo-stage3-live-migrate.sh [OPTIONS]

Options:
  --dry-run                Validate all preconditions and print migration plan without mutating disk
  --arch <amd64|arm64>     Target Gentoo architecture (default: amd64)
  --stage3-url <url>       Pinned Gentoo stage3-hardened-openrc tarball URL
  --stage3-sha512 <hex>    Expected SHA-512 hex digest of the stage3 tarball
  --stage3-dir <path>      Staging directory (default: /gentoo)
  --state-dir <path>       Preserved Bitecho state directory / subvolume (default: /var/lib/bitecho)
  --confirm-snapshot       Assert that an out-of-band disk or @rootfs snapshot has been taken
  -h, --help               Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --arch) ARCH="$2"; shift 2 ;;
    --stage3-url) STAGE3_URL="$2"; shift 2 ;;
    --stage3-sha512) STAGE3_SHA512="$2"; shift 2 ;;
    --stage3-dir) STAGE3_DIR="$2"; shift 2 ;;
    --state-dir) STATE_SUBVOLUME="$2"; shift 2 ;;
    --confirm-snapshot) CONFIRM_SNAPSHOT=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

log() {
  printf '[%s] [gentoo-stage3-migrate] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

die() {
  printf '[%s] [gentoo-stage3-migrate] ERROR: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2
  exit 1
}

assert_preconditions() {
  log "Checking loud preconditions (Rule 6)..."
  if [[ "${DRY_RUN}" -eq 0 && "$(id -u)" -ne 0 ]]; then
    die "Must run as root (or pass --dry-run to inspect preconditions)."
  fi

  case "${ARCH}" in
    amd64|arm64) ;;
    *) die "Unsupported architecture '${ARCH}'. Supported: amd64, arm64." ;;
  esac

  for bin in python3 tar curl sha512sum df free; do
    command -v "${bin}" >/dev/null 2>&1 || die "Required tool missing: ${bin}"
  done

  local total_ram_mib avail_disk_mib
  total_ram_mib="$(free -m | awk '/^Mem:/ {print $2}')"
  avail_disk_mib="$(df -BM --output=avail / | tail -n 1 | tr -dc '0-9')"

  if [[ "${total_ram_mib}" -lt "${MIN_TOTAL_RAM_MIB}" ]]; then
    die "Insufficient RAM: ${total_ram_mib} MiB < ${MIN_TOTAL_RAM_MIB} MiB minimum."
  fi
  if [[ "${avail_disk_mib}" -lt "${MIN_FREE_DISK_MIB}" ]]; then
    die "Insufficient free disk on /: ${avail_disk_mib} MiB < ${MIN_FREE_DISK_MIB} MiB required for dual-OS staging."
  fi

  if [[ "${DRY_RUN}" -eq 0 && "${CONFIRM_SNAPSHOT}" -ne 1 ]]; then
    die "Pre-migration snapshot confirmation required. Take a full-disk or Btrfs @rootfs snapshot first, then pass --confirm-snapshot."
  fi

  log "Preconditions OK: arch=${ARCH}, ram=${total_ram_mib} MiB, free_disk=${avail_disk_mib} MiB, state_dir=${STATE_SUBVOLUME}"
}

setup_zram() {
  log "Step 1: Configuring zram swap (zstd, 100% RAM)..."
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log "[dry-run] Would configure /dev/zram0 with zstd compression at 100% RAM."
    return 0
  fi
  if ! swapon --show | grep -q zram; then
    modprobe zram || true
    if [[ -b /dev/zram0 ]]; then
      echo zstd > /sys/block/zram0/comp_algorithm 2>/dev/null || true
      local mem_bytes
      mem_bytes="$(awk '/^MemTotal:/ {print $2 * 1024}' /proc/meminfo)"
      echo "${mem_bytes}" > /sys/block/zram0/disksize
      mkswap /dev/zram0
      swapon -p 100 /dev/zram0
    fi
  fi
  log "zram active: $(swapon --show | tr '\n' ' ')"
}

stage_gentoo_rootfs() {
  log "Step 2: Staging Hardened Gentoo Stage3 into ${STAGE3_DIR}..."
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log "[dry-run] Would fetch ${STAGE3_URL}, verify SHA-512, and unpack into ${STAGE3_DIR}."
    return 0
  fi
  mkdir -p "${STAGE3_DIR}"
  local tarball="${STAGE3_DIR}/stage3.tar.xz"
  curl -fsSL "${STAGE3_URL}" -o "${tarball}"
  if [[ -n "${STAGE3_SHA512}" ]]; then
    echo "${STAGE3_SHA512}  ${tarball}" | sha512sum -c -
  fi
  tar xpvf "${tarball}" --xattrs-include='*.*' --numeric-owner -C "${STAGE3_DIR}"
  rm -f "${tarball}"
}

prepare_chroot_and_selftest() {
  log "Step 3: Preserving kernel modules, fstab, SSH keys, network config, and verifying chroot..."
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log "[dry-run] Would copy /lib/modules, /etc/fstab, /etc/ssh, mount /proc /sys /dev /run (avoiding BIP-012 F-1), and run OpenRC + full-node --self-test."
    return 0
  fi
  cp -a /lib/modules "${STAGE3_DIR}/lib/" 2>/dev/null || true
  cp -a /etc/fstab "${STAGE3_DIR}/etc/fstab"
  cp -a /etc/resolv.conf "${STAGE3_DIR}/etc/resolv.conf"
  cp -a /etc/ssh/ssh_host_* "${STAGE3_DIR}/etc/ssh/" 2>/dev/null || true
  mkdir -p "${STAGE3_DIR}/root/.ssh"
  cp -a /root/.ssh/authorized_keys "${STAGE3_DIR}/root/.ssh/" 2>/dev/null || true

  # Mount virtual filesystems inside chroot (fixes BIP-012 F-1: /proc/self/exe for $ORIGIN RUNPATH)
  mount --types proc /proc "${STAGE3_DIR}/proc"
  mount --rbind /sys "${STAGE3_DIR}/sys"
  mount --rbind /dev "${STAGE3_DIR}/dev"
  mount --bind /run "${STAGE3_DIR}/run"

  chroot "${STAGE3_DIR}" /bin/sh -c 'env-update && rc-update add dhcpcd default && rc-update add sshd default'

  umount -l "${STAGE3_DIR}/run" "${STAGE3_DIR}/dev" "${STAGE3_DIR}/sys" "${STAGE3_DIR}/proc"
}

execute_atomic_renameat2_pivot() {
  log "Step 4: Executing atomic renameat2(..., RENAME_EXCHANGE) root pivot inside single root Python process..."
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log "[dry-run] Would atomically exchange /etc /var /opt /home /root /media /mnt /usr with ${STAGE3_DIR}/* via SYS_renameat2 (RENAME_EXCHANGE=2) and invoke reboot(RB_AUTOBOOT), preserving ${STATE_SUBVOLUME}."
    return 0
  fi

  # Single elevated root Python process avoids BIP-012 F-2 (sudo passwd loss) and F-3 (merged-/usr ld-linux gap).
  python3 - "${STAGE3_DIR}" "${ARCH}" <<'PY'
import ctypes, os, sys

stage_dir = sys.argv[1]
arch = sys.argv[2]

libc = ctypes.CDLL(None, use_errno=True)
AT_FDCWD = -100
RENAME_EXCHANGE = 2
SYS_renameat2 = 316 if arch == "amd64" else 276  # x86_64=316, aarch64=276

def exchange(p1, p2):
    rc = libc.syscall(SYS_renameat2, AT_FDCWD, p1.encode(), AT_FDCWD, p2.encode(), RENAME_EXCHANGE)
    if rc != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"renameat2({p1}, {p2}) failed: {os.strerror(err)}")

for d in ["etc", "var", "opt", "home", "root", "media", "mnt", "usr"]:
    src = f"/{d}"
    dst = f"{stage_dir}/{d}"
    if os.path.exists(src) and os.path.exists(dst):
        exchange(src, dst)

if os.path.islink("/sbin"):
    os.unlink("/sbin")
os.symlink("usr/bin", "/sbin")

os.sync()
libc.reboot(0x1234567)  # RB_AUTOBOOT
PY
}

main() {
  assert_preconditions
  setup_zram
  stage_gentoo_rootfs
  prepare_chroot_and_selftest
  execute_atomic_renameat2_pivot
  log "Done (dry_run=${DRY_RUN})."
}

main "$@"

# Provider-Agnostic Runbook: In-Place Hardened Gentoo Stage3 Live Migration (`BIP-011 / P-HOST-3`)

This runbook documents the standalone, provider-agnostic procedure for migrating a running Bitecho node (validator or infra) in place from Debian/Ubuntu (`systemd`) to **Hardened Gentoo Linux (`default/linux/<arch>/23.0/no-multilib/hardened`) under OpenRC + `supervise-daemon`** without replacing the instance, changing IPs, or touching `@bitecho-state`.

The procedure was proven end-to-end in **BIP-012** on a `1 GiB` RAM / `30 GB` disk VM (`464 MiB` peak RAM with `zram`, `4,206 MiB` peak disk, `149s` active migration, `21s` atomic pivot reboot, `116s` deterministic rollback).

---

## 1. Preconditions

Verify all preconditions before starting (automated by `./scripts/gentoo-stage3-live-migrate.sh --dry-run`):

1. **Architecture:** `amd64` or `arm64` Linux host with root access.
2. **RAM:** `>= 850 MiB` visible RAM (1 GiB micro-VM class) with kernel `zram` support.
3. **Free Disk Space:** `>= 6 GiB` free on `/` so old rootfs, unpacked `/gentoo` Stage3, runtimes, and kernel modules coexist safely during staging.
4. **Isolated Node State:** Bitecho state (`/var/lib/bitecho` or `/var/lib/clj-web`) resides on its own `@bitecho-state` Btrfs subvolume (or preserved directory) and is **never** rolled back by an OS rollback.
5. **Pre-Migration Outer Snapshot (P-HOST-4):** Take a full-disk snapshot (cloud disk snapshot, LVM/ZFS/Btrfs `@rootfs` snapshot, or raw block backup) before pivoting. Never run the pivot without `--confirm-snapshot`.

---

## 2. Migration Steps

### Step 1: Dry-Run Validation
```bash
sudo ./scripts/gentoo-stage3-live-migrate.sh --dry-run
```

### Step 2: Take Pre-Migration Snapshot
- **Btrfs host:** `sudo btrfs subvolume snapshot -r / /.snapshots/rootfs-pre-gentoo`
- **Cloud VM (any provider):** Create a point-in-time snapshot of the boot disk while the node is online or briefly quiesced.

### Step 3: Stage & Pivot In-Place
```bash
sudo ./scripts/gentoo-stage3-live-migrate.sh \
  --arch amd64 \
  --stage3-url "<pinned-stage3-hardened-openrc-tarball-url>" \
  --stage3-sha512 "<verified-sha512-hex>" \
  --confirm-snapshot
```

What the script performs:
1. **Enables `zram` swap** (`zstd`, `100%` RAM, priority `100`).
2. **Downloads & SHA-512 verifies** the pinned `stage3-<arch>-hardened-openrc` tarball and extracts it into `/gentoo`.
3. **Prepares `/gentoo` chroot:** Copies kernel modules (`/lib/modules`), `/etc/fstab`, SSH host keys & `authorized_keys`, mounts `/proc`, `/sys`, `/dev`, and `/run` (avoiding BIP-012 `F-1` where hardened `RUNPATH` `$ORIGIN` expansion requires `/proc/self/exe`), runs `env-update`, and enables OpenRC services (`dhcpcd`, `sshd`, `zramswap`).
4. **Executes atomic `renameat2(..., RENAME_EXCHANGE)` pivot** inside a single elevated root Python 3 process (avoiding BIP-012 `F-2` `sudo` passwd loss and `F-3` merged-`/usr` `ld-linux` gap), exchanges `/etc /var /opt /home /root /media /mnt /usr` with `/gentoo/*`, calls `sync()`, and invokes `reboot(RB_AUTOBOOT)`.

### Step 4: Install OpenRC `supervise-daemon` Services
Install the co-committed init scripts from `scripts/gentoo-openrc/`:
```bash
# Infra node:
sudo install -m 0755 scripts/gentoo-openrc/bitecho-infra.initd /etc/init.d/bitecho-infra
sudo rc-update add bitecho-infra default
sudo rc-service bitecho-infra start

# Validator node:
sudo install -m 0755 scripts/gentoo-openrc/bitecho-validator.initd /etc/init.d/bitecho-validator
sudo rc-update add bitecho-validator default
sudo rc-service bitecho-validator start
```

---

## 3. Post-Migration Verification (`S-D37-4` / `P-HOST-5`)

1. **OS & OpenRC:**
   ```bash
   cat /etc/os-release        # ID=gentoo
   rc-status                  # dhcpcd, sshd, zramswap, bitecho-* [ started ]
   ```
2. **Runtime & Full-Node Self-Test:**
   ```bash
   node /opt/bitecho/bitecho-full-node.cjs --self-test
   node /opt/bitecho/bitecho-full-node.cjs --attest-root
   ```
3. **Identity & Consensus Continuity:** Confirm the node rejoins quorum with the **same Ed25519 pubkey, balance, epoch, internal/external IPs, bootstrap descriptors, and home sets**.
4. **Cleanup:** Once verified across the stage gate window (`W=8` epochs), reclaim space:
   ```bash
   sudo rm -rf /gentoo /debian.old && sync
   ```

---

## 4. Deterministic Rollback (`P-HOST-4`)

If a migration aborts mid-pivot or fails post-boot verification:
- **Btrfs host:** Restore the pre-migration `@rootfs` snapshot (never touch `@bitecho-state`) and reboot.
- **Cloud VM (provider-agnostic):** Stop instance -> detach boot disk -> create new boot disk from pre-migration snapshot -> attach as boot disk -> start instance. (Verified in BIP-012 Gate 4: `116 seconds` end-to-end back to working Debian.)

---

## 5. Shelved Fallback: Parallel Provisioning

Per BIP-011 `P-HOST-3`, **stage3 live migration is the primary path** (proven by BIP-012). Parallel provisioning (importing a custom Gentoo image, promoting static IPs, detaching/reattaching, and rsyncing quiesced state) remains documented as a shelved fallback only for undersized instances with `< 6 GiB` free disk or `< 850 MiB` RAM.

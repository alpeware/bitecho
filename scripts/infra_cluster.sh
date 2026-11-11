#!/usr/bin/env bash
# ==============================================================================
# Bitecho Infra Cluster Operations & Phase C Rolling Cutover (ns1..ns3)
# ==============================================================================
# Manages snapshot backups, shared TLS-secret provisioning (F-B2), pre-cutover
# state migration, one-node-at-a-time in-place cutover (ns3 -> ns2 -> ns1) from
# clj-web to unified `bitecho infra-node` ("bitecho.org/infra"), instant rollback,
# and post-cutover DNS/HTTPS/SMTP/Validator health auditing.
#
# Preconditions are asserted loudly (AGENTS.md Rule 6). Never mutates node1..node3.
# ==============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOMAIN="${DOMAIN:-bitecho.org}"
SSH_USER="${SSH_USER:-cljweb}"
SSH_KEY="${SSH_KEY:-${ROOT_DIR}/../clj-web/.ssh/clj_web_ed25519}"
NODES=("ns1" "ns2" "ns3")

declare -A NODE_IPS=(
  ["ns1"]="34.19.71.246"
  ["ns2"]="34.56.253.255"
  ["ns3"]="136.108.244.159"
)

declare -A INGRESS_TARGETS=(
  ["ns1"]="35.212.129.138"
  ["ns2"]="35.206.120.143"
  ["ns3"]="35.211.71.139"
)

print_usage() {
  cat << 'EOF'
Usage: ./scripts/infra_cluster.sh <command> [args]

Commands:
  snapshot                       Snapshot /var/lib/clj-web & /etc/clj-web from ns1..ns3 with SHA-256 verification
  provision-secret               Provision shared 32-byte /etc/clj-web/tls-secret.key (0600) across ns1..ns3 (F-B2)
  cutover <ns3|ns2|ns1|rolling>  Build bitecho.jar, migrate state, and cut over node(s) one at a time with rollback guard
  retire-clj-web                 Phase D: remove public clj-web.git on ns1..ns3 and roll updated bitecho.jar across ns3 -> ns2 -> ns1
  publish-git                    Sign 'verified' release tags and sync bare git repos (bitecho, clj-datachannel, clj-fressian) to ns1..ns3
  rollback <ns1|ns2|ns3|all>     Immediately roll back node(s) to clj-web.service
  audit                          Audit authoritative DNS (:53), HTTP (:80), HTTPS (:443), SMTP (:25), and node1..node3 health
EOF
}

assert_preconditions() {
  for bin in ssh rsync curl openssl sha256sum; do
    if ! command -v "$bin" >/dev/null 2>&1; then
      echo "FATAL: Required tool '$bin' not found in PATH." >&2
      exit 1
    fi
  done
  if [[ ! -f "${SSH_KEY}" ]]; then
    echo "FATAL: SSH key not found at ${SSH_KEY}" >&2
    exit 1
  fi
  if [[ ! -s "${ROOT_DIR}/devnet/bootstrap.txt" ]]; then
    echo "FATAL: Validator bootstrap descriptor not found at ${ROOT_DIR}/devnet/bootstrap.txt" >&2
    exit 1
  fi
}

ssh_ns() {
  local node="$1"
  shift
  local ip="${NODE_IPS[$node]:-}"
  if [[ -z "$ip" ]]; then
    echo "FATAL: Unknown infra node '${node}'." >&2
    exit 1
  fi
  ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -i "${SSH_KEY}" "${SSH_USER}@${ip}" "$@"
}

verify_node_health() {
  local node="$1"
  local ip="${NODE_IPS[$node]}"
  echo "  [probe] Verifying ${node} (${ip})..."

  # 1. HTTP :80 /healthz
  local hz
  hz="$(curl -fsS --max-time 5 "http://${ip}/healthz" || true)"
  if [[ "${hz}" != "ok" ]]; then
    echo "  [FAIL] ${node} HTTP :80 /healthz returned '${hz}'" >&2
    return 1
  fi

  # 2. HTTPS :443 /healthz (resolve domain to target IP)
  local hsz
  hsz="$(curl -fsS --max-time 8 --resolve "${DOMAIN}:443:${ip}" "https://${DOMAIN}/healthz" || true)"
  if [[ "${hsz}" != "ok" ]]; then
    echo "  [FAIL] ${node} HTTPS :443 /healthz returned '${hsz}'" >&2
    return 1
  fi

  # 2b. HTTPS :443 / landing page Content-Type must be text/markdown; charset=utf-8 (never application/octet-stream)
  local root_ct
  root_ct="$(curl -fsSI --max-time 8 --resolve "${DOMAIN}:443:${ip}" "https://${DOMAIN}/" | tr -d '\r' | awk 'tolower($1)=="content-type:" {sub(/^[^:]+:[[:space:]]*/, ""); print tolower($0)}' | head -n 1)"
  if [[ "${root_ct}" != "text/markdown; charset=utf-8" ]]; then
    echo "  [FAIL] ${node} HTTPS :443 / Content-Type returned '${root_ct}' (expected 'text/markdown; charset=utf-8')" >&2
    return 1
  fi

  # 3. Authoritative DNS :53 (if dig is available, else Python UDP DNS probe)
  if command -v dig >/dev/null 2>&1; then
    local ans
    ans="$(dig +short +time=3 +tries=1 "@${ip}" "${DOMAIN}" A | head -n 1)"
    if [[ -z "${ans}" ]]; then
      echo "  [FAIL] ${node} UDP :53 returned empty A answer for ${DOMAIN}" >&2
      return 1
    fi
  fi

  # 4. Loopback /statusz on node
  local stz
  stz="$(ssh_ns "$node" "curl -fsS --max-time 5 http://127.0.0.1/statusz" || true)"
  if [[ -z "${stz}" ]]; then
    echo "  [FAIL] ${node} loopback /statusz empty" >&2
    return 1
  fi
  echo "  [OK] ${node} healthy (${stz})"
}

cmd_snapshot() {
  assert_preconditions
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  local backup_dir="${ROOT_DIR}/.backups/infra-pre-cutover-${ts}"
  mkdir -p "${backup_dir}"
  chmod 700 "${backup_dir}"

  echo "=== Creating Pre-Cutover Snapshot in ${backup_dir} ==="
  for node in "${NODES[@]}"; do
    local archive="${backup_dir}/${node}-clj-web-state.tar.gz"
    echo "--> Snapshotting ${node} (${NODE_IPS[$node]})..."
    ssh_ns "$node" "sudo tar -czf - /etc/clj-web /var/lib/clj-web" > "${archive}"
    chmod 600 "${archive}"
    if [[ ! -s "${archive}" ]]; then
      echo "FATAL: Snapshot archive for ${node} is empty!" >&2
      exit 1
    fi
    (cd "${backup_dir}" && sha256sum "$(basename "${archive}")" >> SHA256SUMS)
  done
  echo "=== Snapshot verified: ${backup_dir}/SHA256SUMS ==="
  cat "${backup_dir}/SHA256SUMS"
}

cmd_provision_secret() {
  assert_preconditions
  local local_secret="${ROOT_DIR}/.ssh/infra_tls_secret.key"
  mkdir -p "$(dirname "${local_secret}")"
  if [[ ! -f "${local_secret}" ]]; then
    openssl rand -hex 32 > "${local_secret}"
    chmod 600 "${local_secret}"
    echo "Generated new 32-byte shared TLS secret at ${local_secret}"
  fi
  local expected_sha
  expected_sha="$(sha256sum "${local_secret}" | awk '{print $1}')"

  for node in "${NODES[@]}"; do
    local ip="${NODE_IPS[$node]}"
    echo "--> Provisioning /etc/clj-web/tls-secret.key on ${node} (${ip})..."
    rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
      "${local_secret}" "${SSH_USER}@${ip}:/tmp/tls-secret.key.tmp"
    local remote_sha
    remote_sha="$(ssh_ns "$node" "sudo mkdir -p /etc/clj-web && sudo mv /tmp/tls-secret.key.tmp /etc/clj-web/tls-secret.key && sudo chown root:${SSH_USER} /etc/clj-web/tls-secret.key && sudo chmod 0640 /etc/clj-web/tls-secret.key && sudo sha256sum /etc/clj-web/tls-secret.key | awk '{print \$1}'")"
    if [[ "${remote_sha}" != "${expected_sha}" ]]; then
      echo "FATAL: Secret checksum mismatch on ${node}!" >&2
      exit 1
    fi
  done
  echo "=== Shared TLS secret verified across ns1..ns3 (SHA-256: ${expected_sha}) ==="
}

rollback_node() {
  local node="$1"
  echo "!!! Rolling back ${node} (${NODE_IPS[$node]}) to clj-web.service !!!"
  ssh_ns "$node" bash -s << 'REMOTE_RB'
set -euo pipefail
sudo systemctl stop bitecho-infra.service 2>/dev/null || true
sudo systemctl disable bitecho-infra.service 2>/dev/null || true
sudo systemctl enable clj-web.service
sudo systemctl restart clj-web.service
REMOTE_RB
  sleep 3
  verify_node_health "$node"
}

cmd_rollback() {
  assert_preconditions
  local target="${1:-}"
  if [[ -z "$target" ]]; then
    print_usage
    exit 1
  fi
  if [[ "$target" == "all" ]]; then
    for node in "${NODES[@]}"; do
      rollback_node "$node"
    done
  else
    rollback_node "$target"
  fi
}

cutover_single_node() {
  local node="$1"
  local ip="${NODE_IPS[$node]}"
  echo "=== Cutting over ${node} (${ip}) to unified bitecho infra-node ==="

  ssh_ns "$node" bash -s << 'REMOTE_CUT'
set -euo pipefail
echo "  Running idempotent state migration on /var/lib/clj-web..."
sudo -u cljweb /opt/jdk-25/bin/java \
  -Xms128m -Xmx256m \
  --enable-native-access=ALL-UNNAMED \
  --add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED \
  --add-exports=java.base/sun.security.x509=ALL-UNNAMED \
  -jar /opt/bitecho-infra/bitecho.jar migrate-infra /etc/bitecho-infra/config.edn

sudo tee /etc/systemd/system/bitecho-infra.service >/dev/null << 'UNIT_EOF'
[Unit]
Description=Bitecho Unified Infra Subnet Node (DNS/HTTP/HTTPS/SMTP/ACME)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=cljweb
Group=cljweb
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
WorkingDirectory=/var/lib/clj-web
ExecStart=/opt/jdk-25/bin/java -Xms128m -Xmx384m -XX:+UseCompactObjectHeaders --enable-native-access=ALL-UNNAMED --add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED --add-exports=java.base/sun.security.x509=ALL-UNNAMED -jar /opt/bitecho-infra/bitecho.jar infra-node /etc/bitecho-infra/config.edn
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNIT_EOF

sudo systemctl daemon-reload
sudo systemctl stop clj-web.service
sudo systemctl disable clj-web.service
sudo systemctl enable bitecho-infra.service
sudo systemctl restart bitecho-infra.service
REMOTE_CUT

  echo "  Waiting for ${node} bitecho-infra.service readiness..."
  local ok=false
  for _ in $(seq 1 20); do
    sleep 2
    if verify_node_health "$node" 2>/dev/null; then
      ok=true
      break
    fi
  done
  if [[ "$ok" != true ]]; then
    echo "ERROR: ${node} failed post-cutover health check; triggering automatic rollback!" >&2
    rollback_node "$node"
    exit 1
  fi
  echo "=== ${node} cutover SUCCEEDED ==="
}

cmd_cutover() {
  assert_preconditions
  local target="${1:-}"
  if [[ -z "$target" ]]; then
    print_usage
    exit 1
  fi

  echo "--> Precondition: Auditing validator cluster (node1..node3) before infra cutover..."
  "${ROOT_DIR}/scripts/cluster.sh" audit

  echo "--> Ensuring shared TLS secret is provisioned across ns1..ns3..."
  cmd_provision_secret

  echo "--> Building target/bitecho.jar locally..."
  (cd "${ROOT_DIR}" && clojure -T:build uber)

  local cold_key_file="${ROOT_DIR}/.ssh/infra_cold_root_keypair.edn"
  mkdir -p "$(dirname "${cold_key_file}")"
  if [[ ! -f "${cold_key_file}" ]]; then
    echo "--> Generating dedicated offline Cold Infra Root Keypair at ${cold_key_file}..."
    java --enable-native-access=ALL-UNNAMED \
         --add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED \
         --add-exports=java.base/sun.security.x509=ALL-UNNAMED \
         -jar "${ROOT_DIR}/target/bitecho.jar" gen-keypair "${cold_key_file}" >/dev/null
    chmod 600 "${cold_key_file}"
  fi
  local cold_pubkey
  cold_pubkey="$(sed -n 's/.*:pubkey-hex "\([0-9a-fA-F]*\)".*/\1/p' "${cold_key_file}" | head -n 1)"
  if [[ -z "${cold_pubkey}" ]]; then
    echo "FATAL: Failed to read :pubkey-hex from offline cold key ${cold_key_file}" >&2
    exit 1
  fi

  declare -A PUBKEYS=()
  declare -A FINGERPRINTS=()

  for node in "${NODES[@]}"; do
    local ip="${NODE_IPS[$node]}"
    echo "--> Uploading bitecho.jar, validator bootstrap.txt, and reading identity on ${node} (${ip})..."
    ssh_ns "$node" "sudo mkdir -p /opt/bitecho-infra /etc/bitecho-infra && sudo chown ${SSH_USER}:${SSH_USER} /opt/bitecho-infra /etc/bitecho-infra"
    rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
      "${ROOT_DIR}/target/bitecho.jar" "${SSH_USER}@${ip}:/opt/bitecho-infra/bitecho.jar"
    rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
      "${ROOT_DIR}/devnet/bootstrap.txt" "${SSH_USER}@${ip}:/etc/bitecho-infra/bootstrap.txt"

    local id_out
    id_out="$(ssh_ns "$node" bash -s << REMOTE_ID
set -euo pipefail
TMP_CFG="\$(mktemp /tmp/infra-id-XXXXXX.edn)"
echo "{:node/id :${node} :domain \"${DOMAIN}\" :state-dir \"/var/lib/clj-web\"}" > "\$TMP_CFG"
/opt/jdk-25/bin/java -Xms64m -Xmx128m --enable-native-access=ALL-UNNAMED --add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED --add-exports=java.base/sun.security.x509=ALL-UNNAMED -jar /opt/bitecho-infra/bitecho.jar print-fingerprint "\$TMP_CFG"
rm -f "\$TMP_CFG"
REMOTE_ID
)"
    PUBKEYS[$node]="$(echo "$id_out" | awk '/Ed25519 Pubkey:/ {print $NF}')"
    FINGERPRINTS[$node]="$(echo "$id_out" | awk '/SHA-256 Fingerprint:/ {print $NF}')"
    if [[ -z "${PUBKEYS[$node]}" || -z "${FINGERPRINTS[$node]}" ]]; then
      echo "FATAL: Failed to extract pubkey/fingerprint on ${node}" >&2
      exit 1
    fi
    if [[ "${PUBKEYS[$node]}" == "${cold_pubkey}" ]]; then
      echo "FATAL: Hot node ${node} pubkey must never equal offline Cold Infra Root Key (F-C3)!" >&2
      exit 1
    fi
  done

  for node in "${NODES[@]}"; do
    local ip="${NODE_IPS[$node]}"
    local ingress_ip="${INGRESS_TARGETS[$node]}"
    local tmp_cfg
    tmp_cfg="$(mktemp /tmp/infra-cfg-${node}-XXXXXX.edn)"
    cat > "${tmp_cfg}" << CFG_EOF
{:node/id :${node}
 :domain "${DOMAIN}"
 :state-dir "/var/lib/clj-web"
 :tls-secret-file "/etc/clj-web/tls-secret.key"
 :cold-pubkey "${cold_pubkey}"
 :validator-bootstrap "/etc/bitecho-infra/bootstrap.txt"
 :acme {:enabled? true
        :directory-url "https://acme-v02.api.letsencrypt.org/directory"
        :contact-email "mailto:admin@${DOMAIN}"
        :renew-before-days 30
        :domains ["${DOMAIN}" "ns1.${DOMAIN}" "ns2.${DOMAIN}" "ns3.${DOMAIN}"]}
 :dns {:enabled? true
       :bind-ip "0.0.0.0"
       :port 53
       :ttl-seconds 60
       :ns-ttl-seconds 3600
       :hostmaster "hostmaster.${DOMAIN}"
       :subdomains #{"@" "www" "docs" "mvn" "ingress" "node1.ingress" "node2.ingress" "node3.ingress"}
       :delegated-ingress {"nexus.ingress" {:ns "ns1.nexus.ingress.${DOMAIN}" :ip4 "136.62.15.220" :ttl 60}
                           "ech1nve6n673sekkmdqeak479h57uaxgsnwgddppfasw8gn0qn9ann7qxhy2sq.ingress" {:ns "ns1.nexus.ingress.${DOMAIN}" :ip4 "136.62.15.220" :ttl 60}}}
 :http {:enabled? true
        :bind-ip "0.0.0.0"
        :http-port 80
        :https-port 443
        :ingress-target {:host "${ingress_ip}" :port 5010}
        :content-root "/var/www/clj-web/public"
        :directory-listing? true}
 :smtp {:enabled? true
        :bind-ip "0.0.0.0"
        :port 25
        :allowed-recipients #{"@${DOMAIN}"}}
 :cluster {:enabled? true
           :heartbeat-interval-ms 2000
           :heartbeat-timeout-ms 6000
           :nodes {:ns1 {:ip4 "${NODE_IPS[ns1]}" :port 5000 :pubkey "${PUBKEYS[ns1]}" :fingerprint "${FINGERPRINTS[ns1]}"}
                   :ns2 {:ip4 "${NODE_IPS[ns2]}" :port 5000 :pubkey "${PUBKEYS[ns2]}" :fingerprint "${FINGERPRINTS[ns2]}"}
                   :ns3 {:ip4 "${NODE_IPS[ns3]}" :port 5000 :pubkey "${PUBKEYS[ns3]}" :fingerprint "${FINGERPRINTS[ns3]}"}}}}
CFG_EOF
    rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
      "${tmp_cfg}" "${SSH_USER}@${ip}:/etc/bitecho-infra/config.edn"
    rm -f "${tmp_cfg}"
  done

  if [[ "$target" == "rolling" ]]; then
    # Cut over ns3 -> ns2 -> ns1 one node at a time so >= 2 authoritative nameservers stay live throughout!
    for node in ns3 ns2 ns1; do
      cutover_single_node "$node"
    done
  else
    cutover_single_node "$target"
  fi

  echo "--> Postcondition: Auditing infra cluster (ns1..ns3) & validator cluster (node1..node3)..."
  cmd_audit
}

cmd_retire_clj_web() {
  assert_preconditions
  echo "--> Building target/bitecho.jar locally for Phase D..."
  (cd "${ROOT_DIR}" && clojure -T:build uber)

  for node in ns3 ns2 ns1; do
    local ip="${NODE_IPS[$node]}"
    echo "=== Phase D on ${node} (${ip}): retiring clj-web.git & rolling bitecho.jar ==="
    rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
      "${ROOT_DIR}/target/bitecho.jar" "${SSH_USER}@${ip}:/opt/bitecho-infra/bitecho.jar"

    ssh_ns "$node" bash -s << 'REMOTE_RETIRE'
set -euo pipefail
sudo rm -rf /var/www/clj-web/public/git/clj-web.git
for doc in /var/www/clj-web/public/index.md /var/www/clj-web/public/llms.txt /var/www/clj-web/public/git/index.md; do
  if [[ -f "$doc" ]]; then
    sudo sed -i '/clj-web\.git/d' "$doc"
  fi
done
sudo /opt/jdk-25/bin/java -Xms64m -Xmx256m \
  --enable-native-access=ALL-UNNAMED \
  --add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED \
  --add-exports=java.base/sun.security.x509=ALL-UNNAMED \
  -jar /opt/bitecho-infra/bitecho.jar migrate-infra /etc/bitecho-infra/config.edn
sudo chown -R cljweb:cljweb /var/lib/clj-web
sudo systemctl restart bitecho-infra.service
REMOTE_RETIRE

    for _ in {1..20}; do
      if curl -fsS --max-time 2 "http://${ip}:80/healthz" >/dev/null 2>&1; then
        break
      fi
      sleep 1
    done
    verify_node_health "$node"
    local cljweb_status
    cljweb_status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 --resolve "${DOMAIN}:443:${ip}" "https://${DOMAIN}/git/clj-web.git/info/refs" || true)"
    if [[ "${cljweb_status}" != "404" ]]; then
      echo "FATAL: ${node} still serves /git/clj-web.git/info/refs (HTTP ${cljweb_status})" >&2
      exit 1
    fi
    echo "  [OK] ${node} retired /git/clj-web.git (HTTP 404 verified)"
  done

  cmd_audit
}

cmd_publish_git() {
  assert_preconditions
  local stage_dir
  stage_dir="$(mktemp -d /tmp/bitecho-publish-git-XXXXXX)"
  trap 'rm -rf "${stage_dir}"' RETURN

  echo "=== Publishing Canonical Bare Git Repositories (bitecho, clj-datachannel, clj-fressian) & Web Docs ==="
  declare -A REPO_SHAS=()
  declare -A REPO_SHORT_SHAS=()

  for repo in bitecho clj-datachannel clj-fressian; do
    local src_repo="${ROOT_DIR}/../${repo}"
    local bare_repo="${stage_dir}/${repo}.git"
    if [[ ! -d "${src_repo}/.git" ]]; then
      echo "FATAL: Source repository not found at ${src_repo}" >&2
      exit 1
    fi
    local def_branch
    def_branch="$(git -C "${src_repo}" symbolic-ref --short HEAD 2>/dev/null || git -C "${src_repo}" branch --show-current 2>/dev/null || echo "main")"
    if [[ -z "${def_branch}" ]]; then def_branch="main"; fi

    git -C "${src_repo}" \
      -c gpg.format=ssh \
      -c user.signingkey="${SSH_KEY}.pub" \
      -c user.name="Bitecho Release" \
      -c user.email="release@${DOMAIN}" \
      tag -s -f verified HEAD -m "Verified snapshot of ${repo} on ${DOMAIN}"

    git clone --bare --quiet "${src_repo}" "${bare_repo}"
    git --git-dir="${bare_repo}" symbolic-ref HEAD "refs/heads/${def_branch}"
    rm -rf "${bare_repo}/objects/info/commit-graphs" "${bare_repo}/objects/info/commit-graph"
    git --git-dir="${bare_repo}" repack -a -d -q
    git --git-dir="${bare_repo}" update-server-info
    git --git-dir="${bare_repo}" fsck --full >/dev/null
    local head_sha
    head_sha="$(git --git-dir="${bare_repo}" rev-parse HEAD)"
    local tag_sha
    tag_sha="$(git --git-dir="${bare_repo}" rev-parse verified)"
    REPO_SHAS[$repo]="${head_sha}"
    REPO_SHORT_SHAS[$repo]="${head_sha:0:12}"
    echo "  [OK] ${repo}.git: ${def_branch} @ ${head_sha} (verified tag ${tag_sha})"
  done

  # Generate refreshed index.md, llms.txt, and git/index.md with live commit SHAs (closing L-M3-1)
  cat > "${stage_dir}/index.md" << EOF_INDEX
# Bitecho (${DOMAIN})

Welcome to **Bitecho**, a high-performance, decentralized peer-to-peer messaging and coordination protocol built on pure Clojure and WebRTC DataChannels.

## Agent Onboarding & Light Node Skill

Autonomous agents and operators connecting to the live Bitecho devnet mesh should start with these resources:

- **[Light Node Onboarding & Operator Guide (\`/ONBOARDING.md\`)](/ONBOARDING.md)** (also at [\`/onboarding\`](/onboarding)): Step-by-step instructions to clone, launch a light node (\`--auto-sync\` enabled by default in \`serve\` mode), resolve directory peers, and participate in the network.
- **[Light Node Skill & JSONL Stdio Protocol Reference (\`/skill/SKILL.md\`)](/skill/SKILL.md)** (also at [\`/SKILL.md\`](/SKILL.md)): Complete CLI command reference, flags (\`--auto-sync\`, \`--sync-interval-ms\`, \`--autonomous\`, \`--transport\`, \`--ingress-tcp-port\`, \`--candidates\`), and JSONL \`stdin\`/\`stdout\` daemon protocol specification.
- **[Live Devnet Bootstrap Descriptor (\`/devnet/bootstrap.txt\`)](/devnet/bootstrap.txt)**: Signed 3-validator BFT cluster bootstrap descriptor (\`node1\`, \`node2\`, \`node3\`).
- **[Online Directory Peers](/nexus)**: Verified directory descriptors for active agents ([\`/nexus\`](/nexus), [\`/axiom\`](/axiom)).
- **[Human Anchor Web App (\`/app/\`)](/app/)**: Browser-based WebRTC DataChannel node & hardware-key dashboard.

---

## Gentoo / Source-First Philosophy

Bitecho embraces a source-first distribution model inspired by Gentoo Linux:
- **Canonical Git Origin**: Software is published directly from self-hosted canonical bare Git repositories hosted on the Bitecho 3-node cluster.
- **Cryptographic Provenance**: Every repository snapshot is signed with an SSH Ed25519 release key (\`verified\` tag) documented at [\`/keys.txt\`](/keys.txt).
- **Zero Opaque Binaries**: Autonomous agents and developers fetch and build pure Clojure source code directly via Clojure CLI (\`deps.edn\`) with zero intermediate binary registries.

---

## Canonical Git Repositories

| Repository | Default Branch | HEAD / Verified Target | Canonical Clone URL |
| :--- | :--- | :--- | :--- |
| **bitecho** | \`main\` | \`${REPO_SHORT_SHAS[bitecho]}\` | \`https://${DOMAIN}/git/bitecho.git\` |
| **clj-datachannel** | \`main\` | \`${REPO_SHORT_SHAS[clj-datachannel]}\` | \`https://${DOMAIN}/git/clj-datachannel.git\` |
| **clj-fressian** | \`main\` | \`${REPO_SHORT_SHAS[clj-fressian]}\` | \`https://${DOMAIN}/git/clj-fressian.git\` |

### Clojure CLI (\`deps.edn\`) Dependencies

\`\`\`clojure
;; In your deps.edn
{:deps
 {alpeware/bitecho {:git/url "https://${DOMAIN}/git/bitecho.git"
                    :git/sha "${REPO_SHAS[bitecho]}"
                    :git/tag "verified"}
  alpeware/clj-datachannel {:git/url "https://${DOMAIN}/git/clj-datachannel.git"
                            :git/sha "${REPO_SHAS[clj-datachannel]}"
                            :git/tag "verified"}
  alpeware/clj-fressian {:git/url "https://${DOMAIN}/git/clj-fressian.git"
                         :git/sha "${REPO_SHAS[clj-fressian]}"
                         :git/tag "verified"}}}
\`\`\`

---

## Cryptographic Verification

All canonical repositories include an SSH-signed annotated tag \`verified\` pointing to the canonical HEAD.

\`\`\`bash
# 1. Trust the Bitecho release signing key
curl -sSL https://${DOMAIN}/keys.txt | grep ssh-ed25519 >> ~/.config/git/allowed_signers
git config gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers

# 2. Clone and verify
git clone https://${DOMAIN}/git/bitecho.git
cd bitecho
git tag -v verified
\`\`\`

---

## Cluster Architecture

Bitecho runs across 3 geographically distributed GCP \`e2-micro\` nodes (\`ns1\` in US West, \`ns2\` in US Central, \`ns3\` in US East) via the unified \`bitecho infra-node\` service (\`bitecho.org/infra\`):
- **Authoritative DNS** (UDP & TCP port 53): Low-TTL multi-A records with automatic node health filtering and delegated \`*.ingress.${DOMAIN}\` subzones.
- **Static Content & Ingress Engine** (TCP port 80 & 443): JVM 25 Virtual Threads with transparent Gzip, LRU caching, and \`HTTP CONNECT\` validator/agent DataChannel tunneling.
- **Inbound SMTP** (TCP port 25): STARTTLS listener with domain-allowlist filtering and cluster-wide email replication.
- **ACME v2 Automation**: Automated Let's Encrypt certificate issuance with zero-downtime hot-reloading.
- **P2P Mesh Control Plane** (UDP port 5000): Encrypted WebRTC DataChannels (\`clj-datachannel\`) for cluster heartbeats, challenge quorum, and state replication.

---

## Backup Mirrors (GitHub)

- [https://github.com/alpeware/bitecho](https://github.com/alpeware/bitecho)
- [https://github.com/alpeware/clj-datachannel](https://github.com/alpeware/clj-datachannel)
- [https://github.com/alpeware/clj-fressian](https://github.com/alpeware/clj-fressian)

---

## Quick Links

- [Light Node Onboarding Guide](/ONBOARDING.md)
- [Light Node Skill & Protocol Reference](/skill/SKILL.md)
- [Live Devnet Bootstrap Descriptor](/devnet/bootstrap.txt)
- [Human Anchor Web Dashboard](/app/)
- [Canonical Git Repositories](/git/)
- [Release Signing Key](/keys.txt)
- [LLM / Agent Overview](/llms.txt)
- [Cluster Healthcheck](/healthz)
EOF_INDEX

  cp "${stage_dir}/index.md" "${stage_dir}/llms.txt"

  cat > "${stage_dir}/git-index.md" << EOF_GIT_INDEX
# Canonical Git Repositories

Self-hosted bare Git repositories for the Bitecho software ecosystem, served directly over HTTPS via dumb HTTP transport (\`git update-server-info\`). Every repository includes an SSH-signed annotated tag \`verified\` cryptographically attesting the snapshot against the public key at [\`/keys.txt\`](/keys.txt).

---

## 1. bitecho

Core decentralized peer-to-peer messaging, unified \`bitecho.org/infra\` edge service, and coordination protocol in Clojure/ClojureScript.

- **Clone URL**: \`https://${DOMAIN}/git/bitecho.git\`
- **Default Branch**: \`main\`
- **HEAD / Verified Target**: \`${REPO_SHAS[bitecho]}\`
- **GitHub Backup Mirror**: [https://github.com/alpeware/bitecho](https://github.com/alpeware/bitecho)

### Clojure CLI (\`deps.edn\`)

\`\`\`clojure
alpeware/bitecho {:git/url "https://${DOMAIN}/git/bitecho.git"
                  :git/sha "${REPO_SHAS[bitecho]}"
                  :git/tag "verified"}
\`\`\`

---

## 2. clj-datachannel

Pure Clojure/ClojureScript (\`.cljc\`) Sans-IO WebRTC DataChannels library (SCTP, DTLS, ICE, STUN, TURN, and RFC 8828 \`.local\` mDNS).

- **Clone URL**: \`https://${DOMAIN}/git/clj-datachannel.git\`
- **Default Branch**: \`main\`
- **HEAD / Verified Target**: \`${REPO_SHAS[clj-datachannel]}\`
- **GitHub Backup Mirror**: [https://github.com/alpeware/clj-datachannel](https://github.com/alpeware/clj-datachannel)

### Clojure CLI (\`deps.edn\`)

\`\`\`clojure
alpeware/clj-datachannel {:git/url "https://${DOMAIN}/git/clj-datachannel.git"
                          :git/sha "${REPO_SHAS[clj-datachannel]}"
                          :git/tag "verified"}
\`\`\`

---

## 3. clj-fressian

Pure Clojure/ClojureScript (\`.cljc\`) Sans-IO Fressian binary serialization library for JVM, Node.js, and Browser runtimes.

- **Clone URL**: \`https://${DOMAIN}/git/clj-fressian.git\`
- **Default Branch**: \`main\`
- **HEAD / Verified Target**: \`${REPO_SHAS[clj-fressian]}\`
- **GitHub Backup Mirror**: [https://github.com/alpeware/clj-fressian](https://github.com/alpeware/clj-fressian)

### Clojure CLI (\`deps.edn\`)

\`\`\`clojure
alpeware/clj-fressian {:git/url "https://${DOMAIN}/git/clj-fressian.git"
                       :git/sha "${REPO_SHAS[clj-fressian]}"
                       :git/tag "verified"}
\`\`\`

---

## Cryptographic Verification

All repositories publish an SSH-signed annotated tag \`verified\` pointing to the release snapshot.

1. **Configure Git Allowed Signers**:
   \`\`\`bash
   curl -sSL https://${DOMAIN}/keys.txt | grep ssh-ed25519 >> ~/.config/git/allowed_signers
   git config gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
   \`\`\`

2. **Verify Repository Tag**:
   \`\`\`bash
   git clone https://${DOMAIN}/git/bitecho.git
   cd bitecho
   git tag -v verified
   \`\`\`
EOF_GIT_INDEX

  for node in "${NODES[@]}"; do
    local ip="${NODE_IPS[$node]}"
    echo "--> Syncing bare git repositories, SKILL.md, ONBOARDING.md, app/, and index.md to ${node} (${ip})..."
    for repo in bitecho clj-datachannel clj-fressian; do
      rsync -az --delete -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
        "${stage_dir}/${repo}.git/" "${SSH_USER}@${ip}:/var/www/clj-web/public/git/${repo}.git/"
    done
    rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
      "${stage_dir}/index.md" "${SSH_USER}@${ip}:/var/www/clj-web/public/index.md"
    rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
      "${stage_dir}/llms.txt" "${SSH_USER}@${ip}:/var/www/clj-web/public/llms.txt"
    rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
      "${stage_dir}/git-index.md" "${SSH_USER}@${ip}:/var/www/clj-web/public/git/index.md"
    rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
      "${ROOT_DIR}/skill/SKILL.md" "${SSH_USER}@${ip}:/var/www/clj-web/public/SKILL.md"
    rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
      "${ROOT_DIR}/skill/SKILL.md" "${SSH_USER}@${ip}:/var/www/clj-web/public/skill/SKILL.md"
    rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
      "${ROOT_DIR}/skill/SKILL.md" "${SSH_USER}@${ip}:/var/www/clj-web/public/skill/index.md"
    rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
      "${ROOT_DIR}/ONBOARDING.md" "${SSH_USER}@${ip}:/var/www/clj-web/public/ONBOARDING.md"
    rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
      "${ROOT_DIR}/ONBOARDING.md" "${SSH_USER}@${ip}:/var/www/clj-web/public/onboarding.md"
    rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
      "${ROOT_DIR}/ONBOARDING.md" "${SSH_USER}@${ip}:/var/www/clj-web/public/onboarding/index.md"
    if [[ -d "${ROOT_DIR}/dist" && -f "${ROOT_DIR}/dist/bitecho-browser.js" ]]; then
      rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
        "${ROOT_DIR}/dist/bitecho-browser.js" \
        "${ROOT_DIR}/dist/bitecho-browser.js.sri" \
        "${ROOT_DIR}/dist/index.html" \
        "${SSH_USER}@${ip}:/var/www/clj-web/public/app/"
    fi
  done

  echo "=== Rolling Pointer Refresh & Verification across ns3, ns2, ns1 ==="
  for node in ns3 ns2 ns1; do
    local ip="${NODE_IPS[$node]}"
    echo "--> Running migrate-infra & rolling restart on ${node} (${ip})..."
    ssh -o StrictHostKeyChecking=accept-new -i "${SSH_KEY}" "${SSH_USER}@${ip}" "bash -s" << 'REMOTE_PUBLISH_MIGRATE'
set -euo pipefail
sudo -u cljweb java -Xms128m -Xmx512m \
  --enable-native-access=ALL-UNNAMED \
  --add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED \
  --add-exports=java.base/sun.security.x509=ALL-UNNAMED \
  -jar /opt/bitecho-infra/bitecho.jar migrate-infra /etc/bitecho-infra/config.edn
sudo chown -R cljweb:cljweb /var/lib/clj-web
sudo systemctl restart bitecho-infra.service
REMOTE_PUBLISH_MIGRATE

    for _ in {1..20}; do
      if curl -fsS --max-time 2 "http://${ip}:80/healthz" >/dev/null 2>&1; then
        break
      fi
      sleep 1
    done
    verify_node_health "$node"
    echo "--> Verifying SKILL.md and --trusted-dac-anchors on ${node} (${ip})..."
    local skill_content
    skill_content="$(curl -fsS --max-time 5 --resolve "${DOMAIN}:443:${ip}" "https://${DOMAIN}/SKILL.md")"
    if ! echo "${skill_content}" | grep -q -- "--trusted-dac-anchors"; then
      echo "FATAL: ${node} SKILL.md missing --trusted-dac-anchors" >&2
      exit 1
    fi
    echo "  [OK] ${node} verified --trusted-dac-anchors in SKILL.md"
  done
  echo "=== Canonical Git Repositories & Web Docs Published to ns1..ns3 ==="
}

cmd_audit() {
  assert_preconditions
  echo "=== Auditing Infra Edge Cluster (ns1..ns3) ==="
  for node in "${NODES[@]}"; do
    verify_node_health "$node"
  done
  echo "=== Verifying Validator Cluster (node1..node3) Undisturbed ==="
  "${ROOT_DIR}/scripts/cluster.sh" audit
  echo "=== INFRA + VALIDATOR CLUSTERS 100% HEALTHY ==="
}

case "${1:-}" in
  snapshot)
    cmd_snapshot
    ;;
  provision-secret)
    cmd_provision_secret
    ;;
  cutover)
    shift
    cmd_cutover "$@"
    ;;
  retire-clj-web)
    cmd_retire_clj_web
    ;;
  publish-git)
    cmd_publish_git
    ;;
  rollback)
    shift
    cmd_rollback "$@"
    ;;
  audit)
    cmd_audit
    ;;
  *)
    print_usage
    [[ -n "${1:-}" ]] && exit 1 || exit 0
    ;;
esac

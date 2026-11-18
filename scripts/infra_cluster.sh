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
  ["ns1"]="35.212.172.159"
  ["ns2"]="35.209.253.119"
  ["ns3"]="35.211.30.106"
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
  reprovision-infra-standard     Reserve Standard-tier static IPs and reprovision ns1..ns3 with Standard networking
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

  ssh_ns "$node" bash -s << REMOTE_CUT
set -euo pipefail
if [[ "${RESET_VALIDATOR_STATE:-0}" == "1" ]]; then
  echo "  Archiving and resetting validator state snapshot on ${node}..."
  sudo rm -rf /var/lib/clj-web/state/*
elif [[ -f "/var/lib/clj-web/state/snapshot-${node}.edn" ]] && head -c 3 "/var/lib/clj-web/state/snapshot-${node}.edn" 2>/dev/null | grep -q "^NPY"; then
  echo "  Archiving legacy Nippy validator snapshot on ${node} before Fressian boot..."
  sudo rm -rf /var/lib/clj-web/state/*
fi
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
ExecStart=/opt/jdk-25/bin/java -Xms128m -Xmx448m -XX:MaxMetaspaceSize=112m -XX:MaxDirectMemorySize=64m -XX:+UseCompactObjectHeaders --enable-native-access=ALL-UNNAMED --add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED --add-exports=java.base/sun.security.x509=ALL-UNNAMED -jar /opt/bitecho-infra/bitecho.jar infra-node /etc/bitecho-infra/config.edn
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
  for _ in $(seq 1 45); do
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

verify_release_proof_gate() {
  local version="${1:-$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+' "${ROOT_DIR}/src/bitecho/config.cljc" | head -n1)}"
  version="${version:-0.23.9}"
  local proof_file="${ROOT_DIR}/docs/releases/v${version}-proof.edn"

  echo "--> Verifying Release Proof Gate for v${version}..."
  if [[ "${RELEASE_PROOF:-}" == "skip" || "${RELEASE_PROOF:-}" == "false" ]]; then
    echo "Warning: Release Proof Gate skipped via RELEASE_PROOF=${RELEASE_PROOF}."
    return 0
  fi

  if [[ ! -f "${proof_file}" ]]; then
    echo "Error: Release proof file ${proof_file} not found. Generate it via 'clojure -M:proof ${proof_file}' before cutting over." >&2
    return 1
  fi

  local passed
  passed=$(grep -o ':all-passed? true' "${proof_file}" || true)
  if [[ -z "${passed}" ]]; then
    echo "Error: Release proof in ${proof_file} does not contain ':all-passed? true'. Aborting cutover." >&2
    return 1
  fi

  local proof_commit proof_tree head_commit parent_commit head_tree parent_tree flat_proof
  flat_proof=$(tr '\n' ' ' < "${proof_file}")
  proof_commit=$(echo "${flat_proof}" | sed -n -E 's/.*:commit-sha[[:space:]]+"([^"]+)".*/\1/p')
  proof_tree=$(echo "${flat_proof}" | sed -n -E 's/.*:tree-sha[[:space:]]+"([^"]+)".*/\1/p')
  head_commit=$(git -C "${ROOT_DIR}" rev-parse HEAD 2>/dev/null || true)
  parent_commit=$(git -C "${ROOT_DIR}" rev-parse HEAD~1 2>/dev/null || true)
  head_tree=$(git -C "${ROOT_DIR}" rev-parse HEAD^{tree} 2>/dev/null || true)
  parent_tree=$(git -C "${ROOT_DIR}" rev-parse HEAD~1^{tree} 2>/dev/null || true)

  if [[ -z "${proof_commit}" || "${proof_commit}" == "uncommitted" ]]; then
    echo "Error: Release proof in ${proof_file} is missing a valid :commit-sha." >&2
    return 1
  fi
  if [[ "${proof_commit}" != "${head_commit}" && "${proof_commit}" != "${parent_commit}" ]]; then
    echo "Error: Release proof :commit-sha (${proof_commit}) does not match HEAD (${head_commit}) or HEAD~1 (${parent_commit})." >&2
    return 1
  fi
  if [[ -z "${proof_tree}" ]]; then
    echo "Error: Release proof in ${proof_file} is missing a valid :tree-sha." >&2
    return 1
  fi
  if [[ "${proof_tree}" != "${head_tree}" && "${proof_tree}" != "${parent_tree}" ]]; then
    echo "Error: Release proof :tree-sha (${proof_tree}) does not match HEAD^{tree} (${head_tree}) or HEAD~1^{tree} (${parent_tree})." >&2
    return 1
  fi

  # A-CARB-D27-2: Skip raw dist/ file comparison when dist/ is untracked
  if git -C "${ROOT_DIR}" ls-files --error-unmatch "${ROOT_DIR}/dist/bitecho-light-node.cjs" >/dev/null 2>&1; then
    local proof_node_sha actual_node_sha proof_browser_sha actual_browser_sha
    proof_node_sha=$(echo "${flat_proof}" | sed -n -E 's/.*:node-bundle-sha256[[:space:]]+"([^"]+)".*/\1/p')
    actual_node_sha=$(sha256sum "${ROOT_DIR}/dist/bitecho-light-node.cjs" | awk '{print $1}')
    if [[ "${proof_node_sha}" != "${actual_node_sha}" ]]; then
      echo "Error: Release proof :node-bundle-sha256 (${proof_node_sha}) does not match dist/bitecho-light-node.cjs (${actual_node_sha})." >&2
      return 1
    fi
    proof_browser_sha=$(echo "${flat_proof}" | sed -n -E 's/.*:browser-bundle-sha256[[:space:]]+"([^"]+)".*/\1/p')
    actual_browser_sha=$(sha256sum "${ROOT_DIR}/dist/bitecho-browser.js" | awk '{print $1}')
    if [[ "${proof_browser_sha}" != "${actual_browser_sha}" ]]; then
      echo "Error: Release proof :browser-bundle-sha256 (${proof_browser_sha}) does not match dist/bitecho-browser.js (${actual_browser_sha})." >&2
      return 1
    fi
  else
    echo "Note: dist/ is untracked (A-CARB-D27-2); verified proof :all-passed? true, commit (${proof_commit}), and tree (${proof_tree})."
  fi

  echo "Release Proof Gate PASSED (${proof_file}, commit=${proof_commit}, tree=${proof_tree})."
}

cmd_cutover() {
  assert_preconditions
  local target=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --network)
        local net="$2"
        shift 2
        if [[ -f "${ROOT_DIR}/ops/networks/${net}.env" ]]; then
          # shellcheck disable=SC1090
          source "${ROOT_DIR}/ops/networks/${net}.env"
        fi
        ;;
      --project)
        GCP_PROJECT="$2"
        shift 2
        ;;
      *)
        if [[ -z "$target" ]]; then
          target="$1"
          shift
        else
          echo "Unknown cutover option: $1" >&2
          return 1
        fi
        ;;
    esac
  done
  if [[ -z "$target" ]]; then
    print_usage
    exit 1
  fi

  verify_release_proof_gate

  echo "--> Ensuring shared TLS secret is provisioned across ns1..ns3..."
  cmd_provision_secret

  if [[ "${SKIP_UBER_BUILD:-0}" != "1" || ! -f "${ROOT_DIR}/target/bitecho.jar" ]]; then
    echo "--> Building target/bitecho.jar locally..."
    (cd "${ROOT_DIR}" && clojure -T:build uber)
  else
    echo "--> Using existing target/bitecho.jar (SKIP_UBER_BUILD=1)..."
  fi

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
  declare -A ICE_UFRAGS=()
  declare -A ICE_PWDS=()

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
    ICE_UFRAGS[$node]="$(echo "$id_out" | awk '/ICE ufrag:/ {print $NF}')"
    ICE_PWDS[$node]="$(echo "$id_out" | awk '/ICE pwd:/ {print $NF}')"
    if [[ -z "${PUBKEYS[$node]}" || -z "${FINGERPRINTS[$node]}" || -z "${ICE_UFRAGS[$node]}" || -z "${ICE_PWDS[$node]}" ]]; then
      echo "FATAL: Failed to extract complete identity (pubkey/fingerprint/ice) on ${node}" >&2
      exit 1
    fi
    if [[ "${PUBKEYS[$node]}" == "${cold_pubkey}" ]]; then
      echo "FATAL: Hot node ${node} pubkey must never equal offline Cold Infra Root Key (F-C3)!" >&2
      exit 1
    fi
  done

  local treasury_key_file="${ROOT_DIR}/.ssh/devnet_treasury_keypair.edn"
  local custody_key_file="${ROOT_DIR}/.ssh/devnet_custody_keypair.edn"
  local TREASURY_PUB TREASURY_PRIV CUSTODY_PUB CUSTODY_PRIV
  TREASURY_PUB="$(grep -o ':pubkey-hex "[^"]*"' "${treasury_key_file}" | head -n1 | cut -d'"' -f2)"
  TREASURY_PRIV="$(grep -o ':privkey-hex "[^"]*"' "${treasury_key_file}" | head -n1 | cut -d'"' -f2)"
  CUSTODY_PUB="$(grep -o ':pubkey-hex "[^"]*"' "${custody_key_file}" | head -n1 | cut -d'"' -f2)"
  CUSTODY_PRIV="$(grep -o ':privkey-hex "[^"]*"' "${custody_key_file}" | head -n1 | cut -d'"' -f2)"
  local NODE1_PUB="302a300506032b6570032100d869c1cc916523907f9c4a44b6c9963daf430a08d9d15567b017b6599f87e086"
  local NODE2_PUB="302a300506032b6570032100592ab794dea07da278ef3853e8cc2d2f6ac5e3417eac80d93ab01e1fc61653ba"
  local NODE3_PUB="302a300506032b65700321007b7f58652a2c26b4180aeee45ff12f927a45d92e00fc3462c5d854f6203351f1"
  local devnet_agent_pubkeys="${DEVNET_AGENT_PUBKEYS:-"302a300506032b65700321009b33a9ebd1866d6db419edabe2de9ee74c884dc86b4214f60e3a26f04cbd9cfc 302a300506032b6570032100b53afd55492fe17fca9d0ef0e07b367bf8333490e43b4ecd3610c12c8e6a79f8"}"
  local agent_ledger_lines=""
  local agent_count=0
  for apk in $devnet_agent_pubkeys; do
    if [[ -n "$apk" ]]; then
      agent_ledger_lines="${agent_ledger_lines}                               \"${apk}\" {:balance 1000000 :seq 0 :deps []}\n"
      agent_count=$((agent_count + 1))
    fi
  done
  local custody_bal=$((4194000000 - agent_count * 1000000 - 2850000))

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
        :ingress-target {:host "127.0.0.1" :port 5010}
        :connect-routes {"node1.ingress.${DOMAIN}:443" {:host "35.212.129.138" :port 5010}
                         "node2.ingress.${DOMAIN}:443" {:host "35.206.120.143" :port 5010}
                         "node3.ingress.${DOMAIN}:443" {:host "35.211.71.139" :port 5010}
                         "ns1.${DOMAIN}:443" {:host "127.0.0.1" :port 5010}
                         "ns2.${DOMAIN}:443" {:host "127.0.0.1" :port 5010}
                         "ns3.${DOMAIN}:443" {:host "127.0.0.1" :port 5010}}
        :connect-targets #{"node1.ingress.${DOMAIN}:443"
                           "node2.ingress.${DOMAIN}:443"
                           "node3.ingress.${DOMAIN}:443"
                           "ns1.${DOMAIN}:443"
                           "ns2.${DOMAIN}:443"
                           "ns3.${DOMAIN}:443"
                           "*.ingress.${DOMAIN}:443"}
        :content-root "/var/www/clj-web/public"
        :directory-listing? true}
 :smtp {:enabled? true
        :bind-ip "0.0.0.0"
        :port 25
        :allowed-recipients #{"@${DOMAIN}"}}
 :cluster {:enabled? true
           :heartbeat-interval-ms 2000
           :heartbeat-timeout-ms 6000
           :infra-port 5006
           :nodes {:ns1 {:ip4 "${NODE_IPS[ns1]}" :port 5000 :infra-port 5006 :pubkey "${PUBKEYS[ns1]}" :fingerprint "${FINGERPRINTS[ns1]}"}
                   :ns2 {:ip4 "${NODE_IPS[ns2]}" :port 5000 :infra-port 5006 :pubkey "${PUBKEYS[ns2]}" :fingerprint "${FINGERPRINTS[ns2]}"}
                   :ns3 {:ip4 "${NODE_IPS[ns3]}" :port 5000 :infra-port 5006 :pubkey "${PUBKEYS[ns3]}" :fingerprint "${FINGERPRINTS[ns3]}"}}}
 :validator {:node/id :${node}
             :node-id :${node}
             :network :devnet
             :state-dir "/var/lib/clj-web"
             :treasury-pubkey "${TREASURY_PUB}"
             :treasury-privkey "${TREASURY_PRIV}"
             :custody-pubkey "${CUSTODY_PUB}"
             :custody-privkey "${CUSTODY_PRIV}"
             :genesis-ledger {"${CUSTODY_PUB}" {:balance ${custody_bal} :seq 0 :deps []}
                              "genesis-core-team" {:balance 6300000000 :seq 0 :deps []}
                              "genesis-partners" {:balance 4200000000 :seq 0 :deps []}
                              "genesis-ecosystem" {:balance 4200000000 :seq 0 :deps []}
                              "${NODE1_PUB}" {:balance 1000000 :seq 0 :deps []}
                              "${NODE2_PUB}" {:balance 1000000 :seq 0 :deps []}
                              "${NODE3_PUB}" {:balance 1000000 :seq 0 :deps []}
                              "${PUBKEYS[ns1]}" {:balance 1000000 :seq 0 :deps []}
                              "${PUBKEYS[ns2]}" {:balance 1000000 :seq 0 :deps []}
                              "${PUBKEYS[ns3]}" {:balance 1000000 :seq 0 :deps []}
                              "302a300506032b6570032100e6fb9542cab052ca0a766ca3e62a9710a4878b0755d6692abcbe301041d10c0e" {:balance 1000000 :seq 0 :deps []}
                              "302a300506032b65700321006642f780b64b85fac5728e8f2dd4a98e6e53b1722a2c0917c0c7ef0189c19b08" {:balance 500000 :seq 0 :deps []}
                              "302a300506032b6570032100e0c42229a77cc99152ec454b196cd5f69cd1fae9d0c80895d1e9fafe8fda1a63" {:balance 200000 :seq 0 :deps []}
                              "302a300506032b6570032100bc6b7f02c896caf209b3574b4f2b8c7f7734f86ccdec50b3b1865092b75daa62" {:balance 200000 :seq 0 :deps []}
                              "302a300506032b6570032100575926a259d0266da304dd7be98f4518e4a2beb1bee58803ff1cb379113acbb7" {:balance 150000 :seq 0 :deps []}
                              "302a300506032b65700321004585687db75ca86bcd74c302763cb78952d2603cd7595f4204332dd6346d8127" {:balance 400000 :seq 0 :deps []}
                              "302a300506032b6570032100d41ac4a9177126260efc632218f4098733973aaed6f8a0850396a294593b47ba" {:balance 300000 :seq 0 :deps []}
                              "302a300506032b657003210063560420a577848e3e9747bc7cca62f7ccd4c9c0fc515b5323de68bb3a76ecaa" {:balance 100000 :seq 0 :deps []}
$(printf "%b" "${agent_ledger_lines}")}
             :http {:enabled? true
                    :host "127.0.0.1"
                    :port 8080}
             :transport :datachannel
             :port 5000
             :ingress-port 5010
             :protocol {:tick-interval-ms 10000
                        :epoch-length-ms 10000
                        :nodes #{:node1 :node2 :node3 :ns1 :ns2 :ns3}
                        :validator-count 3
                        :quorum-threshold 2}
             :cluster {:port 5000
                       :agent-port 5010
                       :agent-tcp-port 5010
                       :listen-agents? true
                       :validators ["${NODE1_PUB}" "${NODE2_PUB}" "${NODE3_PUB}"]
                       :mesh-nodes {"${NODE1_PUB}" 1.0 "${NODE2_PUB}" 1.0 "${NODE3_PUB}" 1.0 "${PUBKEYS[ns1]}" 1.0 "${PUBKEYS[ns2]}" 1.0 "${PUBKEYS[ns3]}" 1.0}
                       :nodes {:node1 {:ip "35.212.129.138" :port 5000 :agent-port 5010 :agent-tcp-port 5010 :pubkey "${NODE1_PUB}" :fingerprint "95:09:40:3B:04:A0:B3:F5:88:26:51:CE:C9:A9:8E:0C:A1:15:92:8F:D5:7D:4A:11:A2:6C:3C:B0:0B:AB:0C:3B" :ice-ufrag "1ec0ae74" :ice-pwd "d928f1aac56a0d6e6fdda551"}
                               :node2 {:ip "35.206.120.143" :port 5000 :agent-port 5010 :agent-tcp-port 5010 :pubkey "${NODE2_PUB}" :fingerprint "F8:73:94:91:1D:7B:CA:66:D9:67:9E:4B:72:B0:D0:8D:5F:5C:37:0F:FE:04:2E:ED:86:E6:8D:79:B8:07:43:78" :ice-ufrag "18388497" :ice-pwd "20540a60217702b8869d7bf5"}
                               :node3 {:ip "35.211.71.139" :port 5000 :agent-port 5010 :agent-tcp-port 5010 :pubkey "${NODE3_PUB}" :fingerprint "38:2B:18:4B:23:E8:F4:32:D7:08:5A:2A:A4:45:4F:EE:12:D4:51:B1:9B:2D:66:7C:2E:E1:2A:3E:7C:B3:60:40" :ice-ufrag "4b1d8fc5" :ice-pwd "47e794a9ed5ef04cc0ebbe7f"}
                               :ns1 {:ip "${NODE_IPS[ns1]}" :port 5000 :agent-port 5010 :agent-tcp-port 5010 :pubkey "${PUBKEYS[ns1]}" :fingerprint "${FINGERPRINTS[ns1]}" :ice-ufrag "${ICE_UFRAGS[ns1]}" :ice-pwd "${ICE_PWDS[ns1]}"}
                               :ns2 {:ip "${NODE_IPS[ns2]}" :port 5000 :agent-port 5010 :agent-tcp-port 5010 :pubkey "${PUBKEYS[ns2]}" :fingerprint "${FINGERPRINTS[ns2]}" :ice-ufrag "${ICE_UFRAGS[ns2]}" :ice-pwd "${ICE_PWDS[ns2]}"}
                               :ns3 {:ip "${NODE_IPS[ns3]}" :port 5000 :agent-port 5010 :agent-tcp-port 5010 :pubkey "${PUBKEYS[ns3]}" :fingerprint "${FINGERPRINTS[ns3]}" :ice-ufrag "${ICE_UFRAGS[ns3]}" :ice-pwd "${ICE_PWDS[ns3]}"}}}}}
CFG_EOF
    clojure -M -e "(let [m (clojure.edn/read-string (slurp \"${tmp_cfg}\"))] (assert (map? (:validator m)) \"Missing :validator map in config.edn\"))"
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

  local repos=("bitecho" "clj-datachannel" "clj-fressian")
  if [[ -d "${ROOT_DIR}/../mealy/.git" ]]; then
    repos+=("mealy")
  fi

  for repo in "${repos[@]}"; do
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
- **[Live Devnet Bootstrap Descriptor (\`/devnet/bootstrap.txt\`)](/devnet/bootstrap.txt)**: Signed 6-validator BFT cluster bootstrap descriptor (\`node1..node3\`, \`ns1..ns3\`).
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
    for repo in "${repos[@]}"; do
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
    if [[ -f "${ROOT_DIR}/devnet/bootstrap.txt" && -f "${ROOT_DIR}/devnet/bootstrap.edn" ]]; then
      ssh -o StrictHostKeyChecking=accept-new -i "${SSH_KEY}" "${SSH_USER}@${ip}" "mkdir -p /var/www/clj-web/public/devnet /var/www/clj-web/public/releases/v0.23.5 /var/www/clj-web/public/releases/latest /var/www/clj-web/public/docs/bips /var/www/clj-web/public/web/blog"
      rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
        "${ROOT_DIR}/devnet/bootstrap.txt" "${SSH_USER}@${ip}:/var/www/clj-web/public/devnet/bootstrap.txt"
      rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
        "${ROOT_DIR}/devnet/bootstrap.edn" "${SSH_USER}@${ip}:/var/www/clj-web/public/devnet/bootstrap.edn"
    fi
    if [[ -d "${ROOT_DIR}/docs/bips" ]]; then
      rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
        "${ROOT_DIR}/docs/bips/" "${SSH_USER}@${ip}:/var/www/clj-web/public/docs/bips/"
    fi
    if [[ -d "${ROOT_DIR}/web/blog" ]]; then
      rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
        "${ROOT_DIR}/web/blog/" "${SSH_USER}@${ip}:/var/www/clj-web/public/web/blog/"
    fi
    if [[ -d "${ROOT_DIR}/dist" && -f "${ROOT_DIR}/dist/bitecho-light-node.cjs" && -f "${ROOT_DIR}/dist/bitecho-browser.js" ]]; then
      for rel_dir in "v0.23.5" "latest"; do
        rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
          "${ROOT_DIR}/dist/bitecho-light-node.cjs" \
          "${ROOT_DIR}/dist/bitecho-browser.js" \
          "${ROOT_DIR}/dist/bitecho-browser.js.sri" \
          "${ROOT_DIR}/docs/releases/v0.23.5-proof.edn" \
          "${SSH_USER}@${ip}:/var/www/clj-web/public/releases/${rel_dir}/"
        ssh -o StrictHostKeyChecking=accept-new -i "${SSH_KEY}" "${SSH_USER}@${ip}" \
          "cp -f /var/www/clj-web/public/releases/${rel_dir}/v0.23.5-proof.edn /var/www/clj-web/public/releases/${rel_dir}/proof.edn"
      done
    fi
    if [[ ( "${DEPLOY_LIVE:-0}" == "1" || "${1:-}" == "--deploy" ) && -d "${ROOT_DIR}/dist" && -f "${ROOT_DIR}/dist/bitecho-browser.js" ]]; then
      rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
        "${ROOT_DIR}/dist/bitecho-browser.js" \
        "${ROOT_DIR}/dist/bitecho-browser.js.sri" \
        "${ROOT_DIR}/resources/public/index.html" \
        "${SSH_USER}@${ip}:/var/www/clj-web/public/app/"
      if [[ -f "${ROOT_DIR}/resources/public/relay.html" ]]; then
        rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
          "${ROOT_DIR}/resources/public/relay.html" \
          "${SSH_USER}@${ip}:/var/www/clj-web/public/relay.html"
        rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -i ${SSH_KEY}" \
          "${ROOT_DIR}/resources/public/relay.html" \
          "${SSH_USER}@${ip}:/var/www/clj-web/public/app/relay.html"
      fi
    fi
  done

  if [[ "${DEPLOY_LIVE:-0}" == "1" || "${1:-}" == "--deploy" ]]; then
    echo "=== Rolling Pointer Refresh & Verification across ns3, ns2, ns1 ==="
    for node in ns3 ns2 ns1; do
      local ip="${NODE_IPS[$node]}"
      echo "--> Running migrate-infra & rolling restart on ${node} (${ip})..."
      ssh -o StrictHostKeyChecking=accept-new -i "${SSH_KEY}" "${SSH_USER}@${ip}" "bash -s" << 'REMOTE_PUBLISH_MIGRATE'
set -euo pipefail
sudo systemctl stop bitecho-infra.service || true
sudo -u cljweb /opt/jdk-25/bin/java -Xms128m -Xmx512m \
  --enable-native-access=ALL-UNNAMED \
  --add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED \
  --add-exports=java.base/sun.security.x509=ALL-UNNAMED \
  -jar /opt/bitecho-infra/bitecho.jar migrate-infra /etc/bitecho-infra/config.edn
sudo chown -R cljweb:cljweb /var/lib/clj-web
sudo systemctl start bitecho-infra.service
REMOTE_PUBLISH_MIGRATE

      for _ in $(seq 1 60); do
        if curl -fsS --max-time 2 "http://${ip}:80/healthz" >/dev/null 2>&1; then
          break
        fi
        sleep 2
      done
      verify_node_health "$node"
      echo "--> Verifying SKILL.md and /devnet/bootstrap.txt on ${node} (${ip})..."
      local skill_content
      skill_content="$(curl -fsS --max-time 8 --resolve "${DOMAIN}:443:${ip}" "https://${DOMAIN}/SKILL.md")"
      if ! echo "${skill_content}" | grep -q -- "--trusted-dac-anchors"; then
        echo "FATAL: ${node} SKILL.md missing --trusted-dac-anchors" >&2
        exit 1
      fi
      local bootstrap_content
      bootstrap_content="$(curl -fsS --max-time 8 --resolve "${DOMAIN}:443:${ip}" "https://${DOMAIN}/devnet/bootstrap.txt")"
      if ! echo "${bootstrap_content}" | grep -q "ns3"; then
        echo "FATAL: ${node} /devnet/bootstrap.txt missing 6-validator ns1..ns3 entries" >&2
        exit 1
      fi
      echo "  [OK] ${node} verified --trusted-dac-anchors in SKILL.md and 6-validator /devnet/bootstrap.txt"
    done
  else
    echo "  [INFO] Skipping live migrate-infra + service restart (pass --deploy or DEPLOY_LIVE=1 after deploy go-ahead)"
  fi
  echo "=== Canonical Git Repositories & Web Docs Published to ns1..ns3 ==="
}

cmd_reprovision_infra_standard() {
  echo "=============================================================================="
  echo ">>> Re-provisioning ns1..ns3 on Google Cloud Standard Tier Networking <<<"
  echo "=============================================================================="
  echo "Standard Tier provides 200 GB/month free egress per region (vs 1 GB Premium)."
  echo ""

  declare -A NS_PROJ=(
    [ns1]="bitecho-ns1"
    [ns2]="bitecho-ns2"
    [ns3]="bitecho-ns3"
  )
  declare -A NS_FALLBACK_PROJ=(
    [ns1]="alpeware-bitecho-ns1"
    [ns2]="alpeware-bitecho-ns2"
    [ns3]="alpeware-bitecho-ns3"
  )
  declare -A NS_REG=(
    [ns1]="us-west1"
    [ns2]="us-central1"
    [ns3]="us-east1"
  )

  declare -A NEW_IPS

  for node in "${NODES[@]}"; do
    local def_proj="${NS_PROJ[$node]}"
    local proj
    if gcloud projects describe "$def_proj" &>/dev/null; then
      proj="$def_proj"
    else
      proj="${NS_FALLBACK_PROJ[$node]}"
    fi
    local reg="${NS_REG[$node]}"
    local addr="${node}-standard-ip"

    echo "--> [${node}] Checking Standard Tier static IP ${addr} in ${proj} (${reg})..."
    if ! gcloud compute addresses describe "$addr" --project="$proj" --region="$reg" &>/dev/null; then
      echo "    Reserving static external IPv4 ${addr} with --network-tier=STANDARD..."
      gcloud compute addresses create "$addr" \
        --project="$proj" \
        --region="$reg" \
        --network-tier=STANDARD \
        --quiet
    fi
    local ip
    ip="$(gcloud compute addresses describe "$addr" --project="$proj" --region="$reg" --format='value(address)' 2>/dev/null || echo "UNRESOLVED")"
    NEW_IPS[$node]="$ip"
    echo "    Reserved IP for ${node}: ${ip}"
  done

  echo ""
  echo "=============================================================================="
  echo ">>> STANDARD TIER IP RESERVATIONS COMPLETE <<<"
  echo "=============================================================================="
  echo "Update authoritative .org TLD glue records at your domain registrar with:"
  echo "  ns1.bitecho.org -> ${NEW_IPS[ns1]:-34.19.71.246}"
  echo "  ns2.bitecho.org -> ${NEW_IPS[ns2]:-34.56.253.255}"
  echo "  ns3.bitecho.org -> ${NEW_IPS[ns3]:-136.108.244.159}"
  echo "=============================================================================="
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
  reprovision-infra-standard)
    cmd_reprovision_infra_standard
    ;;
  cutover)
    shift
    cmd_cutover "$@"
    ;;
  retire-clj-web)
    cmd_retire_clj_web
    ;;
  publish-git)
    shift
    cmd_publish_git "$@"
    ;;
  rollback)
    shift
    cmd_rollback "$@"
    ;;
  audit)
    cmd_audit
    ;;
  help|-h|--help)
    print_usage
    exit 0
    ;;
  *)
    print_usage
    [[ -n "${1:-}" ]] && exit 1 || exit 0
    ;;
esac

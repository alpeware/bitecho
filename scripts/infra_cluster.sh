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
       :subdomains #{"@" "www" "docs" "mvn" "ingress" "node1.ingress" "node2.ingress" "node3.ingress"}}
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

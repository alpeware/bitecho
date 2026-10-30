#!/usr/bin/env bash
# ==============================================================================
# scripts/cluster.sh - Cluster management tooling for bitecho.org (Bitecho)
# Manages provisioning, bootstrap, deployment, operations, and status across
# 3 geographically distributed GCP e2-micro nodes (node1, node2, node3).
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

resolve_local_java() {
  if [[ -n "${JAVA_CMD:-}" && -x "${JAVA_CMD:-}" ]]; then
    echo "$JAVA_CMD"
  elif [[ -x "/opt/jdk-25/bin/java" ]]; then
    echo "/opt/jdk-25/bin/java"
  elif [[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME:-}/bin/java" ]]; then
    echo "${JAVA_HOME}/bin/java"
  elif command -v java >/dev/null 2>&1; then
    command -v java
  else
    echo "Error: Java runtime not found. Set JAVA_CMD or JAVA_HOME." >&2
    return 1
  fi
}

# Source local overrides if present
if [[ -f "${ROOT_DIR}/.cluster.env" ]]; then
  # shellcheck disable=SC1091
  source "${ROOT_DIR}/.cluster.env"
fi

BILLING_ACCOUNT="${BILLING_ACCOUNT:-00A760-ADD23B-93C934}"
SSH_USER="${SSH_USER:-bitecho}"
SSH_KEY_DIR="${ROOT_DIR}/.ssh"
SSH_KEY="${SSH_KEY_DIR}/bitecho_cluster_ed25519"
TREASURY_KEY_FILE="${SSH_KEY_DIR}/devnet_treasury_keypair.edn"
CUSTODY_KEY_FILE="${SSH_KEY_DIR}/devnet_custody_keypair.edn"
TICK_INTERVAL_MS="${TICK_INTERVAL_MS:-10000}"

NODES=("node1" "node2" "node3")

declare -A DEFAULT_PROJECT=(
  [node1]="bitecho-node1"
  [node2]="bitecho-node2"
  [node3]="bitecho-node3"
)

declare -A FALLBACK_PROJECT=(
  [node1]="alpeware-bitecho-node1"
  [node2]="alpeware-bitecho-node2"
  [node3]="alpeware-bitecho-node3"
)

declare -A REGION=(
  [node1]="us-west1"
  [node2]="us-central1"
  [node3]="us-east1"
)

declare -A ZONE=(
  [node1]="us-west1-b"
  [node2]="us-central1-a"
  [node3]="us-east1-b"
)

declare -A INSTANCE=(
  [node1]="bitecho-node1"
  [node2]="bitecho-node2"
  [node3]="bitecho-node3"
)

declare -A ADDRESS_NAME=(
  [node1]="bitecho-node1-ip"
  [node2]="bitecho-node2-ip"
  [node3]="bitecho-node3-ip"
)

# ------------------------------------------------------------------------------
# Helpers to resolve dynamic or configured properties
# ------------------------------------------------------------------------------

get_project() {
  local node="$1"
  local env_var="PROJECT_${node}"
  if [[ -n "${!env_var:-}" ]]; then
    echo "${!env_var}"
    return
  fi
  local def_proj="${DEFAULT_PROJECT[$node]}"
  if gcloud projects describe "$def_proj" &>/dev/null; then
    echo "$def_proj"
  else
    echo "${FALLBACK_PROJECT[$node]}"
  fi
}

get_ip() {
  local node="$1"
  local env_var="IP_${node}"
  if [[ -n "${!env_var:-}" ]]; then
    echo "${!env_var}"
    return
  fi
  local proj
  proj="$(get_project "$node")"
  local reg="${REGION[$node]}"
  local addr="${ADDRESS_NAME[$node]}"
  gcloud compute addresses describe "$addr" --project="$proj" --region="$reg" --format='value(address)' 2>/dev/null || true
}

ssh_cmd() {
  local node="$1"
  shift
  local ip
  ip="$(get_ip "$node")"
  if [[ -z "$ip" ]]; then
    echo "Error: IP address for node ${node} could not be resolved. Run 'cluster.sh init' first." >&2
    return 1
  fi
  ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR -i "${SSH_KEY}" "${SSH_USER}@${ip}" "$@"
}

ensure_firewall_rule() {
  local project="$1"
  local name="$2"
  local allow="$3"
  local ranges="$4"
  local tags="$5"
  if gcloud compute firewall-rules describe "$name" --project="$project" &>/dev/null; then
    echo "Updating firewall rule ${name} in ${project}..."
    gcloud compute firewall-rules update "$name" \
      --project="$project" \
      --allow="$allow" \
      --source-ranges="$ranges" \
      --target-tags="$tags" \
      --quiet
  else
    echo "Creating firewall rule ${name} in ${project}..."
    gcloud compute firewall-rules create "$name" \
      --project="$project" \
      --allow="$allow" \
      --source-ranges="$ranges" \
      --target-tags="$tags" \
      --quiet
  fi
}

# ------------------------------------------------------------------------------
# Subcommand: init
# ------------------------------------------------------------------------------

cmd_init() {
  echo "=== Initializing 3-Node Bitecho Devnet Cluster ==="

  # 1. SSH key generation
  echo "--> Ensuring cluster SSH key at ${SSH_KEY}..."
  mkdir -p "${SSH_KEY_DIR}"
  chmod 700 "${SSH_KEY_DIR}"
  if [[ ! -f "${SSH_KEY}" ]]; then
    ssh-keygen -t ed25519 -N "" -C "${SSH_USER}@bitecho.org" -f "${SSH_KEY}"
  fi
  chmod 600 "${SSH_KEY}"
  chmod 644 "${SSH_KEY}.pub"
  local ssh_pub
  ssh_pub="$(cat "${SSH_KEY}.pub")"
  local ssh_meta="${SSH_USER}:${ssh_pub}"

  # 2. Resolve/create projects, link billing, enable compute
  declare -A RESOLVED_PROJECTS=()
  for node in "${NODES[@]}"; do
    local def_proj="${DEFAULT_PROJECT[$node]}"
    local fb_proj="${FALLBACK_PROJECT[$node]}"
    local target_proj="$def_proj"

    echo "--> Resolving GCP project for ${node}..."
    if ! gcloud projects describe "$target_proj" &>/dev/null; then
      echo "Project ${target_proj} does not exist or is not accessible. Attempting to create..."
      if ! gcloud projects create "$target_proj" --name="$target_proj" --quiet &>/dev/null; then
        echo "Could not create ${target_proj}; attempting fallback project ${fb_proj}..."
        target_proj="$fb_proj"
        if ! gcloud projects describe "$target_proj" &>/dev/null; then
          gcloud projects create "$target_proj" --name="$target_proj" --quiet
        fi
      fi
    fi
    RESOLVED_PROJECTS[$node]="$target_proj"
    echo "Using project ${target_proj} for ${node}."

    echo "Linking billing account ${BILLING_ACCOUNT} to ${target_proj}..."
    gcloud billing projects link "$target_proj" --billing-account="${BILLING_ACCOUNT}" --quiet || true

    echo "Enabling compute.googleapis.com on ${target_proj}..."
    gcloud services enable compute.googleapis.com --project="$target_proj" --quiet
  done

  # 3. Reserve regional static external IPv4 addresses
  declare -A RESOLVED_IPS=()
  for node in "${NODES[@]}"; do
    local proj="${RESOLVED_PROJECTS[$node]}"
    local reg="${REGION[$node]}"
    local addr="${ADDRESS_NAME[$node]}"

    echo "--> Checking static external IPv4 ${addr} in ${proj} (${reg})..."
    if ! gcloud compute addresses describe "$addr" --project="$proj" --region="$reg" &>/dev/null; then
      echo "Reserving static external IPv4 ${addr} in ${proj} (${reg})..."
      gcloud compute addresses create "$addr" --project="$proj" --region="$reg" --network-tier=STANDARD --quiet
    fi
    local ip
    ip="$(gcloud compute addresses describe "$addr" --project="$proj" --region="$reg" --format='value(address)')"
    RESOLVED_IPS[$node]="$ip"
    echo "Static IP for ${node}: ${ip}"
  done

  local ip1="${RESOLVED_IPS[node1]}"
  local ip2="${RESOLVED_IPS[node2]}"
  local ip3="${RESOLVED_IPS[node3]}"
  local cluster_ranges="${ip1}/32,${ip2}/32,${ip3}/32"

  # 4. Create/update firewall rules in each project
  for node in "${NODES[@]}"; do
    local proj="${RESOLVED_PROJECTS[$node]}"
    echo "--> Configuring firewall rules in ${proj}..."
    ensure_firewall_rule "$proj" "bitecho-ssh" "tcp:22" "0.0.0.0/0" "bitecho"
    ensure_firewall_rule "$proj" "bitecho-cluster" "udp:5000-5005" "$cluster_ranges" "bitecho"
    ensure_firewall_rule "$proj" "bitecho-agent" "udp:5010" "0.0.0.0/0" "bitecho"
  done

  # 5. Create e2-micro VM instances
  for node in "${NODES[@]}"; do
    local proj="${RESOLVED_PROJECTS[$node]}"
    local z="${ZONE[$node]}"
    local inst="${INSTANCE[$node]}"
    local ip="${RESOLVED_IPS[$node]}"

    echo "--> Checking VM instance ${inst} in ${proj} (${z})..."
    if ! gcloud compute instances describe "$inst" --project="$proj" --zone="$z" &>/dev/null; then
      echo "Creating VM instance ${inst}..."
      gcloud compute instances create "$inst" \
        --project="$proj" \
        --zone="$z" \
        --machine-type=e2-micro \
        --network-tier=STANDARD \
        --image-family=debian-12 \
        --image-project=debian-cloud \
        --boot-disk-size=30GB \
        --boot-disk-type=pd-standard \
        --address="$ip" \
        --tags=bitecho \
        --metadata="ssh-keys=${ssh_meta},block-project-ssh-keys=TRUE" \
        --quiet
    else
      echo "VM ${inst} exists; ensuring SSH metadata is configured..."
      gcloud compute instances add-metadata "$inst" \
        --project="$proj" \
        --zone="$z" \
        --metadata="ssh-keys=${ssh_meta},block-project-ssh-keys=TRUE" \
        --quiet
    fi
  done

  # 6. Wait for SSH readiness and run remote bootstrap
  for node in "${NODES[@]}"; do
    local ip="${RESOLVED_IPS[$node]}"
    echo "--> Waiting for SSH readiness on ${node} (${ip})..."
    local retries=30
    while (( retries > 0 )); do
      if ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=5 -o LogLevel=ERROR -i "${SSH_KEY}" "${SSH_USER}@${ip}" "echo ssh-ok" &>/dev/null; then
        break
      fi
      sleep 5
      (( retries-- ))
    done
    if (( retries == 0 )); then
      echo "Error: SSH connection to ${node} (${ip}) timed out." >&2
      return 1
    fi

    echo "--> Running remote bootstrap script on ${node} (${ip})..."
    ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o LogLevel=ERROR -i "${SSH_KEY}" "${SSH_USER}@${ip}" bash -s << 'REMOTE_BOOTSTRAP'
set -euo pipefail

# 1. Swapfile (1GB)
if ! swapon --show | grep -q '/swapfile'; then
  echo "Configuring 1GB /swapfile..."
  sudo fallocate -l 1G /swapfile || sudo dd if=/dev/zero of=/swapfile bs=1M count=1024
  sudo chmod 600 /swapfile
  sudo mkswap /swapfile
  sudo swapon /swapfile
  if ! grep -q '/swapfile' /etc/fstab; then
    echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
  fi
fi

# 2. Package dependencies
echo "Installing prerequisites via apt..."
sudo apt-get update -y
sudo apt-get install -y --no-install-recommends curl ca-certificates rsync

# 3. OpenJDK 25
if [ ! -x /opt/jdk-25/bin/java ]; then
  echo "Installing OpenJDK 25 into /opt/jdk-25..."
  sudo mkdir -p /opt/jdk-25
  TMP_JDK="$(mktemp /tmp/jdk25-XXXXXX.tar.gz)"
  curl -fsSL -o "$TMP_JDK" "https://api.adoptium.net/v3/binary/latest/25/ga/linux/x64/jdk/hotspot/normal/eclipse"
  sudo tar -xzf "$TMP_JDK" -C /opt/jdk-25 --strip-components=1
  rm -f "$TMP_JDK"
fi

# 4. Log rotation (journald)
sudo mkdir -p /etc/systemd/journald.conf.d
cat << 'JOURNALD_CFG' | sudo tee /etc/systemd/journald.conf.d/size-limit.conf > /dev/null
[Journal]
SystemMaxUse=100M
MaxFileSec=7day
JOURNALD_CFG
sudo systemctl restart systemd-journald || true

# 5. App directories
echo "Creating application directories..."
sudo mkdir -p /opt/bitecho /etc/bitecho /var/lib/bitecho
sudo chown -R "$(id -un):$(id -gn)" /opt/bitecho /etc/bitecho /var/lib/bitecho

# 6. systemd unit file
echo "Writing /etc/systemd/system/bitecho.service..."
cat << 'UNIT' | sudo tee /etc/systemd/system/bitecho.service > /dev/null
[Unit]
Description=Bitecho Full Node & Streamlet Validator
After=network.target

[Service]
Type=simple
User=bitecho
LimitNOFILE=65536
Restart=always
RestartSec=3
ExecStart=/opt/jdk-25/bin/java \
  -Xms256m -Xmx512m -XX:MaxMetaspaceSize=96m -XX:MaxDirectMemorySize=64m \
  -XX:+UseCompactObjectHeaders -XX:+UseZGC \
  --enable-native-access=ALL-UNNAMED \
  --add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED \
  --add-exports=java.base/sun.security.x509=ALL-UNNAMED \
  -jar /opt/bitecho/bitecho.jar run /etc/bitecho/config.edn

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
REMOTE_BOOTSTRAP
  done

  # 7. Save state to .cluster.env and cluster.edn
  echo "--> Saving cluster state to .cluster.env and cluster.edn..."
  cat > "${ROOT_DIR}/.cluster.env" << ENV_EOF
# Auto-generated by cluster.sh init on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
BILLING_ACCOUNT="${BILLING_ACCOUNT}"
SSH_USER="${SSH_USER}"
PROJECT_node1="${RESOLVED_PROJECTS[node1]}"
IP_node1="${ip1}"
PROJECT_node2="${RESOLVED_PROJECTS[node2]}"
IP_node2="${ip2}"
PROJECT_node3="${RESOLVED_PROJECTS[node3]}"
IP_node3="${ip3}"
ENV_EOF

  cat > "${ROOT_DIR}/cluster.edn" << EDN_EOF
;; Auto-generated by cluster.sh init on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
{:cluster {:nodes {:node1 {:project "${RESOLVED_PROJECTS[node1]}" :region "${REGION[node1]}" :zone "${ZONE[node1]}" :ip "${ip1}"}
                   :node2 {:project "${RESOLVED_PROJECTS[node2]}" :region "${REGION[node2]}" :zone "${ZONE[node2]}" :ip "${ip2}"}
                   :node3 {:project "${RESOLVED_PROJECTS[node3]}" :region "${REGION[node3]}" :zone "${ZONE[node3]}" :ip "${ip3}"}}}}
EDN_EOF
  chmod 600 "${ROOT_DIR}/.cluster.env" "${ROOT_DIR}/cluster.edn"

  echo ""
  echo "================================================================================"
  echo "Cluster initialization complete! Run './scripts/cluster.sh deploy' to deploy."
  echo "================================================================================"
}

# ------------------------------------------------------------------------------
# Subcommand: deploy
# ------------------------------------------------------------------------------

cmd_deploy() {
  local reset_state=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --reset-state)
        reset_state=true
        shift
        ;;
      *)
        echo "Unknown deploy option: $1" >&2
        return 1
        ;;
    esac
  done

  echo "=== Deploying Bitecho Devnet to 3-Node Cluster ==="

  # 1. Build local uberjar
  echo "--> Step 1/7: Building target/bitecho.jar locally..."
  (cd "${ROOT_DIR}" && clojure -T:build uber)

  # Check that IPs are available
  local ip1 ip2 ip3
  ip1="$(get_ip node1)"
  ip2="$(get_ip node2)"
  ip3="$(get_ip node3)"
  if [[ -z "$ip1" || -z "$ip2" || -z "$ip3" ]]; then
    echo "Error: Node static IPs could not be resolved. Ensure 'cluster.sh init' was run." >&2
    return 1
  fi

  # 2. Ensure Devnet Treasury & Custody keypairs exist locally
  echo "--> Step 2/7: Ensuring Treasury and Custody Ed25519 keypairs..."
  mkdir -p "${SSH_KEY_DIR}"
  local local_java
  local_java="$(resolve_local_java)"
  if [[ ! -f "${TREASURY_KEY_FILE}" ]]; then
    echo "Generating Devnet Treasury keypair at ${TREASURY_KEY_FILE}..."
    "$local_java" --enable-native-access=ALL-UNNAMED \
         --add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED \
         --add-exports=java.base/sun.security.x509=ALL-UNNAMED \
         -jar "${ROOT_DIR}/target/bitecho.jar" gen-keypair "${TREASURY_KEY_FILE}" >/dev/null
  fi
  if [[ ! -f "${CUSTODY_KEY_FILE}" ]]; then
    echo "Generating Devnet Custody keypair at ${CUSTODY_KEY_FILE}..."
    "$local_java" --enable-native-access=ALL-UNNAMED \
         --add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED \
         --add-exports=java.base/sun.security.x509=ALL-UNNAMED \
         -jar "${ROOT_DIR}/target/bitecho.jar" gen-keypair "${CUSTODY_KEY_FILE}" >/dev/null
  fi

  chmod 600 "${TREASURY_KEY_FILE}" "${CUSTODY_KEY_FILE}"

  local TREASURY_PUB TREASURY_PRIV CUSTODY_PUB CUSTODY_PRIV
  TREASURY_PUB="$(grep -o ':pubkey-hex "[^"]*"' "${TREASURY_KEY_FILE}" | head -n1 | cut -d'"' -f2)"
  TREASURY_PRIV="$(grep -o ':privkey-hex "[^"]*"' "${TREASURY_KEY_FILE}" | head -n1 | cut -d'"' -f2)"
  CUSTODY_PUB="$(grep -o ':pubkey-hex "[^"]*"' "${CUSTODY_KEY_FILE}" | head -n1 | cut -d'"' -f2)"
  CUSTODY_PRIV="$(grep -o ':privkey-hex "[^"]*"' "${CUSTODY_KEY_FILE}" | head -n1 | cut -d'"' -f2)"

  if [[ -z "${TREASURY_PUB:-}" || ! "${TREASURY_PUB}" =~ ^[0-9a-fA-F]{88}$ ]]; then
    echo "Error: Invalid or missing Treasury public key in ${TREASURY_KEY_FILE} (must be 88-char hex)." >&2
    return 1
  fi
  if [[ -z "${TREASURY_PRIV:-}" || ! "${TREASURY_PRIV}" =~ ^[0-9a-fA-F]{96}$ ]]; then
    echo "Error: Invalid or missing Treasury private key in ${TREASURY_KEY_FILE} (must be 96-char hex)." >&2
    return 1
  fi
  if [[ -z "${CUSTODY_PUB:-}" || ! "${CUSTODY_PUB}" =~ ^[0-9a-fA-F]{88}$ ]]; then
    echo "Error: Invalid or missing Custody public key in ${CUSTODY_KEY_FILE} (must be 88-char hex)." >&2
    return 1
  fi
  if [[ -z "${CUSTODY_PRIV:-}" || ! "${CUSTODY_PRIV}" =~ ^[0-9a-fA-F]{96}$ ]]; then
    echo "Error: Invalid or missing Custody private key in ${CUSTODY_KEY_FILE} (must be 96-char hex)." >&2
    return 1
  fi

  echo "Treasury Pubkey: ${TREASURY_PUB}"
  echo "Custody Pubkey:  ${CUSTODY_PUB}"

  # 3. Upload uberjar to all 3 VMs
  echo "--> Step 3/7: Uploading uberjar to all nodes via rsync..."
  for node in "${NODES[@]}"; do
    local ip
    ip="$(get_ip "$node")"
    echo "Uploading to ${node} (${ip})..."
    rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR -i ${SSH_KEY}" \
      "${ROOT_DIR}/target/bitecho.jar" "${SSH_USER}@${ip}:/opt/bitecho/bitecho.jar"
  done

  # 4. Fetch persistent node identities
  echo "--> Step 4/7: Fetching persistent node identities from all nodes..."
  declare -A PUBKEY=()
  declare -A FINGERPRINT=()
  declare -A ICE_UFRAG=()
  declare -A ICE_PWD=()

  for node in "${NODES[@]}"; do
    local ip
    ip="$(get_ip "$node")"
    echo "Fetching identity on ${node} (${ip})..."
    local id_out
    id_out="$(ssh_cmd "$node" bash -s << REMOTE_ID
set -euo pipefail
CFG_FILE="/etc/bitecho/config.edn"
if [ ! -f "\$CFG_FILE" ]; then
  TMP_CFG="/tmp/bootstrap-config.edn"
  echo "{:node/id :${node} :state-dir \"/var/lib/bitecho\"}" > "\$TMP_CFG"
  CFG_FILE="\$TMP_CFG"
fi
/opt/jdk-25/bin/java \
  -Xms128m -Xmx256m \
  --enable-native-access=ALL-UNNAMED \
  --add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED \
  --add-exports=java.base/sun.security.x509=ALL-UNNAMED \
  -jar /opt/bitecho/bitecho.jar print-identity "\$CFG_FILE"
rm -f /tmp/bootstrap-config.edn
REMOTE_ID
)"
    PUBKEY[$node]="$(echo "$id_out" | grep '^Ed25519 Pubkey:' | awk '{print $NF}')"
    FINGERPRINT[$node]="$(echo "$id_out" | grep '^SHA-256 Fingerprint:' | awk '{print $NF}')"
    ICE_UFRAG[$node]="$(echo "$id_out" | grep '^ICE ufrag:' | awk '{print $NF}')"
    ICE_PWD[$node]="$(echo "$id_out" | grep '^ICE pwd:' | awk '{print $NF}')"

    if [[ -z "${PUBKEY[$node]}" || -z "${FINGERPRINT[$node]}" || -z "${ICE_UFRAG[$node]}" || -z "${ICE_PWD[$node]}" ]]; then
      echo "Error: Failed to obtain complete node identity for ${node}." >&2
      echo "Raw output:" >&2
      echo "$id_out" >&2
      return 1
    fi
    echo "${node}: Pubkey=${PUBKEY[$node]:0:16}... FP=${FINGERPRINT[$node]:0:17}... ufrag=${ICE_UFRAG[$node]}"
  done

  # 5. Render and upload per-node config.edn
  echo "--> Step 5/7: Rendering and uploading /etc/bitecho/config.edn..."
  for node in "${NODES[@]}"; do
    local ip
    ip="$(get_ip "$node")"
    echo "Rendering config for ${node} (${ip})..."
    local tmp_cfg
    tmp_cfg="$(mktemp /tmp/config-${node}-XXXXXX.edn)"
    cat > "$tmp_cfg" << CFG_EOF
;; =========================================================================
;; /etc/bitecho/config.edn for ${node}
;;
;; DEVNET TRUST MODEL NOTICE:
;; In Devnet, treasury and custody private keys are distributed to validator
;; nodes to allow automated signing of epoch mints and custody drawdown during
;; testing. In Mainnet, treasury and custody private keys are strictly cold
;; storage keys held offline by governance signers and NEVER deployed to nodes.
;; =========================================================================
{:node/id :${node}
 :network :devnet
 :state-dir "/var/lib/bitecho"
 :treasury-pubkey "${TREASURY_PUB}"
 :treasury-privkey "${TREASURY_PRIV}"
 :custody-pubkey "${CUSTODY_PUB}"
 :custody-privkey "${CUSTODY_PRIV}"
 :genesis-ledger {"${CUSTODY_PUB}" {:balance 4197000000 :seq 0 :deps []}
                  "genesis-core-team" {:balance 6300000000 :seq 0 :deps []}
                  "genesis-partners" {:balance 4200000000 :seq 0 :deps []}
                  "genesis-ecosystem" {:balance 4200000000 :seq 0 :deps []}
                  "${PUBKEY[node1]}" {:balance 1000000 :seq 0 :deps []}
                  "${PUBKEY[node2]}" {:balance 1000000 :seq 0 :deps []}
                  "${PUBKEY[node3]}" {:balance 1000000 :seq 0 :deps []}}
 :protocol {:tick-interval-ms ${TICK_INTERVAL_MS}
            :epoch-length-ms ${TICK_INTERVAL_MS}}
 :http {:enabled? true
        :host "127.0.0.1"
        :port 8080}
 :cluster {:port 5000
           :agent-port 5010
           :listen-agents? ${LISTEN_AGENTS:-false}
           :validators ["${PUBKEY[node1]}" "${PUBKEY[node2]}" "${PUBKEY[node3]}"]
           :nodes {:node1 {:ip "${ip1}" :port 5000 :agent-port 5010 :pubkey "${PUBKEY[node1]}" :fingerprint "${FINGERPRINT[node1]}" :ice-ufrag "${ICE_UFRAG[node1]}" :ice-pwd "${ICE_PWD[node1]}"}
                   :node2 {:ip "${ip2}" :port 5000 :agent-port 5010 :pubkey "${PUBKEY[node2]}" :fingerprint "${FINGERPRINT[node2]}" :ice-ufrag "${ICE_UFRAG[node2]}" :ice-pwd "${ICE_PWD[node2]}"}
                   :node3 {:ip "${ip3}" :port 5000 :agent-port 5010 :pubkey "${PUBKEY[node3]}" :fingerprint "${FINGERPRINT[node3]}" :ice-ufrag "${ICE_UFRAG[node3]}" :ice-pwd "${ICE_PWD[node3]}"}}}}
CFG_EOF

    chmod 600 "$tmp_cfg"
    echo "Validating config locally for ${node}..."
    "$local_java" -jar "${ROOT_DIR}/target/bitecho.jar" validate-config "$tmp_cfg"

    rsync -az -e "ssh -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR -i ${SSH_KEY}" \
      "$tmp_cfg" "${SSH_USER}@${ip}:/etc/bitecho/config.edn.new"
    rm -f "$tmp_cfg"

    ssh_cmd "$node" bash -s << REMOTE_CFG
set -euo pipefail
chmod 600 /etc/bitecho/config.edn.new
/opt/jdk-25/bin/java \
  --enable-native-access=ALL-UNNAMED \
  --add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED \
  --add-exports=java.base/sun.security.x509=ALL-UNNAMED \
  -jar /opt/bitecho/bitecho.jar validate-config /etc/bitecho/config.edn.new
if [ "${reset_state}" = "true" ]; then
  echo "Resetting node state on ${node}..."
  rm -rf /var/lib/bitecho/state/*
fi
mv -f /etc/bitecho/config.edn.new /etc/bitecho/config.edn
REMOTE_CFG
  done

  # 6. Generate local devnet/bootstrap descriptors
  echo "--> Step 6/7: Generating local devnet/bootstrap.edn and devnet/bootstrap.txt..."
  mkdir -p "${ROOT_DIR}/devnet"
  chmod 700 "${ROOT_DIR}/devnet"

  cat > "${ROOT_DIR}/devnet/bootstrap.edn" << EDN_BOOTSTRAP_EOF
;; Auto-generated by scripts/cluster.sh deploy on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
{:network :devnet
 :treasury-pubkey "${TREASURY_PUB}"
 :custody-pubkey "${CUSTODY_PUB}"
 :nodes {:node1 {:ip "${ip1}" :port 5000 :agent-port 5010 :pubkey "${PUBKEY[node1]}" :fingerprint "${FINGERPRINT[node1]}" :ice-ufrag "${ICE_UFRAG[node1]}" :ice-pwd "${ICE_PWD[node1]}"}
         :node2 {:ip "${ip2}" :port 5000 :agent-port 5010 :pubkey "${PUBKEY[node2]}" :fingerprint "${FINGERPRINT[node2]}" :ice-ufrag "${ICE_UFRAG[node2]}" :ice-pwd "${ICE_PWD[node2]}"}
         :node3 {:ip "${ip3}" :port 5000 :agent-port 5010 :pubkey "${PUBKEY[node3]}" :fingerprint "${FINGERPRINT[node3]}" :ice-ufrag "${ICE_UFRAG[node3]}" :ice-pwd "${ICE_PWD[node3]}"}}}
EDN_BOOTSTRAP_EOF

  cat > "${ROOT_DIR}/devnet/bootstrap.txt" << TXT_BOOTSTRAP_EOF
================================================================================
Bitecho Genesis Devnet - Bootstrap Peer & WebRTC Connection Descriptor
Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
================================================================================

Network: devnet (3-node Streamlet BFT validator quorum, N=3, quorum=2 of 3)
Treasury Public Key: ${TREASURY_PUB}
Custody Public Key:  ${CUSTODY_PUB}

Bootstrap Validators:
--------------------------------------------------------------------------------
Node: node1 (us-west1)
  Cluster Address:   ${ip1}:5000 (UDP DataChannel)
  Agent Ingress:     ${ip1}:5010 (UDP DataChannel)
  HTTP Diagnostics:  http://127.0.0.1:8080/healthz, /statusz (bound to localhost)
  Ed25519 Pubkey:    ${PUBKEY[node1]}
  DTLS Fingerprint:  ${FINGERPRINT[node1]}
  ICE Credentials:   ufrag=${ICE_UFRAG[node1]} pwd=${ICE_PWD[node1]}

Node: node2 (us-central1)
  Cluster Address:   ${ip2}:5000 (UDP DataChannel)
  Agent Ingress:     ${ip2}:5010 (UDP DataChannel)
  HTTP Diagnostics:  http://127.0.0.1:8080/healthz, /statusz (bound to localhost)
  Ed25519 Pubkey:    ${PUBKEY[node2]}
  DTLS Fingerprint:  ${FINGERPRINT[node2]}
  ICE Credentials:   ufrag=${ICE_UFRAG[node2]} pwd=${ICE_PWD[node2]}

Node: node3 (us-east1)
  Cluster Address:   ${ip3}:5000 (UDP DataChannel)
  Agent Ingress:     ${ip3}:5010 (UDP DataChannel)
  HTTP Diagnostics:  http://127.0.0.1:8080/healthz, /statusz (bound to localhost)
  Ed25519 Pubkey:    ${PUBKEY[node3]}
  DTLS Fingerprint:  ${FINGERPRINT[node3]}
  ICE Credentials:   ufrag=${ICE_UFRAG[node3]} pwd=${ICE_PWD[node3]}

Connection Instructions for Agents / Light Nodes:
Agent Ingress (UDP port 5010) is disabled by default (:listen-agents? false).
When enabled on a node, agents connect over WebRTC DataChannel (UDP port 5010)
with channel name "bitecho", authenticating via the server's SHA-256 fingerprint
and ICE credentials above. All inbound agent events MUST be wrapped in an
Ed25519-signed envelope via wrap-agent-event.
TXT_BOOTSTRAP_EOF

  chmod 600 "${ROOT_DIR}/devnet/bootstrap.edn" "${ROOT_DIR}/devnet/bootstrap.txt"

  # 7. Restart bitecho.service and poll healthz
  echo "--> Step 7/7: Restarting bitecho.service and verifying healthz..."
  local deploy_failed=false
  for node in "${NODES[@]}"; do
    local ip
    ip="$(get_ip "$node")"
    echo "Restarting service on ${node} (${ip})..."
    ssh_cmd "$node" sudo systemctl restart bitecho.service

    echo "Polling healthz on ${node}..."
    local ok=false
    for _ in {1..30}; do
      local resp
      resp="$(ssh_cmd "$node" curl -fsSL --max-time 2 http://127.0.0.1:8080/healthz 2>/dev/null || true)"
      if [[ "$resp" == *"ok"* ]]; then
        ok=true
        break
      fi
      sleep 1
    done

    if [[ "$ok" == true ]]; then
      echo "${node} is healthy (healthz ok)."
    else
      echo "Error: ${node} health check timed out. Inspecting journal..." >&2
      ssh_cmd "$node" sudo journalctl -u bitecho -n 20 --no-pager || true
      deploy_failed=true
    fi
  done

  if [[ "$deploy_failed" == true ]]; then
    echo "Error: Devnet deployment failed because one or more nodes failed health checks." >&2
    return 1
  fi

  echo ""
  echo "================================================================================"
  echo "Bitecho Devnet deployment complete! Run './scripts/cluster.sh status' to inspect."
  echo "================================================================================"
}

# ------------------------------------------------------------------------------
# Subcommand: status
# ------------------------------------------------------------------------------

cmd_status() {
  echo "=== 3-Node Bitecho Devnet Cluster Status ==="
  printf "%-6s %-16s %-10s %-12s %-16s %-12s %-6s %-12s %-8s %s\n" \
    "Node" "IP" "State" "Memory" "Disk" "Egress(NIC)" "Epoch" "Blocks(N/F)" "Peers" "Supply / Minted / Burns"
  printf "%-6s %-16s %-10s %-12s %-16s %-12s %-6s %-12s %-8s %s\n" \
    "------" "----------------" "----------" "------------" "----------------" "------------" "------" "------------" "--------" "-----------------------"

  for node in "${NODES[@]}"; do
    local ip vm_state state mem_usage disk_usage egress_nic epoch blocks peers tokenomics
    ip="$(get_ip "$node")"
    if [[ -z "$ip" ]]; then
      ip="UNRESOLVED"
      state="UNKNOWN"
      mem_usage="N/A"
      disk_usage="N/A"
      egress_nic="N/A"
      epoch="N/A"
      blocks="N/A"
      peers="N/A"
      tokenomics="N/A"
    else
      local proj
      proj="$(get_project "$node")"
      vm_state="$(gcloud compute instances describe "${INSTANCE[$node]}" --project="$proj" --zone="${ZONE[$node]}" --format='value(status)' 2>/dev/null || echo "UNKNOWN")"
      if [[ "$vm_state" == "RUNNING" ]]; then
        local raw_metrics
        raw_metrics="$(ssh_cmd "$node" bash -s << 'REMOTE_STATUS' 2>/dev/null || echo "SSH_FAILED"
set -o pipefail
svc=$(systemctl is-active bitecho 2>/dev/null || echo "inactive")
mem=$(free -m 2>/dev/null | awk '/Mem:/ {print $3 "/" $2 "M"}' || echo "N/A")
disk=$(df -h / 2>/dev/null | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}' || echo "N/A")
dev=$(ip -o -4 route show to default 2>/dev/null | awk '{print $5}' | head -n1)
dev=${dev:-ens4}
nic_raw=$(cat /sys/class/net/"$dev"/statistics/tx_bytes 2>/dev/null || echo 0)
statusz=$(curl -fsSL --max-time 2 http://127.0.0.1:8080/statusz 2>/dev/null || true)

echo "${svc}|${mem}|${disk}|${nic_raw}|${statusz}"
REMOTE_STATUS
)"
        if [[ -z "$raw_metrics" || "$raw_metrics" == "SSH_FAILED" ]]; then
          state="UNREACHABLE"
          mem_usage="N/A"
          disk_usage="N/A"
          egress_nic="N/A"
          epoch="N/A"
          blocks="N/A"
          peers="N/A"
          tokenomics="N/A"
        else
          local raw_svc raw_mem raw_disk raw_nic raw_statusz
          IFS='|' read -r raw_svc raw_mem raw_disk raw_nic raw_statusz <<< "$raw_metrics"
          state="${raw_svc:-inactive}"
          mem_usage="${raw_mem:-N/A}"
          disk_usage="${raw_disk:-N/A}"

          # Format NIC egress in MB
          if [[ "$raw_nic" =~ ^[0-9]+$ ]]; then
            egress_nic="$(awk -v b="$raw_nic" 'BEGIN {printf "%.1fMB", b/(1024*1024)}')"
          else
            egress_nic="N/A"
          fi

          # Parse statusz line:
          # role=validator epoch=1 head=genesis notarized=0 finalized=0 peers=2/2 supply=18900000000 minted=0 burns=0
          local r_role="" r_epoch="" r_notarized="" r_finalized="" r_peers="" r_supply="" r_minted="" r_burns=""
          for kv in $raw_statusz; do
            case "$kv" in
              role=*) r_role="${kv#role=}" ;;
              epoch=*) r_epoch="${kv#epoch=}" ;;
              notarized=*) r_notarized="${kv#notarized=}" ;;
              finalized=*) r_finalized="${kv#finalized=}" ;;
              peers=*) r_peers="${kv#peers=}" ;;
              supply=*) r_supply="${kv#supply=}" ;;
              minted=*) r_minted="${kv#minted=}" ;;
              burns=*) r_burns="${kv#burns=}" ;;
            esac
          done

          epoch="${r_epoch:-0}"
          blocks="${r_notarized:-0}/${r_finalized:-0}"
          peers="${r_peers:-0/0}"
          if [[ -n "$r_supply" ]]; then
            tokenomics="${r_supply} / ${r_minted:-0} / ${r_burns:-0}"
          else
            tokenomics="N/A"
          fi
        fi
      else
        state="${vm_state:-OFFLINE}"
        mem_usage="N/A"
        disk_usage="N/A"
        egress_nic="N/A"
        epoch="N/A"
        blocks="N/A"
        peers="N/A"
        tokenomics="N/A"
      fi
    fi

    printf "%-6s %-16s %-10s %-12s %-16s %-12s %-6s %-12s %-8s %s\n" \
      "$node" "$ip" "$state" "$mem_usage" "$disk_usage" "$egress_nic" "$epoch" "$blocks" "$peers" "$tokenomics"
  done
}

# ------------------------------------------------------------------------------
# Subcommand: logs
# ------------------------------------------------------------------------------

cmd_logs() {
  local node="${1:-node1}"
  local lines="${2:-100}"
  echo "Streaming logs for bitecho on ${node}..."
  ssh_cmd "$node" sudo journalctl -u bitecho -n "$lines" -f
}

# ------------------------------------------------------------------------------
# Subcommand: bootstrap_sdp
# ------------------------------------------------------------------------------

cmd_bootstrap_sdp() {
  if [[ -f "${ROOT_DIR}/devnet/bootstrap.txt" ]]; then
    cat "${ROOT_DIR}/devnet/bootstrap.txt"
  elif [[ -f "${ROOT_DIR}/devnet/bootstrap.edn" ]]; then
    cat "${ROOT_DIR}/devnet/bootstrap.edn"
  else
    echo "Bootstrap descriptors not yet generated. Run './scripts/cluster.sh deploy' first." >&2
    return 1
  fi
}

# ------------------------------------------------------------------------------
# Subcommand: ssh
# ------------------------------------------------------------------------------

cmd_ssh() {
  local node="${1:-node1}"
  local ip
  ip="$(get_ip "$node")"
  if [[ -z "$ip" ]]; then
    echo "Error: IP address for node ${node} could not be resolved." >&2
    return 1
  fi
  exec ssh -o StrictHostKeyChecking=accept-new -i "${SSH_KEY}" "${SSH_USER}@${ip}"
}

# ------------------------------------------------------------------------------
# Subcommand: chaos
# ------------------------------------------------------------------------------

cmd_chaos() {
  local rounds=3
  local interval=25

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --rounds)
        rounds="$2"
        shift 2
        ;;
      --interval)
        interval="$2"
        shift 2
        ;;
      *)
        echo "Unknown chaos option: $1" >&2
        return 1
        ;;
    esac
  done

  echo "=== Running Chaos Monkey Mode (${rounds} rounds, interval ${interval}s) ==="
  for (( i = 1; i <= rounds; i++ )); do
    local victim="${NODES[$(( RANDOM % ${#NODES[@]} ))]}"
    echo "=== Chaos Round ${i}/${rounds}: Restarting ${victim} ==="
    ssh_cmd "$victim" sudo systemctl restart bitecho.service

    echo "Polling healthz on ${victim} (up to 30s)..."
    local retries=15
    local healthy=false
    while (( retries > 0 )); do
      local resp
      resp="$(ssh_cmd "$victim" curl -fsSL --max-time 2 http://127.0.0.1:8080/healthz 2>/dev/null || true)"
      if [[ "$resp" == *"ok"* ]]; then
        healthy=true
        break
      fi
      sleep 2
      (( retries-- ))
    done
    if [[ "$healthy" != true ]]; then
      echo "Error: ${victim} failed to become healthy within 30s after restart." >&2
      return 1
    fi
    echo "${victim} is healthy (healthz ok)."

    echo "Waiting ${interval}s for WebRTC DataChannel peer reconnection and Streamlet consensus ticks..."
    sleep "$interval"

    cmd_status
    for node in "${NODES[@]}"; do
      local st
      st="$(ssh_cmd "$node" systemctl is-active bitecho 2>/dev/null || echo "inactive")"
      if [[ "$st" != "active" ]]; then
        echo "Error: Node ${node} is not active (state: ${st})." >&2
        return 1
      fi
    done
    echo "Chaos Round ${i}/${rounds} PASSED: All nodes active."
  done

  echo "=== Chaos Monkey Mode Completed Successfully (${rounds} rounds) ==="
}

# ------------------------------------------------------------------------------
# CLI Dispatcher & Usage
# ------------------------------------------------------------------------------

usage() {
  cat << USAGE_EOF
Bitecho Cluster Management Tool (scripts/cluster.sh)

Usage:
  ./scripts/cluster.sh <command> [options]

Commands:
  init                                Provision GCP projects, static IPs, firewall rules, VMs, and bootstrap packages
  deploy [--reset-state]              Build local uberjar, sync configs/keys/binaries, and restart bitecho services
  status                              Display live status table across all 3 cluster nodes
  chaos [--rounds N] [--interval SEC] Run chaos monkey restarting random nodes and checking convergence
  logs [node1|node2|node3]            Stream systemd journal logs from a cluster node
  bootstrap-sdp                       Display WebRTC DataChannel bootstrap connection parameters for agents
  ssh <node1|node2|node3>             Open interactive SSH shell into a cluster node
  help, -h, --help                    Show this help message

Environment Variables & Overrides:
  BILLING_ACCOUNT                     GCP Billing Account (default: 00A760-ADD23B-93C934)
  SSH_USER                            Remote SSH username (default: bitecho)
  TICK_INTERVAL_MS                    Streamlet & Treasury tick interval in ms (default: 10000)
USAGE_EOF
}

main() {
  if [[ $# -eq 0 ]]; then
    usage
    exit 0
  fi

  local cmd="$1"
  shift

  case "$cmd" in
    init)
      cmd_init "$@"
      ;;
    deploy)
      cmd_deploy "$@"
      ;;
    status)
      cmd_status "$@"
      ;;
    chaos)
      cmd_chaos "$@"
      ;;
    logs)
      cmd_logs "$@"
      ;;
    bootstrap-sdp|bootstrap_sdp)
      cmd_bootstrap_sdp "$@"
      ;;
    ssh)
      cmd_ssh "$@"
      ;;
    help|-h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown command: ${cmd}" >&2
      usage >&2
      exit 1
      ;;
  esac
}

main "$@"

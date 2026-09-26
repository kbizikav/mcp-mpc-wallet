#!/bin/sh
# Startup script that runs inside the enclave.
#
# vsock ports (the parent's CID is 3):
#   9000  parent → enclave: the startup bundle (env.sh and the contents of /data) as a tar
#   9001  enclave → parent: the contents of /data (sealed shares, policies, audit log), sent periodically
#   9002  enclave → parent: logs
#   8000  KMS (used directly by kmstool), 8001+ vsock-proxy to external APIs (8004: Base mainnet RPC)
#   7443  parent → enclave: mTLS from A (TLS terminates inside the enclave)
set -eu

ip link set lo up

mkdir -p /data
socat -u VSOCK-LISTEN:9000 - | tar -x -C /data
# shellcheck disable=SC1091
. /data/env.sh
rm -f /data/env.sh

# Point external hosts at separate loopback addresses and relay them to the vsock-proxy (B terminates TLS)
i=2
for entry in base-sepolia.g.alchemy.com:8001 api.tenderly.co:8002 api.openai.com:8003 base-mainnet.g.alchemy.com:8004; do
    host=${entry%%:*}
    port=${entry##*:}
    echo "127.0.0.$i $host" >> /etc/hosts
    socat TCP-LISTEN:443,bind=127.0.0.$i,fork,reuseaddr VSOCK-CONNECT:3:"$port" &
    i=$((i + 1))
done

sync_data() {
    tar -c -C /data . | socat -u - VSOCK-CONNECT:3:9001 || true
}

( while true; do sleep 5; sync_data; done ) &

log() {
    socat -u - VSOCK-CONNECT:3:9002 || cat > /dev/null
}

set +e
# Passkey RPs only for serve (the browser on localhost, and the development software passkey)
extra=""
if [ "$MW_MODE" = "serve" ]; then
    extra="--passkey-rp mcp-mpc-wallet.local=https://mcp-mpc-wallet.local --passkey-rp localhost=http://localhost:8787"
fi
# shellcheck disable=SC2086
/app/mw-node-b "$MW_MODE" \
    --listen vsock:7443 \
    --tls-dir /data/tls \
    --data-dir /data \
    --kms-key-id "$MW_KMS_KEY_ID" \
    --kms-region "$AWS_REGION" \
    --enclave-tls $extra 2>&1 | log
status=$?
sync_data
echo "mw-node-b exited with $status" | log
sleep infinity

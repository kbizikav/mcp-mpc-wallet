#!/bin/sh
# Enclave の中で動く起動スクリプト。
#
# vsock のポート(親の CID は 3):
#   9000  親 → enclave: 起動時の一式(env.sh と /data の中身)を tar で受け取る
#   9001  enclave → 親: /data の中身(封印済みシェア、方針、監査ログ)を定期的に送る
#   9002  enclave → 親: ログ
#   8000  KMS(kmstool が直接使う)、8001〜 外部 API への vsock-proxy
#   7443  親 → enclave: A からの mTLS(TLS は enclave の中で終端する)
set -eu

ip link set lo up

mkdir -p /data
socat -u VSOCK-LISTEN:9000 - | tar -x -C /data
# shellcheck disable=SC1091
. /data/env.sh
rm -f /data/env.sh

# 外部ホストを loopback の別アドレスに向け、vsock-proxy に中継する(TLS は B が終端する)
i=2
for entry in base-sepolia.g.alchemy.com:8001 api.tenderly.co:8002 api.openai.com:8003; do
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
/app/mw-node-b "$MW_MODE" \
    --listen vsock:7443 \
    --tls-dir /data/tls \
    --data-dir /data \
    --kms-key-id "$MW_KMS_KEY_ID" \
    --kms-region "$AWS_REGION" 2>&1 | log
status=$?
sync_data
echo "mw-node-b exited with $status" | log
sleep infinity

#!/bin/bash
# 親インスタンスで enclave を起動する。
#
#   parent.sh start <keygen|serve>   enclave を起動して一式を渡し、中継を始める
#   parent.sh stop                   enclave と中継を止める
#
# /opt/mw/secrets.env に ALCHEMY_API_KEY、TENDERLY_*、OPENAI_API_KEY、MW_KMS_KEY_ID を置く。
# /opt/mw/data に tls/(B の証明書と鍵)と、enclave が送ってきた封印済みデータが入る。
set -euo pipefail

MW=/opt/mw
CID=16
REGION=ap-northeast-1

stop() {
    nitro-cli terminate-enclave --all >/dev/null 2>&1 || true
    pkill -f "vsock-proxy" || true
    pkill -f "socat.*VSOCK" || true
}

role_credentials() {
    local token role
    token=$(curl -sS -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
    role=$(curl -sS -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/iam/security-credentials/)
    curl -sS -H "X-aws-ec2-metadata-token: $token" "http://169.254.169.254/latest/meta-data/iam/security-credentials/$role"
}

start() {
    local mode=$1
    stop
    mkdir -p "$MW/data" "$MW/logs"

    # 外部への中継(許可したホストだけ)
    vsock-proxy 8000 kms.$REGION.amazonaws.com 443 --config "$MW/vsock-proxy.yaml" &
    vsock-proxy 8001 base-sepolia.g.alchemy.com 443 --config "$MW/vsock-proxy.yaml" &
    vsock-proxy 8002 api.tenderly.co 443 --config "$MW/vsock-proxy.yaml" &
    vsock-proxy 8003 api.openai.com 443 --config "$MW/vsock-proxy.yaml" &

    # enclave からのデータとログを受け取る
    socat -u VSOCK-LISTEN:9001,fork,reuseaddr SYSTEM:"tar -x -C $MW/data" &
    socat -u VSOCK-LISTEN:9002,fork,reuseaddr "OPEN:$MW/logs/enclave.log,creat,append" &

    nitro-cli run-enclave --eif-path "$MW/mw-node-b.eif" --cpu-count 1 --memory 1400 \
        --enclave-cid "$CID" ${MW_DEBUG:+--debug-mode}

    # 起動時の一式: API キー、ロールの一時資格情報、モード、/data の中身
    local bundle creds
    bundle=$(mktemp -d)
    creds=$(role_credentials)
    {
        sed 's/^/export /' "$MW/secrets.env"
        echo "export MW_MODE=$mode"
        echo "export AWS_REGION=$REGION"
        echo "export AWS_ACCESS_KEY_ID=$(echo "$creds" | python3 -c 'import json,sys; print(json.load(sys.stdin)["AccessKeyId"])')"
        echo "export AWS_SECRET_ACCESS_KEY=$(echo "$creds" | python3 -c 'import json,sys; print(json.load(sys.stdin)["SecretAccessKey"])')"
        echo "export AWS_SESSION_TOKEN=$(echo "$creds" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Token"])')"
    } > "$bundle/env.sh"
    chmod 600 "$bundle/env.sh"
    cp -a "$MW/data/." "$bundle/"
    for _ in $(seq 1 30); do
        if tar -c -C "$bundle" . | socat -u - VSOCK-CONNECT:$CID:9000 2>/dev/null; then
            break
        fi
        sleep 1
    done
    rm -rf "$bundle"

    # A からの mTLS を enclave に中継する
    socat TCP-LISTEN:7443,fork,reuseaddr VSOCK-CONNECT:$CID:7443 &
    echo "enclave started in $mode mode"
}

case "${1:-}" in
    start) start "${2:?mode}" ;;
    stop) stop ;;
    *) echo "usage: $0 start <keygen|serve> | stop" >&2; exit 2 ;;
esac

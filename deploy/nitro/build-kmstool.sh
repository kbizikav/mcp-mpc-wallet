#!/bin/bash
# Build AWS's official kmstool_enclave_cli and libnsm.so and put them in deploy/nitro/kmstool/.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
git clone --depth 1 https://github.com/aws/aws-nitro-enclaves-sdk-c "$work/sdk"
cd "$work/sdk"
docker build --target kmstool-enclave-cli -t kmstool-enclave-cli -f containers/Dockerfile.al2 .
id=$(docker create kmstool-enclave-cli)
mkdir -p "$here/kmstool"
docker cp "$id:/kmstool_enclave_cli" "$here/kmstool/kmstool_enclave_cli"
docker cp "$id:/usr/lib64/libnsm.so" "$here/kmstool/libnsm.so"
docker rm "$id"
rm -rf "$work"
ls -l "$here/kmstool"

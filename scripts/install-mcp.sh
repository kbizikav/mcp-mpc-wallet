#!/bin/bash
# Register the wallet's MCP server (signing node A) with Claude Code.
#
#   scripts/install-mcp.sh --node-b HOST:PORT --tls-dir DIR --data-dir DIR \
#       [--expected-pcr0 HEX] [--name NAME] [--scope user|project|local] [--apply]
#
# Without --apply it only prints the `claude mcp add` command (with the API key masked).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
name=mcp-mpc-wallet
scope=user
apply=false
node_b="" tls_dir="" data_dir="" pcr0=""

while [ $# -gt 0 ]; do
    case "$1" in
        --node-b) node_b=$2; shift 2 ;;
        --tls-dir) tls_dir=$2; shift 2 ;;
        --data-dir) data_dir=$2; shift 2 ;;
        --expected-pcr0) pcr0=$2; shift 2 ;;
        --name) name=$2; shift 2 ;;
        --scope) scope=$2; shift 2 ;;
        --apply) apply=true; shift ;;
        -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

[ -n "$node_b" ] && [ -n "$tls_dir" ] && [ -n "$data_dir" ] || { sed -n '2,8p' "$0"; exit 2; }
: "${ALCHEMY_API_KEY:?set ALCHEMY_API_KEY (the MCP server builds transactions through Alchemy)}"

abs() { (cd "$1" && pwd); }
tls_dir=$(abs "$tls_dir")
data_dir=$(abs "$data_dir")
for f in "$tls_dir/node-a.pem" "$tls_dir/node-a.key" "$data_dir/share-a.json"; do
    [ -f "$f" ] || { echo "missing $f (run keygen first)" >&2; exit 1; }
done

bin="$root/target/release/mw-node-a"
if [ ! -x "$bin" ]; then
    echo "building mw-node-a (release)..." >&2
    (cd "$root" && cargo build --release -p mw-node-a >&2)
fi

args=(mcp --node-b "$node_b" --tls-dir "$tls_dir" --data-dir "$data_dir")
[ -n "$pcr0" ] && args+=(--expected-pcr0 "$pcr0")

echo "claude mcp add $name --scope $scope -e ALCHEMY_API_KEY=*** -- $bin ${args[*]}"
if $apply; then
    claude mcp add "$name" --scope "$scope" -e "ALCHEMY_API_KEY=$ALCHEMY_API_KEY" -- "$bin" "${args[@]}"
    echo "registered. check with: claude mcp list"
else
    echo "(dry run: re-run with --apply to register it)"
fi

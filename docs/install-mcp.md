# Installing the wallet's MCP server

The MCP server is the **signing node A** (`mw-node-a mcp`). It runs on your machine next to the agent.

The agent can only do two things: look at the wallet, and *propose* transactions or signatures.
Every proposal goes to the judge node B, which runs in an attested AWS Nitro Enclave. B decodes the
proposal itself, simulates it, checks the effects against your policy, and only then co-signs with A.
The agent never gets a tool that could change your policy.

## Prerequisites

- Rust (stable) and this repository.
- An Alchemy API key for Base Sepolia, set as `ALCHEMY_API_KEY`. A uses it to fill in the nonce, gas and fees.
- The output of keygen:
  - `tls/`: `node-a.pem` and `node-a.key` (your client certificate), plus `ca.pem`.
  - `data/`: `share-a.json` (your key share) and `share-c.age` (the encrypted recovery share).
- The judge node's address (`host:7443`) and its enclave image measurement **PCR0**. A refuses to talk
  to a judge node whose attestation does not match this PCR0.

## Install into Claude Code

```sh
export ALCHEMY_API_KEY=...

# Print the command first (dry run)
scripts/install-mcp.sh \
  --node-b 3.112.217.26:7443 \
  --tls-dir .local/nitro/node-a/tls \
  --data-dir .local/nitro/node-a/data \
  --expected-pcr0 <PCR0>

# Register it
scripts/install-mcp.sh ... --apply
claude mcp list
```

The script builds `mw-node-a` in release mode if needed, resolves absolute paths, and runs:

```sh
claude mcp add mcp-mpc-wallet --scope user -e ALCHEMY_API_KEY=... -- \
  /abs/path/target/release/mw-node-a mcp \
  --node-b 3.112.217.26:7443 --tls-dir /abs/tls --data-dir /abs/data --expected-pcr0 <PCR0>
```

To check it works, start Claude Code and ask: *"Use wallet_info to show my wallet."*

## Claude Desktop

Add this to `~/Library/Application Support/Claude/claude_desktop_config.json` and restart Claude Desktop:

```json
{
  "mcpServers": {
    "mcp-mpc-wallet": {
      "command": "/abs/path/target/release/mw-node-a",
      "args": [
        "mcp",
        "--node-b", "3.112.217.26:7443",
        "--tls-dir", "/abs/path/.local/nitro/node-a/tls",
        "--data-dir", "/abs/path/.local/nitro/node-a/data",
        "--expected-pcr0", "<PCR0>"
      ],
      "env": { "ALCHEMY_API_KEY": "..." }
    }
  }
}
```

## Tools

| Tool | What it does |
|---|---|
| `wallet_info` | Address, chain and ETH balance. |
| `propose_transaction` | `to`, `value_wei`, optional `data`, and a `note`. The note is only untrusted context for the judge. |
| `sign_typed_data` | EIP-712 typed data (`eth_signTypedData_v4`) and a `note`. |
| `resume_transaction` | Continues a request that the owner approved in the owner app. |

Results:

| `status` | Meaning |
|---|---|
| `submitted` | The judge approved it. A and B co-signed and B broadcast it. Returns `tx_hash`. The signed transaction never reaches the agent. |
| `signed` | For EIP-712 only: the 65-byte signature. |
| `pending_user_confirmation` | The owner must approve it with a passkey in the owner app. Then call `resume_transaction` with the `request_id` within 5 minutes. |
| `rejected` | Coarse reason only (`policy_violation`, `simulation_failed`, `invalid_request`, `rate_limited`, `unavailable`). The detailed reasons are shown to the owner only. |
| `frozen` | The owner froze the wallet. |

## Troubleshooting

- **`B failed attestation: ... PCRs found were different`**: the judge node runs a different enclave
  image. Update `--expected-pcr0` only if you trust the new image (for example, you built it yourself
  and got the same PCR0).
- **`connecting to B: Connection refused`**: the judge node is not running, or the security group does
  not allow your IP on port 7443.
- **`rejected` with `invalid_request` right after another transaction**: the account nonce moved on.
  Ask the agent to propose again.

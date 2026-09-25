# MCP MPC wallet

自律 AI エージェント向けのウォレット。鍵は 2-of-3 の閾値 ECDSA(cggmp21)で分割し、
エージェントは tx を提案するだけ。判定ノード B が自分でデコード・シミュレーション(Tenderly)・
AI 判定(OpenAI)を行い、承認したものにだけ閾値署名で参加して、自分で送信する。

## crate

| crate | 役割 |
|---|---|
| `mw-core` | 共有の型。承認の束縛・期限・一回限りの引き換え、fail-closed な判定の合成 |
| `mw-chain` | 未署名 EIP-1559 tx の厳格なデコード、既知 call のデコード、JSON-RPC クライアント |
| `mw-simulator` | `Simulator` trait と Tenderly 実装 |
| `mw-judge` | プロンプト(固定の指示と、エスケープしたデータ領域)、複数サンプル判定、OpenAI 実装 |
| `mw-mpc` | `ThresholdSigner` trait。cggmp21 の spike |
| `mw-node-b` | 判定ノード B のパイプライン、レート制限・自動凍結、通知 |
| `mw-audit` | ハッシュチェーン監査ログ |
| `mw-tee` | SealedStorage / Attestation / Transport の trait とモック |
| `mw-http` | webpki-roots で検証する HTTPS 専用クライアント |

## テスト

```sh
cargo test --workspace                     # spike の素数生成で 1〜2 分かかる
cargo test --workspace -- --skip a_sends_partial --skip recovery_paths   # spike を除く
```

実際の Base Sepolia・Tenderly・OpenAI を使うテスト(送信はしない):

```sh
export TENDERLY_API_KEY=... OPENAI_API_KEY=... ALCHEMY_API_KEY=...
export TENDERLY_ACCOUNT_SLUG=... TENDERLY_PROJECT_SLUG=...
# 省略時は gpt-5.5-2026-04-23
export OPENAI_MODEL=...
cargo test -p mw-node-b --test live -- --ignored --test-threads 1
```

API キーはリポジトリに置かないこと(`.env*` は `.gitignore` 済み)。

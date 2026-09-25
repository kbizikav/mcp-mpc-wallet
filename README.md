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
| `mw-wire` | A↔B のメッセージ、接続上での MPC、mTLS と開発用 PKI |
| `mw-policy` | パスキー(WebAuthn ES256)署名つきのユーザー操作と検証 |

| バイナリ | 役割 |
|---|---|
| `mw-node-b` | 判定ノード B(`pki` / `keygen` / `register-passkey` / `serve`) |
| `mw-node-a` | 署名ノード A と MCP サーバ(`keygen` / `info` / `propose` / `resume` / `mcp`) |
| `mw-user` | 開発用ユーザーアプリ(ソフトウェアパスキー) |
| `mw-owner` | オーナー用 Web アプリ(ブラウザのパスキー / Touch ID)。http://localhost:8787 |

- エージェント(Claude Code)への MCP のインストール: [docs/install-mcp.md](docs/install-mcp.md)
- 発表の台本: [docs/demo.md](docs/demo.md)

## 動かし方(Base Sepolia、TEE なしの開発構成)

実行時データ(鍵・証明書・監査ログ)は `.local/` に置く(git 管理外)。

```sh
# 1. デプロイ用 PKI(CA の鍵は発行後に捨てる)
mw-node-b pki --node-b-dir .local/node-b/tls --node-a-dir .local/node-a/tls

# 2. 2-of-3 の鍵生成。A 側は A と C を担当し、C はパスフレーズで暗号化して保存する
mw-node-b keygen --listen 127.0.0.1:7443 --tls-dir .local/node-b/tls --data-dir .local/node-b/data &
mw-node-a keygen --node-b 127.0.0.1:7443 --tls-dir .local/node-a/tls --data-dir .local/node-a/data \
  --passphrase-file ~/.mw-recovery-passphrase

# 3. ユーザーのパスキーを作って B に登録する(B を止めた状態で)
mw-user passkey-new --passkey .local/user/passkey.json
mw-node-b register-passkey --data-dir .local/node-b/data --passkey .local/user/passkey.pub.json

# 4. B を起動し、パスキー署名つきで方針を登録する
mw-node-b serve --listen 127.0.0.1:7443 --tls-dir .local/node-b/tls --data-dir .local/node-b/data &
mw-user set-policy --node-b 127.0.0.1:7443 --tls-dir .local/node-a/tls --wallet <addr> \
  --passkey .local/user/passkey.json --text-file policy.txt

# 5. エージェントには MCP サーバとして A を渡す
mw-node-a mcp --node-b 127.0.0.1:7443 --tls-dir .local/node-a/tls --data-dir .local/node-a/data
```

B には `ALCHEMY_API_KEY`、`TENDERLY_API_KEY`、`TENDERLY_ACCOUNT_SLUG`、`TENDERLY_PROJECT_SLUG`、
`OPENAI_API_KEY`(と任意で `OPENAI_MODEL`)が、A には `ALCHEMY_API_KEY` が必要。

オーナーの操作はブラウザの `mw-owner` でもできる(パスキーは Touch ID。初回だけ `--legacy-passkey` で
開発用パスキーから差し替える。B には `--passkey-rp localhost=http://localhost:8787` を渡しておく)。
要確認になった tx は `mw-user pending` で詳細を見て `mw-user approve --request-id <id>` で承認し、
5 分以内にエージェントが `resume_transaction` を呼ぶと送信される。
`mw-user freeze` は署名なしで凍結でき、解除(`unfreeze`)にはパスキーが要る。

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

## AWS Nitro Enclaves で B を動かす

`deploy/nitro/` に一式がある。B は enclave の中で vsock で待ち受け、TLS は enclave の中で終端する。

- **B のシェア**: KMS のデータキー(attestation つきで取得)+ AES-256-GCM で封印する。
  キーポリシーは `kms:RecipientAttestation:ImageSha384`(= PCR0)が一致する enclave にだけ
  `GenerateDataKey` / `Decrypt` を許す。親のディスクには暗号文しか置かない。
- **B の TLS 証明書**: enclave の中で作る(`--enclave-tls`)。A と `mw-user` は `--expected-pcr0` を
  指定すると、NSM の attestation document(AWS Nitro ルートまでの証明書チェーン、PCR0、nonce、
  TLS 証明書の SHA-256)を検証してから要求を送る。
- **外部 API**: enclave 内で許可したホストを loopback に向け、親の vsock-proxy(allowlist)経由で出す。

手順(親インスタンスは c6g.large、Amazon Linux 2023、`aws-nitro-enclaves-cli` 入り):

```sh
# 1. kmstool(AWS 公式)をビルドして deploy/nitro/kmstool/ に置く
deploy/nitro/build-kmstool.sh
# 2. enclave イメージを作る(Apple Silicon の Mac なら linux/arm64 をそのまま作れる)
docker build --platform linux/arm64 -f deploy/nitro/Dockerfile.enclave -t mw-node-b-enclave:latest .
# 3. 親で EIF にする(PCR0 が出る)
NITRO_CLI_ARTIFACTS=/opt/mw/artifacts nitro-cli build-enclave --docker-uri mw-node-b-enclave:latest --output-file /opt/mw/mw-node-b.eif
# 4. KMS キーポリシーの PCR0 を更新し、親で enclave を起動する
/opt/mw/parent.sh start keygen   # 鍵生成(A から mw-node-a keygen --expected-pcr0 ...)
/opt/mw/parent.sh start serve
```

親の `/opt/mw/secrets.env` に API キーと `MW_KMS_KEY_ID`、`/opt/mw/data/tls` にデプロイ PKI の B 側を置く。

開発段階の制約: API キーと AWS の一時資格情報は親から渡す。パスキーの初回登録は親に置いたファイルで行う。
方針・凍結状態は enclave から親に同期するが、巻き戻しは防げていない。KMS キーポリシーはアカウント管理者が変更できる。

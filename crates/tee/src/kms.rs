//! Nitro Enclave の中での封印: KMS のデータキー(attestation つき)+ AES-256-GCM。
//!
//! KMS への要求は AWS 公式の `kmstool_enclave_cli` に任せる。これは enclave の attestation
//! document を KMS に渡し、KMS はキーポリシー(PCR0 などの条件)を満たす enclave にだけ
//! データキーを返す。平文のデータキーは enclave の外に出ない。
//!
//! 保存するのは「KMS で暗号化したデータキー」と「暗号文」だけなので、親インスタンスや
//! 運営者はファイルを読んでも中身を得られない。

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use serde::{Deserialize, Serialize};

use crate::{SealedStorage, TeeError};

/// enclave から KMS に使う一時的な資格情報(親インスタンスのロール)。
pub struct KmsCredentials {
    pub access_key_id: String,
    pub secret_access_key: SecretString,
    pub session_token: SecretString,
}

impl KmsCredentials {
    pub fn from_env() -> Result<Self, TeeError> {
        let var = |name: &str| {
            std::env::var(name).map_err(|_| TeeError::Storage(format!("{name} is not set")))
        };
        Ok(Self {
            access_key_id: var("AWS_ACCESS_KEY_ID")?,
            secret_access_key: SecretString::from(var("AWS_SECRET_ACCESS_KEY")?),
            session_token: SecretString::from(var("AWS_SESSION_TOKEN")?),
        })
    }
}

pub struct KmsToolSealedStorage {
    pub dir: PathBuf,
    pub tool: PathBuf,
    pub region: String,
    pub key_id: String,
    /// 親インスタンスで KMS への vsock-proxy が待つポート
    pub proxy_port: u16,
    pub credentials: KmsCredentials,
}

#[derive(Serialize, Deserialize)]
struct SealedFile {
    version: u32,
    /// KMS で暗号化されたデータキー(base64)
    kms_ciphertext: String,
    nonce: String,
    ciphertext: String,
}

impl KmsToolSealedStorage {
    fn path(&self, label: &str) -> Result<PathBuf, TeeError> {
        if label.is_empty() || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(TeeError::Storage(format!("invalid label {label:?}")));
        }
        Ok(self.dir.join(format!("{label}.kms.json")))
    }

    fn run_tool(&self, args: &[&str]) -> Result<String, TeeError> {
        let output = Command::new(&self.tool)
            .args(args)
            .args(["--region", &self.region])
            .args(["--proxy-port", &self.proxy_port.to_string()])
            .args(["--aws-access-key-id", &self.credentials.access_key_id])
            .args([
                "--aws-secret-access-key",
                self.credentials.secret_access_key.expose_secret(),
            ])
            .args([
                "--aws-session-token",
                self.credentials.session_token.expose_secret(),
            ])
            .output()
            .map_err(|e| TeeError::Storage(format!("running kmstool: {e}")))?;
        if !output.status.success() {
            // 標準エラーには秘密は出ないが、長さは抑える
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(TeeError::Storage(format!(
                "kmstool failed: {}",
                err.chars().take(300).collect::<String>()
            )));
        }
        String::from_utf8(output.stdout).map_err(|e| TeeError::Storage(e.to_string()))
    }

    /// `KEY: base64` 形式の行から値を取り出す。
    fn field(output: &str, name: &str) -> Result<Vec<u8>, TeeError> {
        let prefix = format!("{name}:");
        let value = output
            .lines()
            .find_map(|l| l.trim().strip_prefix(&prefix))
            .ok_or_else(|| TeeError::Storage(format!("kmstool output has no {name}")))?;
        STANDARD
            .decode(value.trim())
            .map_err(|e| TeeError::Storage(format!("kmstool {name}: {e}")))
    }
}

fn cipher(key: &[u8]) -> Result<Aes256Gcm, TeeError> {
    Aes256Gcm::new_from_slice(key).map_err(|_| TeeError::Storage("data key is not 256 bits".into()))
}

impl SealedStorage for KmsToolSealedStorage {
    fn seal(&self, label: &str, secret: &SecretSlice<u8>) -> Result<(), TeeError> {
        let path = self.path(label)?;
        let out = SecretString::from(self.run_tool(&[
            "genkey",
            "--key-id",
            &self.key_id,
            "--key-spec",
            "AES-256",
        ])?);
        let kms_ciphertext = Self::field(out.expose_secret(), "CIPHERTEXT")?;
        let data_key = SecretSlice::from(Self::field(out.expose_secret(), "PLAINTEXT")?);

        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher(data_key.expose_secret())?
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: secret.expose_secret(),
                    aad: label.as_bytes(),
                },
            )
            .map_err(|_| TeeError::Storage("encryption failed".into()))?;
        let file = SealedFile {
            version: 1,
            kms_ciphertext: STANDARD.encode(kms_ciphertext),
            nonce: STANDARD.encode(nonce),
            ciphertext: STANDARD.encode(ciphertext),
        };

        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut f = options
            .open(&path)
            .map_err(|e| TeeError::Storage(format!("{}: {e}", path.display())))?;
        f.write_all(&serde_json::to_vec(&file).map_err(|e| TeeError::Storage(e.to_string()))?)
            .and_then(|()| f.sync_all())
            .map_err(|e| TeeError::Storage(e.to_string()))
    }

    fn unseal(&self, label: &str) -> Result<SecretSlice<u8>, TeeError> {
        let path = self.path(label)?;
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(TeeError::NotFound(label.to_owned()));
            }
            Err(e) => return Err(TeeError::Storage(e.to_string())),
        };
        let file: SealedFile =
            serde_json::from_slice(&bytes).map_err(|e| TeeError::Storage(e.to_string()))?;
        let out = SecretString::from(self.run_tool(&[
            "decrypt",
            "--ciphertext",
            &file.kms_ciphertext,
        ])?);
        let data_key = SecretSlice::from(Self::field(out.expose_secret(), "PLAINTEXT")?);
        let decode = |v: &str| {
            STANDARD
                .decode(v)
                .map_err(|e| TeeError::Storage(e.to_string()))
        };
        let nonce: [u8; 12] = decode(&file.nonce)?
            .try_into()
            .map_err(|_| TeeError::Storage("bad nonce".into()))?;
        let plaintext = cipher(data_key.expose_secret())?
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &decode(&file.ciphertext)?,
                    aad: label.as_bytes(),
                },
            )
            .map_err(|_| {
                TeeError::Storage("sealed data was tampered with or the key is wrong".into())
            })?;
        Ok(SecretSlice::from(plaintext))
    }

    fn exists(&self, label: &str) -> bool {
        self.path(label).is_ok_and(|p| p.exists())
    }

    fn labels(&self) -> Result<Vec<String>, TeeError> {
        crate::labels_in(&self.dir, ".kms.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// kmstool の代わりに、固定のデータキーを返すスクリプトを使う。
    fn fake_tool(dir: &std::path::Path) -> PathBuf {
        let key = STANDARD.encode([7u8; 32]);
        let script = dir.join("fake-kmstool");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\ncase \"$1\" in\n  genkey) echo \"CIPHERTEXT: {ct}\"; echo \"PLAINTEXT: {key}\";;\n  decrypt) echo \"PLAINTEXT: {key}\";;\nesac\n",
                ct = STANDARD.encode(b"wrapped-key"),
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        script
    }

    fn storage(dir: &std::path::Path) -> KmsToolSealedStorage {
        KmsToolSealedStorage {
            dir: dir.to_path_buf(),
            tool: fake_tool(dir),
            region: "ap-northeast-1".into(),
            key_id: "alias/test".into(),
            proxy_port: 8000,
            credentials: KmsCredentials {
                access_key_id: "AKIA".into(),
                secret_access_key: SecretString::from("secret"),
                session_token: SecretString::from("token"),
            },
        }
    }

    #[cfg(unix)]
    #[test]
    fn seals_and_unseals_without_storing_the_data_key() {
        let dir = std::env::temp_dir().join(format!("mw-kms-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let s = storage(&dir);
        s.seal("share-b", &SecretSlice::from(b"key share".to_vec()))
            .unwrap();
        assert!(s.exists("share-b"));
        assert_eq!(s.labels().unwrap(), ["share-b"]);
        let raw = std::fs::read_to_string(dir.join("share-b.kms.json")).unwrap();
        assert!(
            !raw.contains(&STANDARD.encode([7u8; 32])),
            "data key stored"
        );
        assert!(!raw.contains("key share"));
        assert_eq!(s.unseal("share-b").unwrap().expose_secret(), b"key share");

        // 暗号文を書き換えると復号できない
        let mut file: serde_json::Value = serde_json::from_str(&raw).unwrap();
        file["ciphertext"] = serde_json::json!(STANDARD.encode(b"tampered-ciphertext-bytes"));
        std::fs::write(dir.join("share-c.kms.json"), file.to_string()).unwrap();
        assert!(s.unseal("share-c").is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}

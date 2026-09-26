//! For tests: produce values in the same format as the browser's WebAuthn, using a software passkey.
//!
//! ```text
//! browser_emulator new <file>                 # create a passkey and print the JSON for adopt
//! browser_emulator sign <file> < challenge.json   # turn a /api/challenge response into a /api/submit body
//! ```

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use mw_policy::UserOperation;
use mw_policy::software::SoftwarePasskey;
use p256::pkcs8::EncodePublicKey;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let (command, file) = (args[1].as_str(), &args[2]);
    match command {
        "new" => {
            let passkey = SoftwarePasskey::generate("localhost", "http://localhost:8788");
            let registration = passkey.registration();
            let spki =
                p256::PublicKey::from_sec1_bytes(&registration.public_key)?.to_public_key_der()?;
            std::fs::write(file, serde_json::to_vec(&passkey)?)?;
            println!(
                "{}",
                serde_json::json!({
                    "credential_id": URL_SAFE_NO_PAD.encode(&registration.credential_id),
                    "spki": URL_SAFE_NO_PAD.encode(spki.as_bytes()),
                })
            );
        }
        "sign" => {
            let challenge: serde_json::Value = serde_json::from_reader(std::io::stdin())?;
            let operation: UserOperation = serde_json::from_value(challenge["operation"].clone())?;
            // The challenge the server returned must match the one computed from the operation
            anyhow::ensure!(
                challenge["challenge"] == URL_SAFE_NO_PAD.encode(operation.challenge()),
                "server challenge does not match the operation"
            );
            let mut passkey: SoftwarePasskey = serde_json::from_slice(&std::fs::read(file)?)?;
            let signed = passkey.sign(operation.clone());
            std::fs::write(file, serde_json::to_vec(&passkey)?)?;
            let a = signed.assertion;
            println!(
                "{}",
                serde_json::json!({
                    "operation": operation,
                    "assertion": {
                        "credential_id": URL_SAFE_NO_PAD.encode(&a.credential_id),
                        "authenticator_data": URL_SAFE_NO_PAD.encode(&a.authenticator_data),
                        "client_data_json": URL_SAFE_NO_PAD.encode(&a.client_data_json),
                        "signature": URL_SAFE_NO_PAD.encode(&a.signature),
                    }
                })
            );
        }
        other => anyhow::bail!("unknown command {other}"),
    }
    Ok(())
}

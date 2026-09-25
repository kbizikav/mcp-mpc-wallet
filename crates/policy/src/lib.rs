//! ユーザーのパスキー(WebAuthn, ES256)で署名した操作と、その検証。
//!
//! B は方針の変更・要確認 tx の承認・凍結の解除を、登録済みのパスキーで署名されたものだけ受け付ける
//! (不変条件 6)。署名対象(challenge)は操作の正規化ハッシュで、操作の内容に束縛される。
//! 検証は p256 の ECDSA を使い、暗号プリミティブは実装しない。

mod operation;
mod protocol;
mod webauthn;

#[cfg(feature = "software-passkey")]
pub mod software;

pub use operation::{SignedUserOperation, UserOperation};
pub use protocol::{PendingView, UserRequest, UserResponse};
pub use webauthn::{PasskeyAssertion, PasskeyError, PasskeyVerifier, RegisteredPasskey};

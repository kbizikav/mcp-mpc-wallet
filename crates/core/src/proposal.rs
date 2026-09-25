use alloy_primitives::{Address, Bytes};
use serde::{Deserialize, Serialize};

/// エージェントや外部コントラクトなど、攻撃者が制御しうる文字列。
///
/// `Display` を実装しないので、`format!` でプロンプトやログにそのまま混ざることはない。
/// 中身を使うときは `as_untrusted_str` を明示的に呼ぶ。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UntrustedText(String);

impl UntrustedText {
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    pub fn as_untrusted_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for UntrustedText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UntrustedText({} bytes)", self.0.len())
    }
}

/// エージェントが A 経由で B に送る EIP-712 署名の提案。
///
/// B は `typed_data` を自分でデコードして digest を計算する。署名はエージェントに返る。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedDataProposal {
    pub wallet: Address,
    pub chain_id: u64,
    /// EIP-712 の typed data(types / primaryType / domain / message)
    pub typed_data: serde_json::Value,
    pub agent_note: UntrustedText,
}

/// エージェントが A 経由で B に送る署名の提案。
///
/// B が信用するのは `unsigned_tx` の生バイト列だけで、`agent_note` は参考情報として扱う。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    /// 署名に使うウォレットのアドレス(= tx の from)
    pub wallet: Address,
    pub chain_id: u64,
    /// EIP-2718 でエンコードした未署名 tx
    pub unsigned_tx: Bytes,
    pub agent_note: UntrustedText,
}

use alloy_primitives::{Address, B256};
use mw_core::{AgentOutcome, Proposal};
use mw_mpc::net::WireMsg;
use mw_policy::{UserRequest, UserResponse};
use serde::{Deserialize, Serialize};

/// A(ユーザーの PC)から B(判定ノード)へ。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AtoB {
    /// 署名の提案。B が判定し、承認なら続けて `SignRequest` を送ってくる
    Propose {
        proposal: Proposal,
    },
    /// ユーザーが承認した要求の署名・送信を再開する
    Resume {
        wallet: Address,
        request_id: B256,
    },
    /// ユーザーアプリからの操作(方針・承認・凍結など)
    User {
        request: UserRequest,
    },
    /// B のシェアがまだないときだけ受け付ける鍵生成
    Keygen {
        session: B256,
    },
    /// 鍵生成が終わり、A 側で得た公開鍵のアドレス(B と一致を確認する)
    KeygenResult {
        address: Address,
    },
    Mpc {
        msg: WireMsg,
    },
    /// A の部分署名。B にだけ送る
    PartialSignature {
        partial: serde_json::Value,
    },
    /// A が署名要求を断った
    Decline {
        reason: String,
    },
}

/// B から A へ。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BtoA {
    /// 承認した tx の署名に参加してほしい。`signing_hash` は A が提案したものと一致しなければならない
    SignRequest {
        session: B256,
        signing_hash: B256,
    },
    KeygenAccepted,
    KeygenDone {
        address: Address,
    },
    Mpc {
        msg: WireMsg,
    },
    /// 最終結果。署名済み tx は含まない
    Outcome {
        outcome: AgentOutcome,
    },
    User {
        response: UserResponse,
    },
    Error {
        message: String,
    },
}

// MPC 以外のメッセージは、後で読むためにそのまま返す(Err に載るのは意図どおり)
#[allow(clippy::result_large_err)]
impl AtoB {
    pub fn into_mpc(self) -> Result<WireMsg, Self> {
        match self {
            AtoB::Mpc { msg } => Ok(msg),
            other => Err(other),
        }
    }
}

#[allow(clippy::result_large_err)]
impl BtoA {
    pub fn into_mpc(self) -> Result<WireMsg, Self> {
        match self {
            BtoA::Mpc { msg } => Ok(msg),
            other => Err(other),
        }
    }
}

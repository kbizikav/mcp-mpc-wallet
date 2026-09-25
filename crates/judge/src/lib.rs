//! AI 判定の LLM 呼び出しの抽象化。本実装は OpenAI(M3)。
//!
//! プロンプトは「固定の指示」と「データ領域」に分ける。攻撃者が制御しうる文字列は
//! データ領域にだけ入れる(不変条件 8)。

mod judge;
mod prompt;

pub use judge::{JudgeOutcome, LlmJudgement, SampleResult, judge, parse_judgement};
pub use prompt::{INSTRUCTIONS, build_request, escape_data};

use std::future::Future;
use std::sync::Mutex;

/// LLM への 1 回の問い合わせ。
#[derive(Clone, Debug, PartialEq)]
pub struct LlmRequest {
    /// 固定テンプレートから作った指示。攻撃者由来の文字列を含めない
    pub instructions: String,
    /// JSON でエスケープ済みのデータ領域
    pub data: String,
    /// 出力の JSON schema(構造化出力)
    pub response_schema: serde_json::Value,
}

#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    #[error("LLM API unavailable: {0}")]
    Unavailable(String),
    #[error("LLM API refused or returned an error: {0}")]
    Api(String),
}

pub trait LlmClient: Send + Sync {
    /// 固定したモデルのバージョン。監査ログに残す
    fn model_id(&self) -> &str;

    /// 生の出力テキストを返す。パースは呼び出し側が行い、失敗は fail closed で扱う
    fn complete(
        &self,
        request: &LlmRequest,
    ) -> impl Future<Output = Result<String, LlmError>> + Send;
}

/// あらかじめ決めた出力を順に返すモック。
pub struct ScriptedLlm {
    responses: Mutex<Vec<Result<String, String>>>,
    requests: Mutex<Vec<LlmRequest>>,
}

impl ScriptedLlm {
    pub fn new(responses: impl IntoIterator<Item = Result<String, String>>) -> Self {
        let mut responses: Vec<_> = responses.into_iter().collect();
        responses.reverse();
        Self {
            responses: Mutex::new(responses),
            requests: Mutex::default(),
        }
    }

    pub fn requests(&self) -> Vec<LlmRequest> {
        self.requests.lock().expect("poisoned").clone()
    }
}

impl LlmClient for ScriptedLlm {
    fn model_id(&self) -> &str {
        "scripted-mock"
    }

    async fn complete(&self, request: &LlmRequest) -> Result<String, LlmError> {
        self.requests
            .lock()
            .expect("poisoned")
            .push(request.clone());
        match self.responses.lock().expect("poisoned").pop() {
            Some(Ok(text)) => Ok(text),
            Some(Err(message)) => Err(LlmError::Api(message)),
            None => Err(LlmError::Unavailable("no scripted response".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn scripted_responses_in_order_then_unavailable() {
        let llm = ScriptedLlm::new([Ok("{}".into()), Err("rate limited".into())]);
        let request = LlmRequest {
            instructions: "judge".into(),
            data: "{}".into(),
            response_schema: serde_json::json!({}),
        };
        assert_eq!(llm.complete(&request).await.unwrap(), "{}");
        assert!(matches!(
            llm.complete(&request).await,
            Err(LlmError::Api(_))
        ));
        assert!(matches!(
            llm.complete(&request).await,
            Err(LlmError::Unavailable(_))
        ));
        assert_eq!(llm.requests().len(), 3);
    }
}

//! Abstraction over the LLM calls of the AI judgment, and an implementation with the OpenAI Responses API.
//!
//! The prompt is split into "fixed instructions" and a "data section". Attacker-controlled strings
//! go into the data section only (invariant 8).

mod judge;
pub mod openai;
mod prompt;

pub use judge::{JudgeOutcome, LlmJudgement, SampleResult, judge, parse_judgement};
pub use openai::{OpenAiClient, OpenAiConfig};
pub use prompt::{INSTRUCTIONS, build_request, escape_data};

use std::future::Future;
use std::sync::Mutex;

/// One query to the LLM.
#[derive(Clone, Debug, PartialEq)]
pub struct LlmRequest {
    /// Instructions built from a fixed template. Never contains attacker-controlled strings
    pub instructions: String,
    /// The data section, JSON-escaped
    pub data: String,
    /// JSON schema of the output (structured output)
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
    /// The pinned model version. Recorded in the audit log
    fn model_id(&self) -> &str;

    /// Return the raw output text. The caller parses it and treats failures as fail closed
    fn complete(
        &self,
        request: &LlmRequest,
    ) -> impl Future<Output = Result<String, LlmError>> + Send;
}

/// A mock that returns predefined outputs in order.
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

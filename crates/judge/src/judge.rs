use mw_core::Verdict;
use serde::{Deserialize, Serialize};

use crate::{LlmClient, LlmRequest};

const MAX_REASONS: usize = 16;
const MAX_TEXT_LEN: usize = 2_000;

/// The LLM's output. Fields outside the schema make parsing fail.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmJudgement {
    pub verdict: Verdict,
    pub reasons: Vec<String>,
    pub user_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("output is not a valid judgement: {0}")]
    Invalid(String),
    #[error("output is too long")]
    TooLong,
}

pub fn parse_judgement(text: &str) -> Result<LlmJudgement, ParseError> {
    let judgement: LlmJudgement =
        serde_json::from_str(text.trim()).map_err(|e| ParseError::Invalid(e.to_string()))?;
    if judgement.reasons.len() > MAX_REASONS
        || judgement.user_summary.len() > MAX_TEXT_LEN
        || judgement.reasons.iter().any(|r| r.len() > MAX_TEXT_LEN)
    {
        return Err(ParseError::TooLong);
    }
    Ok(judgement)
}

/// The result of one sample.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum SampleResult {
    Judged(LlmJudgement),
    LlmError { message: String },
    ParseError { message: String },
}

impl SampleResult {
    /// A failed sample counts as `NeedsUserConfirmation`.
    pub fn verdict(&self) -> Verdict {
        match self {
            SampleResult::Judged(j) => j.verdict,
            SampleResult::LlmError { .. } | SampleResult::ParseError { .. } => {
                Verdict::NeedsUserConfirmation
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct JudgeOutcome {
    pub verdict: Verdict,
    pub model_id: String,
    pub samples: Vec<SampleResult>,
}

impl JudgeOutcome {
    /// The reasons shown to the user (deduplicated).
    pub fn reasons(&self) -> Vec<String> {
        let mut reasons: Vec<String> = Vec::new();
        for sample in &self.samples {
            let new = match sample {
                SampleResult::Judged(j) => j.reasons.clone(),
                SampleResult::LlmError { message } => vec![format!("llm error: {message}")],
                SampleResult::ParseError { message } => {
                    vec![format!("unparsable output: {message}")]
                }
            };
            for reason in new {
                if !reasons.contains(&reason) {
                    reasons.push(reason);
                }
            }
        }
        reasons
    }
}

/// Send the same query `samples` times and combine them, failing closed.
///
/// An LLM error, a parse failure or disagreement between samples never results in `Approve`.
pub async fn judge<L: LlmClient>(llm: &L, request: &LlmRequest, samples: usize) -> JudgeOutcome {
    let mut results = Vec::with_capacity(samples);
    for _ in 0..samples {
        let result = match llm.complete(request).await {
            Ok(text) => match parse_judgement(&text) {
                Ok(judgement) => SampleResult::Judged(judgement),
                Err(e) => SampleResult::ParseError {
                    message: e.to_string(),
                },
            },
            Err(e) => SampleResult::LlmError {
                message: e.to_string(),
            },
        };
        results.push(result);
    }
    JudgeOutcome {
        verdict: Verdict::fail_closed(results.iter().map(SampleResult::verdict)),
        model_id: llm.model_id().to_owned(),
        samples: results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ScriptedLlm, build_request};

    fn out(verdict: &str) -> Result<String, String> {
        Ok(format!(
            r#"{{"verdict":"{verdict}","reasons":["r"],"user_summary":"s"}}"#
        ))
    }

    async fn run(responses: Vec<Result<String, String>>) -> JudgeOutcome {
        let n = responses.len();
        let llm = ScriptedLlm::new(responses);
        judge(&llm, &build_request(&serde_json::json!({})), n).await
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unanimous_approve() {
        let outcome = run(vec![out("approve"), out("approve"), out("approve")]).await;
        assert_eq!(outcome.verdict, Verdict::Approve);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn disagreement_needs_confirmation() {
        let outcome = run(vec![
            out("approve"),
            out("needs_user_confirmation"),
            out("approve"),
        ])
        .await;
        assert_eq!(outcome.verdict, Verdict::NeedsUserConfirmation);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn any_reject_rejects() {
        let outcome = run(vec![out("approve"), out("reject"), out("approve")]).await;
        assert_eq!(outcome.verdict, Verdict::Reject);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn llm_error_never_approves() {
        let outcome = run(vec![out("approve"), Err("500".into()), out("approve")]).await;
        assert_eq!(outcome.verdict, Verdict::NeedsUserConfirmation);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unparsable_output_never_approves() {
        for bad in [
            "approve",
            r#"{"verdict":"approve"}"#,
            r#"{"verdict":"approve","reasons":[],"user_summary":"","extra":1}"#,
            r#"{"verdict":"APPROVE","reasons":[],"user_summary":""}"#,
            r#"{"verdict":"approve","reasons":[],"user_summary":""} trailing"#,
        ] {
            let outcome = run(vec![out("approve"), Ok(bad.into()), out("approve")]).await;
            assert_eq!(outcome.verdict, Verdict::NeedsUserConfirmation, "{bad}");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn zero_samples_reject() {
        let outcome = run(vec![]).await;
        assert_eq!(outcome.verdict, Verdict::Reject);
    }

    #[test]
    fn rejects_oversized_output() {
        let long = "x".repeat(MAX_TEXT_LEN + 1);
        let text = format!(r#"{{"verdict":"approve","reasons":[],"user_summary":"{long}"}}"#);
        assert_eq!(parse_judgement(&text).unwrap_err(), ParseError::TooLong);
    }
}

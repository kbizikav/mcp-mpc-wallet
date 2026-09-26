use serde::{Deserialize, Serialize};

/// A judgment. `Ord` orders by strictness (Approve < NeedsUserConfirmation < Reject).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Approve,
    NeedsUserConfirmation,
    Reject,
}

impl Verdict {
    /// Combine several judgments into one, failing closed.
    ///
    /// - Empty: `Reject`
    /// - Unanimous: that judgment
    /// - Disagreement: the stricter of the strictest judgment and `NeedsUserConfirmation`
    ///
    /// The result is `Approve` only if there is at least one judgment and all of them are `Approve`.
    pub fn fail_closed(verdicts: impl IntoIterator<Item = Verdict>) -> Verdict {
        let mut iter = verdicts.into_iter();
        let Some(first) = iter.next() else {
            return Verdict::Reject;
        };
        let mut strictest = first;
        let mut unanimous = true;
        for v in iter {
            unanimous &= v == first;
            strictest = strictest.max(v);
        }
        if unanimous {
            first
        } else {
            strictest.max(Verdict::NeedsUserConfirmation)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Verdict::{self, *};

    #[test]
    fn empty_rejects() {
        assert_eq!(Verdict::fail_closed([]), Reject);
    }

    #[test]
    fn unanimous_is_kept() {
        assert_eq!(Verdict::fail_closed([Approve, Approve, Approve]), Approve);
        assert_eq!(Verdict::fail_closed([Reject]), Reject);
    }

    #[test]
    fn disagreement_never_approves() {
        assert_eq!(
            Verdict::fail_closed([Approve, Approve, NeedsUserConfirmation]),
            NeedsUserConfirmation
        );
        assert_eq!(Verdict::fail_closed([Approve, Reject]), Reject);
    }
}

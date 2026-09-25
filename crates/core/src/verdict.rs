use serde::{Deserialize, Serialize};

/// 判定結果。`Ord` は制限の強さの順(Approve < NeedsUserConfirmation < Reject)。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Approve,
    NeedsUserConfirmation,
    Reject,
}

impl Verdict {
    /// 複数の判定を fail closed で 1 つにまとめる。
    ///
    /// - 空なら `Reject`
    /// - 全員一致ならその判定
    /// - 食い違えば、最も強い制限と `NeedsUserConfirmation` のうち強い方
    ///
    /// `Approve` になるのは、1 つ以上あってすべてが `Approve` のときだけ。
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

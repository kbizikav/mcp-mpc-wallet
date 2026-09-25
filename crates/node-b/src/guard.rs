//! ウォレットごとのレート制限と自動凍結(不変条件 9)。

use std::collections::{HashMap, VecDeque};

use alloy_primitives::Address;
use mw_core::Verdict;

#[derive(Clone, Debug)]
pub struct GuardConfig {
    /// `proposal_window_secs` の間に受け付ける提案の上限
    pub max_proposals: usize,
    pub proposal_window_secs: u64,
    /// `reject_window_secs` の間にこの回数だけ拒否したら凍結する
    pub max_rejects: usize,
    pub reject_window_secs: u64,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            max_proposals: 20,
            proposal_window_secs: 60,
            max_rejects: 3,
            reject_window_secs: 600,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    Allowed,
    RateLimited,
    Frozen,
}

#[derive(Default)]
struct WalletState {
    proposals: VecDeque<u64>,
    rejects: VecDeque<u64>,
    frozen: bool,
}

pub struct WalletGuard {
    config: GuardConfig,
    wallets: HashMap<Address, WalletState>,
}

fn prune(times: &mut VecDeque<u64>, now: u64, window: u64) {
    while times
        .front()
        .is_some_and(|&t| now.saturating_sub(t) >= window)
    {
        times.pop_front();
    }
}

impl WalletGuard {
    pub fn new(config: GuardConfig) -> Self {
        Self {
            config,
            wallets: HashMap::new(),
        }
    }

    /// 提案を受け付けてよいかを判定し、受け付けたら記録する。
    pub fn admit(&mut self, wallet: Address, now: u64) -> Admission {
        let state = self.wallets.entry(wallet).or_default();
        if state.frozen {
            return Admission::Frozen;
        }
        prune(&mut state.proposals, now, self.config.proposal_window_secs);
        if state.proposals.len() >= self.config.max_proposals {
            return Admission::RateLimited;
        }
        state.proposals.push_back(now);
        Admission::Allowed
    }

    /// 判定を記録する。この判定で新たに凍結したら `true`。
    pub fn record(&mut self, wallet: Address, verdict: Verdict, now: u64) -> bool {
        if verdict != Verdict::Reject {
            return false;
        }
        let state = self.wallets.entry(wallet).or_default();
        prune(&mut state.rejects, now, self.config.reject_window_secs);
        state.rejects.push_back(now);
        if !state.frozen && state.rejects.len() >= self.config.max_rejects {
            state.frozen = true;
            return true;
        }
        false
    }

    pub fn freeze(&mut self, wallet: Address) {
        self.wallets.entry(wallet).or_default().frozen = true;
    }

    pub fn is_frozen(&self, wallet: Address) -> bool {
        self.wallets.get(&wallet).is_some_and(|s| s.frozen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: Address = Address::repeat_byte(1);

    fn guard() -> WalletGuard {
        WalletGuard::new(GuardConfig {
            max_proposals: 2,
            proposal_window_secs: 60,
            max_rejects: 3,
            reject_window_secs: 600,
        })
    }

    #[test]
    fn rate_limits_within_window() {
        let mut g = guard();
        assert_eq!(g.admit(W, 0), Admission::Allowed);
        assert_eq!(g.admit(W, 1), Admission::Allowed);
        assert_eq!(g.admit(W, 2), Admission::RateLimited);
        assert_eq!(g.admit(W, 60), Admission::Allowed);
        // 別のウォレットには影響しない
        assert_eq!(g.admit(Address::repeat_byte(2), 2), Admission::Allowed);
    }

    #[test]
    fn freezes_after_repeated_rejects() {
        let mut g = guard();
        assert!(!g.record(W, Verdict::Reject, 0));
        assert!(!g.record(W, Verdict::Approve, 1));
        assert!(!g.record(W, Verdict::NeedsUserConfirmation, 1));
        assert!(!g.record(W, Verdict::Reject, 2));
        assert!(g.record(W, Verdict::Reject, 3));
        assert!(g.is_frozen(W));
        assert_eq!(g.admit(W, 1_000), Admission::Frozen);
        // 凍結の通知は一度だけ
        assert!(!g.record(W, Verdict::Reject, 4));
    }

    #[test]
    fn old_rejects_expire() {
        let mut g = guard();
        g.record(W, Verdict::Reject, 0);
        g.record(W, Verdict::Reject, 1);
        assert!(!g.record(W, Verdict::Reject, 601));
        assert!(!g.is_frozen(W));
    }
}

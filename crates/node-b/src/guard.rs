//! Per-wallet rate limits and automatic freezing (invariant 9).

use std::collections::{HashMap, VecDeque};

use alloy_primitives::Address;
use mw_core::Verdict;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct GuardConfig {
    /// Maximum number of proposals accepted within `proposal_window_secs`
    pub max_proposals: usize,
    pub proposal_window_secs: u64,
    /// Freeze after this many rejections within `reject_window_secs`
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
    /// Increases on every freeze. Unfreezing needs a signature over this value
    freeze_epoch: u64,
}

impl WalletState {
    fn freeze(&mut self) -> bool {
        if self.frozen {
            return false;
        }
        self.frozen = true;
        self.freeze_epoch += 1;
        true
    }
}

/// The persisted freeze state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreezeState {
    pub wallet: Address,
    pub frozen: bool,
    pub freeze_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnfreezeError {
    #[error("the wallet is not frozen")]
    NotFrozen,
    #[error("the unfreeze was signed for freeze epoch {signed}, current is {current}")]
    StaleEpoch { signed: u64, current: u64 },
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

    /// Decide whether a proposal may be accepted, and record it if so.
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

    /// Record a judgment. Returns `true` if this judgment newly froze the wallet.
    pub fn record(&mut self, wallet: Address, verdict: Verdict, now: u64) -> bool {
        if verdict != Verdict::Reject {
            return false;
        }
        let state = self.wallets.entry(wallet).or_default();
        prune(&mut state.rejects, now, self.config.reject_window_secs);
        state.rejects.push_back(now);
        state.rejects.len() >= self.config.max_rejects && state.freeze()
    }

    /// Freeze. Returns `true` if newly frozen.
    pub fn freeze(&mut self, wallet: Address) -> bool {
        self.wallets.entry(wallet).or_default().freeze()
    }

    /// Accept only an unfreeze signed for the current freeze epoch.
    pub fn unfreeze(&mut self, wallet: Address, signed_epoch: u64) -> Result<(), UnfreezeError> {
        let state = self.wallets.entry(wallet).or_default();
        if !state.frozen {
            return Err(UnfreezeError::NotFrozen);
        }
        if signed_epoch != state.freeze_epoch {
            return Err(UnfreezeError::StaleEpoch {
                signed: signed_epoch,
                current: state.freeze_epoch,
            });
        }
        state.frozen = false;
        state.rejects.clear();
        Ok(())
    }

    pub fn is_frozen(&self, wallet: Address) -> bool {
        self.wallets.get(&wallet).is_some_and(|s| s.frozen)
    }

    pub fn freeze_epoch(&self, wallet: Address) -> u64 {
        self.wallets.get(&wallet).map_or(0, |s| s.freeze_epoch)
    }

    pub fn snapshot(&self) -> Vec<FreezeState> {
        self.wallets
            .iter()
            .map(|(&wallet, s)| FreezeState {
                wallet,
                frozen: s.frozen,
                freeze_epoch: s.freeze_epoch,
            })
            .collect()
    }

    pub fn restore(&mut self, states: &[FreezeState]) {
        for s in states {
            let state = self.wallets.entry(s.wallet).or_default();
            state.frozen = s.frozen;
            state.freeze_epoch = s.freeze_epoch;
        }
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
        // Other wallets are not affected
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
        // The freeze is notified only once
        assert!(!g.record(W, Verdict::Reject, 4));
    }

    #[test]
    fn unfreeze_requires_current_epoch() {
        let mut g = guard();
        assert_eq!(g.unfreeze(W, 0), Err(UnfreezeError::NotFrozen));
        assert!(g.freeze(W));
        assert!(!g.freeze(W), "already frozen");
        assert_eq!(g.freeze_epoch(W), 1);
        g.unfreeze(W, 1).unwrap();
        assert!(!g.is_frozen(W));

        // The signature of the previous unfreeze cannot be used for the next freeze
        g.freeze(W);
        assert_eq!(
            g.unfreeze(W, 1),
            Err(UnfreezeError::StaleEpoch {
                signed: 1,
                current: 2
            })
        );
    }

    #[test]
    fn snapshot_round_trip() {
        let mut g = guard();
        g.freeze(W);
        let mut restored = guard();
        restored.restore(&g.snapshot());
        assert!(restored.is_frozen(W));
        assert_eq!(restored.freeze_epoch(W), 1);
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

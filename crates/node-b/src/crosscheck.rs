//! Cross-checking the decoded tx against the simulation (invariant 7).
//!
//! On any disagreement, the simulator's result is not trusted and the outcome falls to "needs confirmation".

use alloy_primitives::{Address, U256};
use mw_chain::{DecodedTx, KnownCall};
use mw_simulator::SimulationReport;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Discrepancy {
    BlockMismatch { expected: u64, simulated: u64 },
    MissingNativeTransfer { amount: U256 },
    MissingTokenTransfer { token: Address, amount: U256 },
    MissingAllowanceChange { token: Address, spender: Address },
    UnrecognizedChange(String),
}

impl std::fmt::Display for Discrepancy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BlockMismatch {
                expected,
                simulated,
            } => write!(
                f,
                "simulation ran on block {simulated}, expected {expected}"
            ),
            Self::MissingNativeTransfer { amount } => write!(
                f,
                "tx sends {amount} wei but the simulation shows no matching native transfer"
            ),
            Self::MissingTokenTransfer { token, amount } => write!(
                f,
                "calldata transfers {amount} of {token} but the simulation shows no matching transfer"
            ),
            Self::MissingAllowanceChange { token, spender } => write!(
                f,
                "calldata changes the allowance of {spender} on {token} but the simulation does not"
            ),
            Self::UnrecognizedChange(what) => {
                write!(
                    f,
                    "the simulation reports an effect the wallet cannot check: {what}"
                )
            }
        }
    }
}

pub fn crosscheck(
    wallet: Address,
    decoded: &DecodedTx,
    call: Option<&KnownCall>,
    report: &SimulationReport,
    expected_block: u64,
) -> Vec<Discrepancy> {
    let tx = &decoded.tx;
    let to = tx.to.to().copied();
    let mut found = Vec::new();

    if report.block_number != expected_block {
        found.push(Discrepancy::BlockMismatch {
            expected: expected_block,
            simulated: report.block_number,
        });
    }

    found.extend(
        report
            .unrecognized_changes
            .iter()
            .cloned()
            .map(Discrepancy::UnrecognizedChange),
    );

    if !tx.value.is_zero() {
        let matched = report.transfers.iter().any(|t| {
            t.token.is_none()
                && t.from == wallet
                && t.amount == tx.value
                && to.is_none_or(|to| t.to == to)
        });
        if !matched {
            found.push(Discrepancy::MissingNativeTransfer { amount: tx.value });
        }
    }

    let (Some(token), Some(call)) = (to, call) else {
        return found;
    };
    let has_transfer = |from: Address, recipient: Address, amount: U256| {
        report.transfers.iter().any(|t| {
            t.token == Some(token) && t.from == from && t.to == recipient && t.amount == amount
        })
    };
    let has_allowance = |spender: Address, at_least: U256, exact: bool| {
        report.allowance_changes.iter().any(|c| {
            c.token == token
                && c.owner == wallet
                && c.spender == spender
                && if exact {
                    c.amount == at_least
                } else {
                    c.amount >= at_least
                }
        })
    };
    match *call {
        KnownCall::Erc20Transfer {
            to: recipient,
            amount,
        } => {
            if !has_transfer(wallet, recipient, amount) {
                found.push(Discrepancy::MissingTokenTransfer { token, amount });
            }
        }
        KnownCall::Erc20TransferFrom {
            from,
            to: recipient,
            amount,
        } => {
            if !has_transfer(from, recipient, amount) {
                found.push(Discrepancy::MissingTokenTransfer { token, amount });
            }
        }
        KnownCall::Erc20Approve { spender, amount } => {
            if !has_allowance(spender, amount, true) {
                found.push(Discrepancy::MissingAllowanceChange { token, spender });
            }
        }
        KnownCall::Erc20IncreaseAllowance { spender, added } => {
            if !has_allowance(spender, added, false) {
                found.push(Discrepancy::MissingAllowanceChange { token, spender });
            }
        }
        // The simulator does not report NFT operator approvals, so this cannot be cross-checked. Signals decide
        KnownCall::SetApprovalForAll { .. } => {}
    }
    found
}

#[cfg(test)]
mod tests {
    use alloy_consensus::TxEip1559;
    use alloy_primitives::{B256, Bytes, TxKind};
    use mw_chain::calls::{encode_erc20_approve, encode_erc20_transfer};
    use mw_chain::decode_known_call;
    use mw_simulator::{AllowanceChange, AssetTransfer};

    use super::*;

    const WALLET: Address = Address::repeat_byte(0xaa);
    const TOKEN: Address = Address::repeat_byte(0x70);
    const BOB: Address = Address::repeat_byte(0xb0);

    fn decoded(to: Address, value: u64, input: Vec<u8>) -> DecodedTx {
        DecodedTx {
            tx: TxEip1559 {
                chain_id: 84532,
                to: TxKind::Call(to),
                value: U256::from(value),
                input: input.into(),
                ..Default::default()
            },
            payload: Bytes::new(),
            signing_hash: B256::ZERO,
        }
    }

    fn report(
        transfers: Vec<AssetTransfer>,
        allowance_changes: Vec<AllowanceChange>,
    ) -> SimulationReport {
        SimulationReport {
            success: true,
            gas_used: 50_000,
            block_number: 10,
            transfers,
            allowance_changes,
            unrecognized_changes: vec![],
            raw_response_hash: B256::ZERO,
        }
    }

    fn transfer(token: Option<Address>, to: Address, amount: u64) -> AssetTransfer {
        AssetTransfer {
            token,
            from: WALLET,
            to,
            amount: U256::from(amount),
            symbol: None,
            decimals: None,
        }
    }

    #[test]
    fn native_transfer_matches() {
        let tx = decoded(BOB, 5, vec![]);
        assert!(
            crosscheck(
                WALLET,
                &tx,
                None,
                &report(vec![transfer(None, BOB, 5)], vec![]),
                10
            )
            .is_empty()
        );
        assert_eq!(
            crosscheck(
                WALLET,
                &tx,
                None,
                &report(vec![transfer(None, BOB, 4)], vec![]),
                10
            ),
            vec![Discrepancy::MissingNativeTransfer {
                amount: U256::from(5)
            }]
        );
    }

    #[test]
    fn token_transfer_must_match_calldata() {
        let input = encode_erc20_transfer(BOB, U256::from(100));
        let call = decode_known_call(&input);
        let tx = decoded(TOKEN, 0, input);
        let ok = report(vec![transfer(Some(TOKEN), BOB, 100)], vec![]);
        assert!(crosscheck(WALLET, &tx, call.as_ref(), &ok, 10).is_empty());

        // The simulator reporting a different recipient is a disagreement
        let lying = report(
            vec![transfer(Some(TOKEN), Address::repeat_byte(0xee), 100)],
            vec![],
        );
        assert_eq!(
            crosscheck(WALLET, &tx, call.as_ref(), &lying, 10),
            vec![Discrepancy::MissingTokenTransfer {
                token: TOKEN,
                amount: U256::from(100)
            }]
        );
    }

    #[test]
    fn approve_must_match_calldata() {
        let input = encode_erc20_approve(BOB, U256::MAX);
        let call = decode_known_call(&input);
        let tx = decoded(TOKEN, 0, input);
        let change = |amount| AllowanceChange {
            token: TOKEN,
            owner: WALLET,
            spender: BOB,
            amount,
        };
        assert!(
            crosscheck(
                WALLET,
                &tx,
                call.as_ref(),
                &report(vec![], vec![change(U256::MAX)]),
                10
            )
            .is_empty()
        );
        assert_eq!(
            crosscheck(
                WALLET,
                &tx,
                call.as_ref(),
                &report(vec![], vec![change(U256::from(1))]),
                10
            ),
            vec![Discrepancy::MissingAllowanceChange {
                token: TOKEN,
                spender: BOB
            }]
        );
    }

    #[test]
    fn unrecognized_changes_are_discrepancies() {
        let tx = decoded(BOB, 0, vec![]);
        let mut r = report(vec![], vec![]);
        r.unrecognized_changes = vec!["ERC721 Transfer".into()];
        assert_eq!(
            crosscheck(WALLET, &tx, None, &r, 10),
            vec![Discrepancy::UnrecognizedChange("ERC721 Transfer".into())]
        );
    }

    #[test]
    fn block_must_match() {
        let tx = decoded(BOB, 0, vec![]);
        assert_eq!(
            crosscheck(WALLET, &tx, None, &report(vec![], vec![]), 11),
            vec![Discrepancy::BlockMismatch {
                expected: 11,
                simulated: 10
            }]
        );
    }
}

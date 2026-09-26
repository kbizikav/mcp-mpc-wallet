//! Known calls that B can read directly from calldata.
//!
//! The decoded calls are used to cross-check simulation results and to extract signals.

use alloy_primitives::{Address, U256};
use alloy_sol_types::{SolCall, sol};
use serde::Serialize;

sol! {
    function transfer(address to, uint256 amount) returns (bool);
    function approve(address spender, uint256 amount) returns (bool);
    function transferFrom(address from, address to, uint256 amount) returns (bool);
    function increaseAllowance(address spender, uint256 addedValue) returns (bool);
    function setApprovalForAll(address operator, bool approved);
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KnownCall {
    Erc20Transfer {
        to: Address,
        amount: U256,
    },
    Erc20Approve {
        spender: Address,
        amount: U256,
    },
    Erc20TransferFrom {
        from: Address,
        to: Address,
        amount: U256,
    },
    Erc20IncreaseAllowance {
        spender: Address,
        added: U256,
    },
    SetApprovalForAll {
        operator: Address,
        approved: bool,
    },
}

/// If the calldata is a known call, decode it strictly (no extra bytes).
pub fn decode_known_call(input: &[u8]) -> Option<KnownCall> {
    let selector: [u8; 4] = input.get(..4)?.try_into().ok()?;
    let call = match selector {
        transferCall::SELECTOR => {
            let c = transferCall::abi_decode_validate(input).ok()?;
            KnownCall::Erc20Transfer {
                to: c.to,
                amount: c.amount,
            }
        }
        approveCall::SELECTOR => {
            let c = approveCall::abi_decode_validate(input).ok()?;
            KnownCall::Erc20Approve {
                spender: c.spender,
                amount: c.amount,
            }
        }
        transferFromCall::SELECTOR => {
            let c = transferFromCall::abi_decode_validate(input).ok()?;
            KnownCall::Erc20TransferFrom {
                from: c.from,
                to: c.to,
                amount: c.amount,
            }
        }
        increaseAllowanceCall::SELECTOR => {
            let c = increaseAllowanceCall::abi_decode_validate(input).ok()?;
            KnownCall::Erc20IncreaseAllowance {
                spender: c.spender,
                added: c.addedValue,
            }
        }
        setApprovalForAllCall::SELECTOR => {
            let c = setApprovalForAllCall::abi_decode_validate(input).ok()?;
            KnownCall::SetApprovalForAll {
                operator: c.operator,
                approved: c.approved,
            }
        }
        _ => return None,
    };
    // Calldata with trailing extra bytes is not treated as a known call
    (call_len(&call) == input.len()).then_some(call)
}

fn call_len(call: &KnownCall) -> usize {
    4 + 32
        * match call {
            KnownCall::Erc20TransferFrom { .. } => 3,
            _ => 2,
        }
}

/// Build ERC-20 transfer calldata (used by tests and agent tooling).
pub fn encode_erc20_transfer(to: Address, amount: U256) -> Vec<u8> {
    transferCall { to, amount }.abi_encode()
}

/// Build ERC-20 approve calldata.
pub fn encode_erc20_approve(spender: Address, amount: U256) -> Vec<u8> {
    approveCall { spender, amount }.abi_encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_transfer_and_approve() {
        let to = Address::repeat_byte(5);
        assert_eq!(
            decode_known_call(&encode_erc20_transfer(to, U256::from(7))),
            Some(KnownCall::Erc20Transfer {
                to,
                amount: U256::from(7)
            })
        );
        assert_eq!(
            decode_known_call(&encode_erc20_approve(to, U256::MAX)),
            Some(KnownCall::Erc20Approve {
                spender: to,
                amount: U256::MAX
            })
        );
    }

    #[test]
    fn ignores_unknown_and_malformed() {
        assert_eq!(decode_known_call(&[]), None);
        assert_eq!(decode_known_call(&[0xde, 0xad, 0xbe, 0xef]), None);

        let mut truncated = encode_erc20_transfer(Address::ZERO, U256::from(1));
        truncated.pop();
        assert_eq!(decode_known_call(&truncated), None);

        let mut padded = encode_erc20_transfer(Address::ZERO, U256::from(1));
        padded.extend_from_slice(&[0u8; 32]);
        assert_eq!(decode_known_call(&padded), None);
    }
}

//! EVM まわり: 未署名 tx のデコード、既知 call のデコード、チェーン RPC の抽象化。

pub mod calls;
pub mod client;
pub mod rpc;
pub mod tx;
pub mod typed;

pub use calls::{KnownCall, decode_known_call};
pub use client::{BlockInfo, ChainClient, ChainError, MockChain};
pub use rpc::{FeeSuggestion, JsonRpcClient, ReceiptInfo};
pub use tx::{DecodeError, DecodedTx, decode_unsigned, encode_signed};
pub use typed::{DecodedTypedData, KnownTypedData, TypedDataError, decode_typed_data};

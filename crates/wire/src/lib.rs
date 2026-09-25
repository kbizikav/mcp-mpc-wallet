//! A↔B 間のプロトコル: メッセージ、フレーミング、接続上での MPC、mTLS。

pub mod conn;
pub mod messages;
pub mod tls;

pub use conn::{Connection, WireError};
pub use messages::{AtoB, BtoA};

//! The A↔B protocol: messages, framing, MPC over the connection, and mTLS.

pub mod conn;
pub mod messages;
pub mod tls;

pub use conn::{Connection, WireError};
pub use messages::{AtoB, BtoA};

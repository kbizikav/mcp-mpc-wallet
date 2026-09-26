//! Signing node A: an MCP server that runs next to the agent on the user's machine.
//!
//! A's share is treated as readable by the agent or malware. B's judgment is what protects the funds.
//! Of B's signing requests, A only partially signs the hash of a tx that A itself proposed.

pub mod mcp;
pub mod session;
pub mod shares;
pub mod txbuild;

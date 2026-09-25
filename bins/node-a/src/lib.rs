//! 署名ノード A: ユーザーの PC でエージェントと同居する MCP サーバ。
//!
//! A のシェアはエージェントやマルウェアに読まれうる前提で扱う。資金を守るのは B の判定。
//! A は B が求めた署名要求のうち、自分が提案した tx の hash にだけ部分署名する。

pub mod mcp;
pub mod session;
pub mod shares;
pub mod txbuild;

//! The chains this wallet runs on.

use std::fmt;
use std::str::FromStr;

/// A supported chain. Base Sepolia is the default; Base mainnet moves real funds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Network {
    #[default]
    BaseSepolia,
    Base,
}

impl Network {
    pub const ALL: [Self; 2] = [Self::BaseSepolia, Self::Base];

    pub const fn chain_id(self) -> u64 {
        match self {
            Self::BaseSepolia => 84532,
            Self::Base => 8453,
        }
    }

    /// Human-readable name (shown in the owner app)
    pub const fn name(self) -> &'static str {
        match self {
            Self::BaseSepolia => "Base Sepolia",
            Self::Base => "Base",
        }
    }

    /// The value of `--chain`
    pub const fn slug(self) -> &'static str {
        match self {
            Self::BaseSepolia => "base-sepolia",
            Self::Base => "base",
        }
    }

    pub const fn is_testnet(self) -> bool {
        matches!(self, Self::BaseSepolia)
    }

    /// Host of the Alchemy JSON-RPC endpoint (also allowlisted in the enclave's vsock-proxy)
    pub const fn alchemy_host(self) -> &'static str {
        match self {
            Self::BaseSepolia => "base-sepolia.g.alchemy.com",
            Self::Base => "base-mainnet.g.alchemy.com",
        }
    }

    /// The Alchemy RPC URL. It contains the API key, so keep it secret.
    pub fn alchemy_url(self, api_key: &str) -> String {
        format!("https://{}/v2/{api_key}", self.alchemy_host())
    }

    pub const fn explorer(self) -> &'static str {
        match self {
            Self::BaseSepolia => "https://sepolia.basescan.org",
            Self::Base => "https://basescan.org",
        }
    }

    pub fn from_chain_id(chain_id: u64) -> Option<Self> {
        Self::ALL.into_iter().find(|n| n.chain_id() == chain_id)
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|n| n.slug() == s)
            .ok_or_else(|| format!("unknown chain `{s}` (expected base-sepolia or base)"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_and_chain_ids_round_trip() {
        for n in Network::ALL {
            assert_eq!(n.slug().parse::<Network>(), Ok(n));
            assert_eq!(Network::from_chain_id(n.chain_id()), Some(n));
        }
        assert_eq!(Network::default(), Network::BaseSepolia);
        assert!("mainnet".parse::<Network>().is_err());
        assert_eq!(Network::from_chain_id(1), None);
    }

    #[test]
    fn alchemy_url_uses_the_network_host() {
        assert_eq!(
            Network::Base.alchemy_url("k"),
            "https://base-mainnet.g.alchemy.com/v2/k"
        );
        assert!(Network::BaseSepolia.is_testnet() && !Network::Base.is_testnet());
    }
}

//! netmux-core: platform-agnostic engine for a Linux network aggregation tool.
//!
//! Provides interface discovery, throughput statistics, load-balancing /
//! failover policies, minimal IP packet parsing, a Linux TUN device wrapper
//! and the aggregator that combines them. Designed to be embedded by the GPUI
//! frontend (`netmux-app`) or any other driver.

pub mod aggregator;
pub mod error;
pub mod interface;
pub mod logging;
pub mod packet;
pub mod policy;
pub mod stats;
pub mod tun;

pub use aggregator::{Aggregator, ForwardDecision, Mode, PcapGenerator};
pub use error::{NetmuxError, Result};
pub use interface::{Interface, InterfaceKind};
pub use policy::{
    AggregatorConfig, BalanceAlgorithm, CandidateIface, InterfacePolicy, Strategy,
};

/// Branding / application shared name.
pub const APP_NAME: &str = "NetMux";
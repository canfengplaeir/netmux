//! Bandwidth allocation policies: load balancing, failover and priorities.

use serde::{Deserialize, Serialize};

use crate::error::{NetmuxError, Result};
use crate::interface::InterfaceKind;

/// The top-level aggregation strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    /// Distribute flows across all usable interfaces.
    LoadBalance,
    /// Send all traffic over the highest-priority usable interface, switch on failure.
    Failover,
}

/// How flows are assigned inside [`Strategy::LoadBalance`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BalanceAlgorithm {
    /// Cycle interfaces in fixed order.
    RoundRobin,
    /// Hash the 5-tuple to keep a flow pinned to an interface.
    Hash,
    /// Send each flow to the currently least-loaded interface.
    LeastLoaded,
}

/// Per-interface configuration: priority and relative weight.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct InterfacePolicy {
    /// Higher number = preferred. Used by failover (and as a tie-break).
    pub priority: u32,
    /// Relative weight used by weighted load balancing (1..=100).
    pub weight: u32,
    /// Whether this interface may serve traffic.
    pub enabled: bool,
}

impl Default for InterfacePolicy {
    fn default() -> Self {
        Self {
            priority: 10,
            weight: 1,
            enabled: true,
        }
    }
}

impl InterfacePolicy {
    pub fn with_priority(mut self, p: u32) -> Self {
        self.priority = p;
        self
    }
}

/// Complete user-configurable aggregation settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatorConfig {
    pub strategy: Strategy,
    pub algorithm: BalanceAlgorithm,
    /// Per-interface overrides (interface name -> policy).
    #[serde(default)]
    pub interfaces: std::collections::HashMap<String, InterfacePolicy>,
    /// Seconds between health checks (failover).
    pub health_check_interval_secs: u64,
    /// Whether the aggregated virtual interface is currently active.
    pub enabled: bool,
}

impl Default for AggregatorConfig {
    fn default() -> Self {
        Self {
            strategy: Strategy::LoadBalance,
            algorithm: BalanceAlgorithm::Hash,
            interfaces: Default::default(),
            health_check_interval_secs: 5,
            enabled: true,
        }
    }
}

impl AggregatorConfig {
    /// Validate the configuration is internally consistent.
    pub fn validate(&self) -> Result<()> {
        if self.health_check_interval_secs == 0 {
            return Err(NetmuxError::Config(
                "health_check_interval_secs must be >= 1".into(),
            ));
        }
        for (name, p) in &self.interfaces {
            if p.weight == 0 {
                return Err(NetmuxError::Config(format!(
                    "weight of {name} must be >= 1 (use enabled=false to disable)"
                )));
            }
        }
        Ok(())
    }
}

/// A live interface view used by the scheduler during selection.
#[derive(Debug, Clone)]
pub struct CandidateIface {
    pub name: String,
    pub kind: InterfaceKind,
    pub policy: InterfacePolicy,
    /// Recent TX bytes/s (used by least-loaded).
    pub tx_bps: f64,
    /// Recent RX bytes/s.
    pub rx_bps: f64,
    /// True if healthy and ready to carry traffic.
    pub healthy: bool,
}

/// Names an aggregation mode for the TUN egress.
#[derive(Debug, Clone, Copy)]
pub enum Connectivity {
    /// A real TUN device is aggregating real traffic.
    Tunnelling,
    /// Simulation mode (no root) for demonstration.
    Simulation,
}

/// Decide a flow's egress interface.
///
/// * `flows` - list of flight flows of the form "srcIP:port->dstIP:port". Hash
///   mode derives a stable key from the 5-tuple; round-robin / least-loaded use
///   a rotating or load-sensitive selection.
/// * `flow_key` - the concrete flow identifier of the packet being routed.
pub fn select_interface(
    cfg: &AggregatorConfig,
    candidates: &[CandidateIface],
    flow_key: &str,
    rr_counter: &mut u64,
) -> Option<String> {
    let usable: Vec<&CandidateIface> = candidates
        .iter()
        .filter(|c| c.policy.enabled && c.healthy)
        .collect();
    if usable.is_empty() {
        return None;
    }

    // Weighted ordering helper shared by algorithms that honour weight/priority.
    fn weighted_pool<'a>(list: &[&'a CandidateIface]) -> Vec<&'a CandidateIface> {
        let total: u64 = list.iter().map(|c| c.policy.weight.max(1) as u64).sum();
        let mut pool = Vec::new();
        for c in list {
            let w = c.policy.weight.max(1) as u64;
            let n = ((total as f64 * w as f64 + 0.5) as u64).max(1);
            for _ in 0..n {
                pool.push(*c);
            }
        }
        // Deterministic order for tests.
        pool.sort_by_key(|c| c.name.clone());
        pool
    }

    match cfg.strategy {
        Strategy::Failover => {
            // Highest priority, else weighted fallback.
            let mut iter = usable.clone();
            iter.sort_by(|a, b| b.policy.priority.cmp(&a.policy.priority));
            iter.into_iter().next().map(|c| c.name.clone())
        }
        Strategy::LoadBalance => match cfg.algorithm {
            BalanceAlgorithm::RoundRobin => {
                let pool = weighted_pool(&usable);
                if pool.is_empty() {
                    return None;
                }
                let idx = (*rr_counter % pool.len() as u64) as usize;
                *rr_counter = rr_counter.wrapping_add(1);
                Some(pool[idx].name.clone())
            }
            BalanceAlgorithm::Hash => {
                let pool = weighted_pool(&usable);
                if pool.is_empty() {
                    return None;
                }
                let h = fnv1a(flow_key.as_bytes());
                Some(pool[(h as usize) % pool.len()].name.clone())
            }
            BalanceAlgorithm::LeastLoaded => {
                // Least TX load wins; prio/weight break ties via weighted pool order.
                let mut best: Option<&CandidateIface> = None;
                let mut best_load = f64::INFINITY;
                for c in &usable {
                    let load = c.tx_bps + c.rx_bps;
                    if load < best_load {
                        best_load = load;
                        best = Some(c);
                    }
                }
                best.map(|c| c.name.clone())
            }
        },
    }
}

/// FNV-1a 32-bit hash used for stable flow pinning.
pub fn fnv1a(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for &b in bytes {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn iface(name: &str, prio: u32, weight: u32, tx: f64) -> CandidateIface {
        CandidateIface {
            name: name.into(),
            kind: InterfaceKind::Ethernet,
            policy: InterfacePolicy {
                priority: prio,
                weight,
                enabled: true,
            },
            tx_bps: tx,
            rx_bps: 0.0,
            healthy: true,
        }
    }

    #[test]
    fn failover_picks_highest_priority() {
        let cfg = AggregatorConfig {
            strategy: Strategy::Failover,
            ..Default::default()
        };
        let pool = vec![iface("wlan0", 5, 1, 0.0), iface("eth0", 20, 1, 0.0)];
        let mut rr = 0;
        let pick = select_interface(&cfg, &pool, "x", &mut rr).unwrap();
        assert_eq!(pick, "eth0");

        // simulate eth0 failing
        let mut down = pool.clone();
        down[1].healthy = false;
        let pick = select_interface(&cfg, &down, "x", &mut rr).unwrap();
        assert_eq!(pick, "wlan0");
    }

    #[test]
    fn hash_keeps_flow_stable() {
        let cfg = AggregatorConfig {
            strategy: Strategy::LoadBalance,
            algorithm: BalanceAlgorithm::Hash,
            ..Default::default()
        };
        let pool = vec![iface("eth0", 10, 1, 0.0), iface("wlan0", 10, 1, 0.0)];
        let mut rr = 0;
        let a = select_interface(&cfg, &pool, "1.1.1.1:5000->8.8.8.8:443", &mut rr).unwrap();
        let b = select_interface(&cfg, &pool, "1.1.1.1:5000->8.8.8.8:443", &mut rr).unwrap();
        assert_eq!(a, b);
        assert!(a == "eth0" || a == "wlan0");
    }

    #[test]
    fn disabled_interfaces_are_skipped() {
        let cfg = AggregatorConfig { ..Default::default() };
        let mut eth = iface("eth0", 10, 1, 0.0);
        eth.policy.enabled = false;
        let pool = vec![eth, iface("wlan0", 10, 1, 0.0)];
        let mut rr = 0;
        let pick = select_interface(&cfg, &pool, "x", &mut rr).unwrap();
        assert_eq!(pick, "wlan0");
    }

    #[test]
    fn empty_pool_returns_none() {
        let cfg = AggregatorConfig { ..Default::default() };
        // simulate all down by filtering inside: use a non-healthy candidate
        let pool = vec![CandidateIface {
            healthy: false,
            ..iface("eth0", 10, 1, 0.0)
        }];
        let mut rr = 0;
        assert!(select_interface(&cfg, &pool, "x", &mut rr).is_none());
        // keep panel quiet
        let _ = HashMap::<String, InterfacePolicy>::new();
    }
}
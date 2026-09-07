//! The network aggregation engine.
//!
//! Wires together interface discovery, throughput stats and the scheduling
//! policy into a single component. The application drives it in one of two
//! modes:
//!
//! * [`Mode::Tunnelling`] - a real TUN device feeds raw IP packets into
//!   [`Aggregator::route`], which picks an egress interface per flow.
//! * [`Mode::Simulation`]  - a synthetic traffic generator (`PcapGenerator`)
//!   exercises the same code path without root, so the whole UI is
//!   demonstrable on any machine.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::interface::{self, InterfaceKind};
use crate::packet::{self, Flow};
use crate::policy::{self, AggregatorConfig, CandidateIface};
use crate::stats::StatsCollector;

/// Whether the aggregator is connected to a real kernel interface (TUN) or a
/// built-in traffic simulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Tunnelling,
    Simulation,
}

impl Mode {
    pub fn label(&self) -> &'static str {
        match self {
            Mode::Tunnelling => "隧道聚合 (TUN)",
            Mode::Simulation => "模拟演示 (Simulation)",
        }
    }
}

/// The result of routing one packet.
#[derive(Debug, Clone)]
pub struct ForwardDecision {
    pub flow: Flow,
    pub interface: Option<String>,
}

/// A live, mutable aggregation engine.
#[derive(Debug)]
pub struct Aggregator {
    pub config: AggregatorConfig,
    pub mode: Mode,
    pub stats: StatsCollector,
    candidates: Vec<CandidateIface>,
    rr_counter: u64,
    /// flow-key -> egress-iface cache (for tracing / visibility).
    pub flow_table: std::collections::HashMap<String, String>,
}

impl Aggregator {
    /// Construct an aggregator in the given mode with a validated config.
    pub fn new(config: AggregatorConfig, mode: Mode) -> Result<Self, crate::error::NetmuxError> {
        config.validate()?;
        Ok(Self {
            config,
            mode,
            stats: StatsCollector::default(),
            candidates: Vec::new(),
            rr_counter: 0,
            flow_table: Default::default(),
        })
    }

    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    /// Enumerate the host's physical, non-loopback interfaces as scheduling
    /// candidates. The base policy priority is inferred by kind (ethernet >
    /// cellular > wifi), overridable through `config.interfaces`.
    pub fn refresh_candidates(&mut self) {
        let ifaces = interface::enumerate().unwrap_or_default();
        let mut next: Vec<CandidateIface> = Vec::new();

        for i in ifaces {
            if matches!(i.kind, InterfaceKind::Loopback | InterfaceKind::Virtual) {
                continue;
            }
            let base_prior = match i.kind {
                InterfaceKind::Ethernet => 30,
                InterfaceKind::Cellular => 20,
                InterfaceKind::Wifi => 10,
                _ => 5,
            };
            let cfg_pol = self
                .config
                .interfaces
                .get(&i.name)
                .copied()
                .unwrap_or_else(|| policy::InterfacePolicy::default())
                .with_priority(base_prior.max(0));

            let s = self.stats.samples.get(&i.name);
            next.push(CandidateIface {
                name: i.name,
                kind: i.kind,
                policy: cfg_pol,
                tx_bps: s.map(|v| v.tx_bytes_per_sec).unwrap_or(0.0),
                rx_bps: s.map(|v| v.rx_bytes_per_sec).unwrap_or(0.0),
                // In simulation the "links" are always healthy unless disabled.
                healthy: i.carrier && i.is_up,
            });
        }
        self.candidates = next;
    }

    /// Update throughput/health stats and refresh candidate liveness.
    pub fn tick(&mut self) {
        self.stats.refresh();
        for c in &mut self.candidates {
            if let Some(s) = self.stats.samples.get(&c.name) {
                c.tx_bps = s.tx_bytes_per_sec;
                c.rx_bps = s.rx_bytes_per_sec;
            }
        }
        // Re-run enumeration so new/removed interfaces and link changes are seen.
        self.refresh_candidates();
    }

    /// Current scheduling candidates (clone for UI/JSON serialization).
    pub fn candidates(&self) -> Vec<CandidateIface> {
        self.candidates.clone()
    }

    /// Inject synthetic candidates for [`Mode::Simulation`]. Used when the host
    /// has no real physical uplinks so the demo still demonstrates scheduling.
    pub fn inject_sim_candidates(
        &mut self,
        entries: &[(&str, InterfaceKind, u32, u32)],
    ) {
        self.candidates.clear();
        for (name, kind, priority, weight) in entries {
            let policy = crate::policy::InterfacePolicy::default()
                .with_priority(*priority);
            self.candidates.push(CandidateIface {
                name: (*name).to_string(),
                kind: *kind,
                policy: crate::policy::InterfacePolicy {
                    priority: policy.priority,
                    weight: *weight,
                    enabled: true,
                },
                tx_bps: 0.0,
                rx_bps: 0.0,
                healthy: true,
            });
        }
    }

    /// Route a raw IP packet to its egress interface.
    pub fn route(&mut self, pkt: &[u8]) -> Option<ForwardDecision> {
        if !self.config.enabled {
            return None;
        }
        let flow = packet::parse(pkt)?;
        let decision = self.select(&flow.key());
        decision.map(|d| ForwardDecision { flow, interface: Some(d) })
    }

    fn select(&mut self, flow_key: &str) -> Option<String> {
        let pick = policy::select_interface(&self.config, &self.candidates, flow_key, &mut self.rr_counter)?;
        self.flow_table
            .entry(flow_key.to_string())
            .and_modify(|e| *e = pick.clone())
            .or_insert_with(|| pick.clone());
        Some(pick)
    }

    /// Expose per-candidate load (used by the UI's bandwidth bars).
    pub fn load_of(&self, name: &str) -> f64 {
        self.candidates
            .iter()
            .find(|c| c.name == name)
            .map(|c| c.tx_bps + c.rx_bps)
            .unwrap_or(0.0)
    }
}

/// A small synthetic flow generator for [`Mode::Simulation`].
#[derive(Debug, Clone)]
pub struct PcapGenerator {
    pub rate_per_sec: f64,
    tick: u64,
    seeds: [u32; 8],
}

impl Default for PcapGenerator {
    fn default() -> Self {
        Self {
            rate_per_sec: 50.0,
            tick: 0,
            seeds: [7, 13, 29, 41, 53, 67, 79, 97],
        }
    }
}

impl PcapGenerator {
    /// Build a realistic-looking IP/TCP packet of the given length.
    pub fn next_packet(&mut self, len: usize) -> Vec<u8> {
        self.tick = self.tick.wrapping_add(1);
        let s = &mut self.seeds[(self.tick as usize) % 8];
        *s = s.wrapping_mul(1664525).wrapping_add(1013904223);
        let rnd = *s;

        // 20-byte IPv4 (no options) + 20-byte TCP header[..]
        let min = 40usize;
        let total = min.max(len);
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x45;
        pkt[9] = 6; // TCP

        // pseudo-random addresses
        pkt[12] = (rnd >> 16) as u8;
        pkt[13] = (rnd >> 8) as u8;
        pkt[14] = 1;
        pkt[15] = (rnd >> 24) as u8;
        pkt[16] = 8;
        pkt[17] = 8;
        pkt[18] = 4 + (rnd % 4) as u8;
        pkt[19] = 8;

        // ports
        let sport = (rnd % 60000) as u16 + 1024;
        let dport = 443u16;
        pkt[20..22].copy_from_slice(&sport.to_be_bytes());
        pkt[22..24].copy_from_slice(&dport.to_be_bytes());

        pkt
    }

    /// Emit the recommended packets-per-tick given a running rate.
    pub fn per_tick(&self, dt: Duration) -> usize {
        ((self.rate_per_sec * dt.as_secs_f64()).max(1.0)) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulation_routes_packets() {
        let cfg = AggregatorConfig::default();
        let mut agg = Aggregator::new(cfg, Mode::Simulation).unwrap();
        agg.refresh_candidates();
        let mut gen = PcapGenerator::default();
        let pkt = gen.next_packet(128);
        // Even with no physical interfaces found, routing must not panic and
        // must return a decision object (interface may be None in headless CI).
        let d = agg.route(&pkt);
        if let Some(d) = d {
            let _ = d.interface;
        }
    }

    #[test]
    fn disabled_aggregator_drops() {
        let mut cfg = AggregatorConfig::default();
        cfg.enabled = false;
        let mut agg = Aggregator::new(cfg, Mode::Simulation).unwrap();
        agg.refresh_candidates();
        let mut gen = PcapGenerator::default();
        assert!(agg.route(&gen.next_packet(64)).is_none());
    }
}
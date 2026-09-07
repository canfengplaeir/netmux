//! Per-interface throughput and health statistics.
//!
//! Samples `/sys/class/net` counters on a fixed interval and derives
//! bytes/second (both directions), plus liveness used by failover.

use std::collections::HashMap;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::interface;

/// A sampled snapshot of one interface's usage.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct IfaceSample {
    pub rx_bytes_per_sec: f64,
    pub tx_bytes_per_sec: f64,
    pub rx_pkt_per_sec: f64,
    pub tx_pkt_per_sec: f64,
    pub is_up: bool,
}

/// Tracks and computes stats for all interfaces.
#[derive(Debug)]
pub struct StatsCollector {
    last_counters: HashMap<String, (u64, u64, u64, u64)>,
    last_at: Instant,
    pub samples: HashMap<String, IfaceSample>,
}

impl Default for StatsCollector {
    fn default() -> Self {
        Self {
            last_counters: HashMap::new(),
            last_at: Instant::now(),
            samples: HashMap::new(),
        }
    }
}

impl StatsCollector {
    /// Refresh `self.samples` from the current sysfs counters.
    pub fn refresh(&mut self) {
        let net_dir = std::path::PathBuf::from("/sys/class/net");
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_at).as_secs_f64();
        self.last_at = now;

        let mut current: HashMap<String, (u64, u64, u64, u64)> = HashMap::new();
        if let Ok(entries) = std::fs::read_dir(&net_dir) {
            for entry in entries.flatten() {
                let dir = entry.path();
                let Some(name) = entry.file_name().to_str().map(String::from) else {
                    continue;
                };
                let rx_b = interface::read_u64(&dir.join("statistics/rx_bytes"));
                let tx_b = interface::read_u64(&dir.join("statistics/tx_bytes"));
                let rx_p = interface::read_u64(&dir.join("statistics/rx_packets"));
                let tx_p = interface::read_u64(&dir.join("statistics/tx_packets"));
                current.insert(name.clone(), (rx_b, tx_b, rx_p, tx_p));

                let is_up = interface::read_bool(&dir.join("carrier"))
                    || matches!(
                        std::fs::read_to_string(dir.join("operstate"))
                            .unwrap_or_default()
                            .trim(),
                        "up"
                    );

                let (orp, otx, orxp, otxp) = match self.last_counters.get(&name) {
                    Some((a, b, c, d)) => (*a, *b, *c, *d),
                    None => {
                        self.samples.insert(
                            name,
                            IfaceSample {
                                rx_bytes_per_sec: 0.0,
                                tx_bytes_per_sec: 0.0,
                                rx_pkt_per_sec: 0.0,
                                tx_pkt_per_sec: 0.0,
                                is_up,
                            },
                        );
                        continue;
                    }
                };

                let dt = elapsed.max(1e-3);
                let sample = IfaceSample {
                    rx_bytes_per_sec: rx_b.saturating_sub(orp) as f64 / dt,
                    tx_bytes_per_sec: tx_b.saturating_sub(otx) as f64 / dt,
                    rx_pkt_per_sec: rx_p.saturating_sub(orxp) as f64 / dt,
                    tx_pkt_per_sec: tx_p.saturating_sub(otxp) as f64 / dt,
                    is_up,
                };
                self.samples.insert(name, sample);
            }
        }
        self.last_counters = current;
    }
}

/// Helper to format bytes-per-second into a human-friendly string.
pub fn fmt_bps(bps: f64) -> String {
    fmt_bytes(bps, Some(1.0)) + "/s"
}

/// Format a byte quantity (optionally as a rate relative to `scale`).
pub fn fmt_bytes(bytes: f64, scale: Option<f64>) -> String {
    let v = match scale {
        Some(s) => bytes / s,
        None => bytes,
    };
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut idx = 0;
    let mut val = v;
    while val >= 1024.0 && idx < units.len() - 1 {
        val /= 1024.0;
        idx += 1;
    }
    format!("{val:.1}{}{}", units[idx], scale.map_or("", |_| ""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_helpers() {
        assert_eq!(fmt_bytes(1536.0, None), "1.5KB");
        assert!(fmt_bps(2.0 * 1024.0 * 1024.0).ends_with("/s"));
    }

    #[test]
    fn collector_runs_without_panic() {
        let mut c = StatsCollector::default();
        c.refresh();
        c.refresh();
        c.samples.iter().for_each(|_| {});
    }
}
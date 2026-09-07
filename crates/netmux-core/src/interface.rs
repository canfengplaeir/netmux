//! Network interface discovery and OS-level byte counters.
//!
//! Reads `/sys/class/net` for reliable per-interface TX/RX byte counters and
//! link/oper state. This is the Linux-native source of truth for throughput
//! and health monitoring.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{NetmuxError, Result};

/// A logical network interface discovered on the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interface {
    /// Kernel interface name, e.g. `eth0`, `wlan0`, `enp3s0`.
    pub name: String,
    /// Human friendly display name.
    pub display_name: String,
    /// Link address (MAC) if present, `None` for e.g. loopback on some systems.
    pub mac: Option<String>,
    /// Whether the interface is administratively up (`IFF_UP` kernel flag).
    pub is_up: bool,
    /// Physical link carriers: true when `carrier` sysfs attr is `1`.
    pub carrier: bool,
    /// Interface type classification.
    pub kind: InterfaceKind,
    /// Cumulative bytes received since boot (from `/sys/class/net/<n>/statistics/rx_bytes`).
    pub rx_bytes: u64,
    /// Cumulative bytes transmitted since boot.
    pub tx_bytes: u64,
}

/// Coarse classification helper used by the UI to group interfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceKind {
    /// Wired ethernet.
    Ethernet,
    /// Wireless LAN.
    Wifi,
    /// Cellular / mobile data modems.
    Cellular,
    /// Loopback.
    Loopback,
    /// Virtual devices (bridges, bonds, tun/tap) that are not physical uplinks.
    Virtual,
    /// Unknown / unclassified.
    Other,
}

pub(crate) fn read_u64(path: &Path) -> u64 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

pub(crate) fn read_bool(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

fn classify(name: &str, operstate: &str) -> InterfaceKind {
    if name.starts_with("lo") {
        InterfaceKind::Loopback
    } else if name.starts_with("wl") || name.starts_with("wlan") || name.starts_with("wifi") {
        InterfaceKind::Wifi
    } else if name.starts_with("wwan") || name.starts_with("rmnet") || name.starts_with("usb")
        || name.starts_with("eth-usb")
    {
        InterfaceKind::Cellular
    } else if name.starts_with("en") || name.starts_with("eth") || name.starts_with("em") {
        InterfaceKind::Ethernet
    } else if name.starts_with("virbr") || name.starts_with("br")
        || name.starts_with("docker")
        || name.starts_with("tun") || name.starts_with("tap") || name.starts_with("veth")
        || name.starts_with("bond") || name.starts_with("netmux")
        || name.starts_with("vpn") || name.starts_with("utun")
        || name.starts_with("tailscale")
    {
        InterfaceKind::Virtual
    } else {
        match operstate {
            _ => {
                // Heuristic: virtual bridges are common catch-alls.
                if name.starts_with("lo") {
                    InterfaceKind::Loopback
                } else {
                    InterfaceKind::Other
                }
            }
        }
    }
}

/// Enumerate all interfaces by scanning `/sys/class/net`.
pub fn enumerate() -> Result<Vec<Interface>> {
    let net_dir = PathBuf::from("/sys/class/net");
    let entries = std::fs::read_dir(&net_dir)
        .map_err(|e| NetmuxError::io("reading /sys/class/net", e))?;

    let mut out = Vec::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        let name = match dir.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        let operstate = std::fs::read_to_string(dir.join("operstate"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".into());
        // Authoritative admin state: the `IFF_UP` bit of the kernel flags.
        // `operstate` alone is unreliable — USB NICs commonly report "unknown"
        // while being up and carrying traffic. The flags file is hex ("0x1003").
        let flags = std::fs::read_to_string(dir.join("flags"))
            .ok()
            .and_then(|s| u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);
        let is_up = flags & 0x1 != 0;
        let kind = classify(&name, &operstate);

        let mac = std::fs::read_to_string(dir.join("address"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != "00:00:00:00:00:00");

        out.push(Interface {
            display_name: name.clone(),
            name,
            mac,
            is_up,
            carrier: read_bool(&dir.join("carrier")),
            kind,
            rx_bytes: read_u64(&dir.join("statistics/rx_bytes")),
            tx_bytes: read_u64(&dir.join("statistics/tx_bytes")),
        });
    }

    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Snapshot counter bytes for every interface (for delta computation).
pub fn counter_map() -> HashMap<String, (u64, u64)> {
    let net_dir = PathBuf::from("/sys/class/net");
    let mut map = HashMap::new();
    if let Ok(entries) = std::fs::read_dir(&net_dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str().map(String::from) {
                let dir = entry.path();
                let rx = read_u64(&dir.join("statistics/rx_bytes"));
                let tx = read_u64(&dir.join("statistics/tx_bytes"));
                map.insert(name, (rx, tx));
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_works() {
        assert_eq!(classify("eth0", "up"), InterfaceKind::Ethernet);
        assert_eq!(classify("wlP2p33s0", "up"), InterfaceKind::Wifi);
        assert_eq!(classify("lo", "unknown"), InterfaceKind::Loopback);
        assert_eq!(classify("wwan0", "unknown"), InterfaceKind::Cellular);
        assert_eq!(classify("br0", "up"), InterfaceKind::Virtual);
        assert_eq!(classify("netmux0", "up"), InterfaceKind::Virtual);
    }
}
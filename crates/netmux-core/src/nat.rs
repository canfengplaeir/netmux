//! Userspace NAT session table for the aggregator's data plane.
//!
//! Outbound packets from the TUN (source = the TUN address) are rewritten to
//! use the selected egress interface's IP address and sent out the raw egress
//! socket. Reply packets arriving on that interface are matched against the
//! session table and reverse-NATed back into the TUN.
//!
//! Sessions are keyed by the client 4-tuple; the NAT keeps the client source
//! port as the external source port (port-preserving), which is safe across
//! distinct egress IPs.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::packet;

/// A tracked bidirectional NAT session.
#[derive(Debug, Clone)]
pub struct Session {
    pub client_ip: Ipv4Addr,
    pub client_port: u16,
    pub server_ip: Ipv4Addr,
    pub server_port: u16,
    pub proto: u8,
    pub egress_iface: String,
    pub egress_ip: Ipv4Addr,
    /// Packets forwarded on the outbound leg.
    pub tx_packets: u64,
    /// Packets forwarded on the return leg.
    pub rx_packets: u64,
}

/// Outbound key: (proto, client, sport, server, dport).
type OutKey = (u8, Ipv4Addr, u16, Ipv4Addr, u16);
/// Return key: (proto, server, sport, egress_ip, client_port).
type RetKey = (u8, Ipv4Addr, u16, Ipv4Addr, u16);

#[derive(Debug, Default)]
pub struct NatTable {
    by_outbound: HashMap<OutKey, Session>,
    by_return: HashMap<RetKey, u64>, // -> session index
    index: u64,
}

impl NatTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of live sessions.
    pub fn sessions(&self) -> usize {
        self.by_outbound.len()
    }

    /// Register (or reuse) a session for an outbound flow. Returns the session.
    pub fn register(&mut self, flow: &packet::Flow, egress_iface: &str, egress_ip: Ipv4Addr) -> Option<Session> {
        let client_ip = parse_ip(flow.src.as_str())?;
        let server_ip = parse_ip(flow.dst.as_str())?;
        let key = (flow.proto, client_ip, flow.sport, server_ip, flow.dport);
        if let Some(s) = self.by_outbound.get(&key) {
            return Some(s.clone());
        }
        let ret_key = (flow.proto, server_ip, flow.dport, egress_ip, flow.sport);
        let session = Session {
            client_ip,
            client_port: flow.sport,
            server_ip,
            server_port: flow.dport,
            proto: flow.proto,
            egress_iface: egress_iface.to_string(),
            egress_ip,
            tx_packets: 0,
            rx_packets: 0,
        };
        self.by_outbound.insert(key, session.clone());
        self.by_return.insert(ret_key, self.index);
        self.index = self.index.wrapping_add(1);
        Some(session)
    }

    /// Look up the session for a return packet (already addressed to the
    /// egress IP). Returns the session to reverse-NAT into.
    pub fn lookup_return(&self, proto: u8, src_ip: Ipv4Addr, sport: u16, dst_ip: Ipv4Addr, dport: u16) -> Option<Session> {
        let ret_key = (proto, src_ip, sport, dst_ip, dport);
        self.by_return.get(&ret_key).and_then(|_| {
            self.by_outbound
                .values()
                .find(|s| {
                    s.proto == proto
                        && s.server_ip == src_ip
                        && s.server_port == sport
                        && s.egress_ip == dst_ip
                        && s.client_port == dport
                })
                .cloned()
        })
    }
}

fn parse_ip(s: &str) -> Option<Ipv4Addr> {
    s.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(proto: u8, client: &str, sport: u16, server: &str, dport: u16) -> packet::Flow {
        packet::Flow {
            src: client.into(),
            dst: server.into(),
            proto,
            sport,
            dport,
        }
    }

    #[test]
    fn registers_and_roundtrips() {
        let mut t = NatTable::new();
        let f = flow(6, "10.99.0.1", 12345, "8.8.8.8", 443);
        let s = t
            .register(&f, "wlan0", Ipv4Addr::new(192, 168, 31, 49))
            .unwrap();
        assert_eq!(s.egress_iface, "wlan0");
        assert_eq!(t.sessions(), 1);

        // Return packet: src=server:443, dst=egress_ip:12345
        let ret = t
            .lookup_return(6, Ipv4Addr::new(8, 8, 8, 8), 443, Ipv4Addr::new(192, 168, 31, 49), 12345)
            .unwrap();
        assert_eq!(ret.client_ip, Ipv4Addr::new(10, 99, 0, 1));
        assert_eq!(ret.client_port, 12345);

        // Different server port must NOT match.
        assert!(t
            .lookup_return(6, Ipv4Addr::new(8, 8, 8, 8), 53, Ipv4Addr::new(192, 168, 31, 49), 12345)
            .is_none());
    }

    #[test]
    fn same_flow_reuses_session() {
        let mut t = NatTable::new();
        let f = flow(17, "10.99.0.1", 5000, "1.1.1.1", 53);
        t.register(&f, "eth0", Ipv4Addr::new(10, 0, 0, 5)).unwrap();
        let s2 = t
            .register(&f, "eth0", Ipv4Addr::new(10, 0, 0, 5))
            .unwrap();
        assert_eq!(t.sessions(), 1);
        assert_eq!(s2.client_port, 5000);
    }

    #[test]
    fn two_flows_use_two_sessions() {
        let mut t = NatTable::new();
        t.register(&flow(6, "10.99.0.1", 1000, "8.8.8.8", 443), "wlan0", Ipv4Addr::new(192, 168, 31, 49))
            .unwrap();
        t.register(&flow(6, "10.99.0.1", 1001, "8.8.8.8", 443), "eth0", Ipv4Addr::new(10, 0, 0, 5))
            .unwrap();
        assert_eq!(t.sessions(), 2);
    }
}

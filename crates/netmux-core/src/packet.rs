//! Minimal IPv4/IPv6 packet parsing needed to identify a flow.
//!
//! The aggregator reads layer-3 packets from the TUN device. To apply a
//! per-flow policy we need a stable "5-tuple" key. Only TCP/UDP carry port
//! numbers that matter for the key; other protocols hash on addresses + proto.
//!
//! This module also provides the checksum helpers used by the userspace NAT
//! forwarder (source/destination rewrite for egress and return traffic).

use std::net::Ipv4Addr;

/// A parsed flow descriptor.
#[derive(Debug, Clone)]
pub struct Flow {
    pub src: String,
    pub dst: String,
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
}

impl Flow {
    /// Human-readable, stable identifier used for hashing and logging.
    pub fn key(&self) -> String {
        format!("{}:{}->{}:{}", self.src, self.sport, self.dst, self.dport)
    }
}

/// Internet checksum (RFC 1071) over `data`.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// TCP/UDP checksum covering the pseudo-header and the segment, treating the
/// 2-byte checksum field (offset 16) as zero per RFC 793 / 768.
pub fn transport_checksum(src: [u8; 4], dst: [u8; 4], proto: u8, l4: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // 12-byte pseudo-header: src(4) dst(4) zero(1) proto(1) len(2)
    let mut ph = [0u8; 12];
    ph[..4].copy_from_slice(&src);
    ph[4..8].copy_from_slice(&dst);
    ph[9] = proto;
    ph[10..12].copy_from_slice(&(l4.len() as u16).to_be_bytes());
    let mut i = 0;
    while i + 1 < ph.len() {
        sum += u16::from_be_bytes([ph[i], ph[i + 1]]) as u32;
        i += 2;
    }

    // Segment with the checksum field zeroed.
    i = 0;
    while i + 1 < l4.len() {
        let bytes = if i == 16 { [0u8, 0] } else { [l4[i], l4[i + 1]] };
        sum += u16::from_be_bytes(bytes) as u32;
        i += 2;
    }
    if l4.len() % 2 == 1 {
        sum += (l4[l4.len() - 1] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Rewrite the IPv4 source address and fix the IP header checksum plus the
/// TCP/UDP checksum (which covers the pseudo-header). Returns false for
/// non-IPv4 or truncated packets.
pub fn rewrite_ipv4_source(pkt: &mut [u8], new_src: Ipv4Addr) -> bool {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return false;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if pkt.len() < ihl {
        return false;
    }
    pkt[12..16].copy_from_slice(&new_src.octets());

    pkt[10] = 0;
    pkt[11] = 0;
    let ip_sum = checksum(&pkt[..ihl]);
    pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    let proto = pkt[9];
    if matches!(proto, 6 | 17) && pkt.len() >= ihl + 18 {
        let dst = [pkt[16], pkt[17], pkt[18], pkt[19]];
        let l4 = &pkt[ihl..];
        let sum = transport_checksum(new_src.octets(), dst, proto, l4);
        pkt[ihl + 16..ihl + 18].copy_from_slice(&sum.to_be_bytes());
    }
    true
}

/// Rewrite the IPv4 destination address and fix checksums (return path).
pub fn rewrite_ipv4_dest(pkt: &mut [u8], new_dst: Ipv4Addr) -> bool {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return false;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if pkt.len() < ihl {
        return false;
    }
    pkt[16..20].copy_from_slice(&new_dst.octets());

    pkt[10] = 0;
    pkt[11] = 0;
    let ip_sum = checksum(&pkt[..ihl]);
    pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    let proto = pkt[9];
    if matches!(proto, 6 | 17) && pkt.len() >= ihl + 18 {
        let src = [pkt[12], pkt[13], pkt[14], pkt[15]];
        let l4 = &pkt[ihl..];
        let sum = transport_checksum(src, new_dst.octets(), proto, l4);
        pkt[ihl + 16..ihl + 18].copy_from_slice(&sum.to_be_bytes());
    }
    true
}

/// Parse the outer header of an IP packet and return the flow.
///
/// Returns `None` for malformed/unsupported packets.
pub fn parse(pkt: &[u8]) -> Option<Flow> {
    if pkt.is_empty() {
        return None;
    }
    let version = pkt[0] >> 4;
    match version {
        4 => parse_v4(pkt),
        6 => parse_v6(pkt),
        _ => None,
    }
}

fn parse_v4(pkt: &[u8]) -> Option<Flow> {
    if pkt.len() < 20 {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < ihl {
        return None;
    }
    let proto = pkt[9];
    let src = format!("{}.{}.{}.{}", pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = format!("{}.{}.{}.{}", pkt[16], pkt[17], pkt[18], pkt[19]);

    let mut sport = 0u16;
    let mut dport = 0u16;
    if (proto == 6 || proto == 17) && pkt.len() >= ihl + 4 {
        sport = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
        dport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
    }

    Some(Flow {
        src,
        dst,
        proto,
        sport,
        dport,
    })
}

/// Very tolerant IPv6 parser — resolves the longest common-case transport for
/// TCP/UDP after a minimal extension-header walk for the transport layer.
fn parse_v6(pkt: &[u8]) -> Option<Flow> {
    if pkt.len() < 40 {
        return None;
    }
    let src = ip6(&pkt[8..24]);
    let dst = ip6(&pkt[24..40]);
    let mut next_header = pkt[6];
    let mut offset = 40usize;

    // Walk a small number of extension headers (hop-by-hop, routing, dest opts).
    for _ in 0..8 {
        match next_header {
            6 | 17 => break, // TCP / UDP
            0 | 43 | 60 | 135 => {
                // ext header: length field at [offset+1]; (len+1)*8 bytes
                if pkt.len() < offset + 2 {
                    return None;
                }
                let ext_len = ((pkt[offset + 1] as usize) + 1) * 8;
                next_header = pkt[offset];
                offset += ext_len;
            }
            _ => break,
        }
    }

    let mut sport = 0u16;
    let mut dport = 0u16;
    if matches!(next_header, 6 | 17) && pkt.len() >= offset + 4 {
        sport = u16::from_be_bytes([pkt[offset], pkt[offset + 1]]);
        dport = u16::from_be_bytes([pkt[offset + 2], pkt[offset + 3]]);
    }

    Some(Flow {
        src,
        dst,
        proto: next_header,
        sport,
        dport,
    })
}

fn ip6(b: &[u8]) -> String {
    let mut out = String::new();
    // compress the longest run of zero hextets for readability (best-effort)
    let words: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();

    let mut best_start = usize::MAX;
    let mut best_len = 0usize;
    let mut cur_start = usize::MAX;
    let mut cur_len = 0usize;
    for (i, w) in words.iter().enumerate() {
        if *w == 0 {
            if cur_start == usize::MAX {
                cur_start = i;
                cur_len = 1;
            } else {
                cur_len += 1;
            }
            if cur_len > best_len {
                best_len = cur_len;
                best_start = cur_start;
            }
        } else {
            cur_start = usize::MAX;
            cur_len = 0;
        }
    }
    let compress = best_len >= 2;

    for (i, w) in words.iter().enumerate() {
        if compress && i >= best_start && i < best_start + best_len {
            if i == best_start {
                out.push_str(if best_start == 0 { ":" } else { ":" });
            }
            continue;
        }
        if out.len() > 0 && !out.ends_with(':') {
            out.push(':');
        }
        out.push_str(&format!("{w:x}"));
    }
    if compress && best_start + best_len == 8 {
        out.push(':');
    }
    if out.is_empty() {
        out.push_str("::");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_tcp() {
        let mut p = vec![0u8; 20];
        p[0] = 0x45; // v4, ihl=5
        p[9] = 6; // TCP
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[8, 8, 8, 8]);
        p.extend_from_slice(&0x1f90u16.to_be_bytes()); // 8080
        p.extend_from_slice(&0x01bbu16.to_be_bytes()); // 443
        let f = parse(&p).unwrap();
        assert_eq!(f.src, "10.0.0.1");
        assert_eq!(f.dst, "8.8.8.8");
        assert_eq!(f.sport, 8080);
        assert_eq!(f.dport, 443);
        assert_eq!(f.key(), "10.0.0.1:8080->8.8.8.8:443");
    }

    #[test]
    fn parses_ipv4_icmp_no_ports() {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[9] = 1; // ICMP
        let f = parse(&p).unwrap();
        assert_eq!(f.sport, 0);
        assert_eq!(f.dport, 0);
    }

    #[test]
    fn rejects_too_short() {
        assert!(parse(&[0u8]).is_none());
    }

    #[test]
    fn checksum_known_vector() {
        // Classic RFC 1071 example: 0x4500 0x0073 0x0000 0x4000 0x4011 0x0000 ...
        let hdr = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(checksum(&hdr), 0xb861);
    }

    #[test]
    fn transport_checksum_matches_pseudo_header_checksum() {
        // The TCP/UDP checksum equals the plain checksum over the 12-byte
        // pseudo-header + segment with the checksum field zeroed.
        let src = [10u8, 0, 0, 1];
        let dst = [8u8, 8, 8, 8];
        let l4 = [0u8; 8];
        let mut buf = [0u8; 20];
        buf[..4].copy_from_slice(&src);
        buf[4..8].copy_from_slice(&dst);
        buf[9] = 17;
        buf[10..12].copy_from_slice(&8u16.to_be_bytes());
        let expected = checksum(&buf);
        assert_eq!(transport_checksum(src, dst, 17, &l4), expected);
    }

    #[test]
    fn source_rewrite_fixes_checksums() {
        // Build a minimal TCP SYN-like packet and verify the IP header
        // checksum validates after the rewrite.
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[10, 99, 0, 1]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        pkt[20..22].copy_from_slice(&0x1234u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&0x01bbu16.to_be_bytes());
        pkt[24..28].copy_from_slice(&0u32.to_be_bytes()); // seq
        // a plausible pre-rewrite checksum
        let pre = checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&pre.to_be_bytes());

        let new_src = std::net::Ipv4Addr::new(192, 168, 31, 49);
        assert!(rewrite_ipv4_source(&mut pkt, new_src));
        assert_eq!(&pkt[12..16], &[192, 168, 31, 49]);
        // header checksum must now validate
        let saved = [pkt[10], pkt[11]];
        pkt[10] = 0;
        pkt[11] = 0;
        assert_eq!(checksum(&pkt[..20]), u16::from_be_bytes(saved));
    }
}
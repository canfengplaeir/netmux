//! Minimal IPv4/IPv6 packet parsing needed to identify a flow.
//!
//! The aggregator reads layer-3 packets from the TUN device. To apply a
//! per-flow policy we need a stable "5-tuple" key. Only TCP/UDP carry port
//! numbers that matter for the key; other protocols hash on addresses + proto.

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
}
//! Native NetBIOS Name Service (NBNS) client over UDP/137.
//!
//! Implements the "node status" query (what `nmblookup -A <ip>` does), which
//! returns the remote name table: registered NetBIOS names with their suffixes
//! and flags, plus the adapter MAC address. This needs no external tooling.
//!
//! References: RFC 1001/1002 (NetBIOS over TCP/UDP).

use crate::output::NetbiosName;
use anyhow::{Context, Result, bail};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Result of a NetBIOS node-status query.
#[derive(Debug, Clone, Default)]
pub struct NodeStatus {
    pub names: Vec<NetbiosName>,
    pub mac: Option<String>,
    /// Best-guess workgroup/domain derived from the name table.
    pub workgroup: Option<String>,
}

/// NBSTAT query type.
const QTYPE_NBSTAT: u16 = 0x0021;
/// Internet class.
const QCLASS_IN: u16 = 0x0001;

/// First-level encode a 16-byte NetBIOS name into its 32-byte representation.
///
/// Each byte is split into two nibbles, each added to `b'A'`.
fn encode_netbios_name(name: &str, suffix: u8) -> Vec<u8> {
    // Build the padded 16-byte name: up to 15 chars (space padded) + 1 suffix.
    let mut raw = [b' '; 16];
    let bytes = name.as_bytes();
    let n = bytes.len().min(15);
    raw[..n].copy_from_slice(&bytes[..n]);
    raw[15] = suffix;

    let mut out = Vec::with_capacity(32);
    for &b in &raw {
        out.push(b'A' + (b >> 4));
        out.push(b'A' + (b & 0x0F));
    }
    out
}

/// Build a node-status request packet for the wildcard name `*`.
fn build_node_status_request(txid: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(50);
    // Header
    pkt.extend_from_slice(&txid.to_be_bytes()); // transaction id
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // flags: standard query, unicast
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question: QNAME = length-prefixed encoded "*" name, then 0x00 terminator.
    let encoded = encode_netbios_name("*", 0x00);
    pkt.push(encoded.len() as u8); // 0x20 (32)
    pkt.extend_from_slice(&encoded);
    pkt.push(0x00); // root label terminator

    pkt.extend_from_slice(&QTYPE_NBSTAT.to_be_bytes());
    pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());
    pkt
}

/// Skip a DNS/NetBIOS-encoded name in `buf` starting at `pos`, returning the
/// position just past it. Handles label sequences and compression pointers.
fn skip_name(buf: &[u8], mut pos: usize) -> Result<usize> {
    loop {
        let len = *buf.get(pos).context("truncated name")?;
        if len == 0 {
            return Ok(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer: 2 bytes total.
            return Ok(pos + 2);
        }
        pos += 1 + len as usize;
        if pos > buf.len() {
            bail!("name label runs past end of buffer");
        }
    }
}

/// Decode the suffix byte into a human-readable service description.
fn suffix_description(suffix: u8, is_group: bool) -> &'static str {
    match (suffix, is_group) {
        (0x00, false) => "Workstation Service",
        (0x00, true) => "Domain/Workgroup Name",
        (0x03, _) => "Messenger Service",
        (0x06, _) => "RAS Server Service",
        (0x1b, _) => "Domain Master Browser",
        (0x1c, true) => "Domain Controllers",
        (0x1d, _) => "Master Browser",
        (0x1e, true) => "Browser Service Elections",
        (0x1f, _) => "NetDDE Service",
        (0x20, _) => "File Server Service",
        (0x21, _) => "RAS Client Service",
        (0x22, _) => "Exchange Interchange",
        (0x23, _) => "Exchange Store",
        (0x24, _) => "Exchange Directory",
        (0x2b, _) => "Lotus Notes Server",
        (0x87, _) => "Exchange MTA",
        (0xbe, _) => "Network Monitor Agent",
        (0xbf, _) => "Network Monitor Application",
        _ => "Unknown Service",
    }
}

/// Render the 16-bit NAME_FLAGS field as a readable string.
fn render_flags(flags: u16) -> String {
    let mut parts = Vec::new();
    // Owner node type (bits 14-13).
    let ont = (flags >> 13) & 0x03;
    parts.push(match ont {
        0 => "B",
        1 => "P",
        2 => "M",
        _ => "H",
    });
    if flags & 0x1000 != 0 {
        parts.push("DEREGISTERING");
    }
    if flags & 0x0800 != 0 {
        parts.push("CONFLICT");
    }
    if flags & 0x0400 != 0 {
        parts.push("ACTIVE");
    }
    if flags & 0x0200 != 0 {
        parts.push("PERMANENT");
    }
    parts.join(" ")
}

/// Parse a node-status response, returning the decoded name table.
fn parse_node_status_response(buf: &[u8]) -> Result<NodeStatus> {
    if buf.len() < 12 {
        bail!("response too short for NBNS header");
    }
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    if ancount == 0 {
        bail!("no answer records in node-status response");
    }

    // Skip header (12) + answer name.
    let mut pos = skip_name(buf, 12)?;
    // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2)
    pos += 2 + 2 + 4;
    let rdlength = u16::from_be_bytes([
        *buf.get(pos).context("truncated rdlength")?,
        *buf.get(pos + 1).context("truncated rdlength")?,
    ]) as usize;
    pos += 2;
    let rdata_end = (pos + rdlength).min(buf.len());

    let num_names = *buf.get(pos).context("truncated num_names")? as usize;
    pos += 1;

    let mut status = NodeStatus::default();
    for _ in 0..num_names {
        if pos + 18 > rdata_end {
            break;
        }
        let raw_name = &buf[pos..pos + 15];
        let suffix = buf[pos + 15];
        let flags = u16::from_be_bytes([buf[pos + 16], buf[pos + 17]]);
        pos += 18;

        let name = String::from_utf8_lossy(raw_name).trim_end().to_string();
        let is_group = flags & 0x8000 != 0;
        let kind = if is_group { "GROUP" } else { "UNIQUE" };

        // Derive workgroup: a GROUP name is the workgroup/domain.
        if is_group && status.workgroup.is_none() && (suffix == 0x00 || suffix == 0x1e) {
            status.workgroup = Some(name.clone());
        }

        status.names.push(NetbiosName {
            name: format!("{name} ({})", suffix_description(suffix, is_group)),
            suffix,
            kind: kind.to_string(),
            flags: render_flags(flags),
        });
    }

    // After the names come statistics: the first 6 bytes are the adapter MAC.
    if pos + 6 <= rdata_end {
        let mac = &buf[pos..pos + 6];
        if mac.iter().any(|&b| b != 0) {
            status.mac = Some(
                mac.iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(":"),
            );
        }
    }

    Ok(status)
}

/// Perform a NetBIOS node-status query against `host` (port 137/udp).
pub async fn node_status(host: &str, timeout_secs: u64) -> Result<NodeStatus> {
    // Resolve to a socket address on port 137.
    let addr: SocketAddr = tokio::net::lookup_host((host, 137u16))
        .await
        .with_context(|| format!("failed to resolve {host}"))?
        .next()
        .with_context(|| format!("no address for {host}"))?;

    let bind_addr = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let sock = UdpSocket::bind(bind_addr)
        .await
        .context("failed to bind local UDP socket")?;
    sock.connect(addr).await.with_context(|| format!("failed to connect UDP to {addr}"))?;

    let txid: u16 = (std::process::id() & 0xFFFF) as u16;
    let req = build_node_status_request(txid);
    sock.send(&req).await.context("failed to send NBNS request")?;

    let mut buf = vec![0u8; 2048];
    let n = timeout(Duration::from_secs(timeout_secs), sock.recv(&mut buf))
        .await
        .context("NetBIOS query timed out")?
        .context("failed to receive NBNS response")?;
    buf.truncate(n);

    parse_node_status_response(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_wildcard_name() {
        // "*" + 15 nulls(0x00 suffix), but we pad with spaces then suffix.
        // For "*": first byte '*' = 0x2A -> nibbles 2,A -> 'C','K'.
        let enc = encode_netbios_name("*", 0x00);
        assert_eq!(enc.len(), 32);
        assert_eq!(enc[0], b'C'); // 0x2A >> 4 = 2 -> 'A'+2 = 'C'
        assert_eq!(enc[1], b'K'); // 0x2A & 0xF = 0xA -> 'A'+10 = 'K'
        // Remaining padded with spaces 0x20 -> nibbles 2,0 -> 'C','A'
        assert_eq!(enc[2], b'C');
        assert_eq!(enc[3], b'A');
    }

    #[test]
    fn encode_known_vector() {
        // Classic RFC example: "FRED" padded -> starts with EGFCEFEECACACACA...
        let enc = encode_netbios_name("FRED", 0x00);
        let s = String::from_utf8(enc).unwrap();
        assert!(s.starts_with("EGFCEFEE"), "got {s}");
    }

    #[test]
    fn request_has_question() {
        let pkt = build_node_status_request(0x1234);
        assert_eq!(&pkt[0..2], &[0x12, 0x34]);
        // QDCOUNT == 1
        assert_eq!(&pkt[4..6], &[0x00, 0x01]);
        // Name length prefix is 0x20.
        assert_eq!(pkt[12], 0x20);
        // Ends with NBSTAT type + IN class.
        let tail = &pkt[pkt.len() - 4..];
        assert_eq!(tail, &[0x00, 0x21, 0x00, 0x01]);
    }

    #[test]
    fn parse_synthetic_response() {
        // Build a minimal node-status response with two names.
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0x1234u16.to_be_bytes()); // txid
        pkt.extend_from_slice(&0x8400u16.to_be_bytes()); // flags (response)
        pkt.extend_from_slice(&0u16.to_be_bytes()); // qd
        pkt.extend_from_slice(&1u16.to_be_bytes()); // an
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ns
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ar
        // Answer name: 0x20 + 32 bytes + 0x00
        pkt.push(0x20);
        pkt.extend_from_slice(&encode_netbios_name("*", 0x00));
        pkt.push(0x00);
        pkt.extend_from_slice(&QTYPE_NBSTAT.to_be_bytes());
        pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes()); // ttl

        // RDATA
        let mut rdata = Vec::new();
        rdata.push(2u8); // num names
        // name 1: HOST unique, active
        let mut n1 = [b' '; 15];
        n1[..4].copy_from_slice(b"HOST");
        rdata.extend_from_slice(&n1);
        rdata.push(0x20); // suffix
        rdata.extend_from_slice(&0x0400u16.to_be_bytes()); // active, unique
        // name 2: WORKGROUP group, active
        let mut n2 = [b' '; 15];
        n2[..9].copy_from_slice(b"WORKGROUP");
        rdata.extend_from_slice(&n2);
        rdata.push(0x00); // suffix
        rdata.extend_from_slice(&0x8400u16.to_be_bytes()); // group + active
        // MAC
        rdata.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);

        pkt.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // rdlength
        pkt.extend_from_slice(&rdata);

        let status = parse_node_status_response(&pkt).unwrap();
        assert_eq!(status.names.len(), 2);
        assert_eq!(status.workgroup.as_deref(), Some("WORKGROUP"));
        assert_eq!(status.mac.as_deref(), Some("DE:AD:BE:EF:00:01"));
        assert!(status.names[0].name.starts_with("HOST"));
        assert_eq!(status.names[0].kind, "UNIQUE");
        assert_eq!(status.names[1].kind, "GROUP");
    }
}

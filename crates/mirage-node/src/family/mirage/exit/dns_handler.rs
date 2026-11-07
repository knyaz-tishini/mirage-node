/// DNS handler for exit nodes.
///
/// When the client's TUN sends a DNS query (port 53) through the tunnel,
/// the exit intercepts the raw bytes, parses the query, resolves via the
/// node's DoH resolver (respecting `prefer_ipv6`), and returns a
/// synthesised DNS response — never touching an upstream 53/tcp or 53/udp.
///
/// Fall-back: if parsing fails, qtype is unsupported (not A/AAAA), or DoH
/// returns no records, the caller should forward the raw bytes to upstream.
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use mirage_core::error::MirageError;
use tracing::{debug, info, warn};

use crate::core::doh::DoHResolver;

// ── DNS wire constants ────────────────────────────────────────────────────────

const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;
/// Default TTL for synthesised answers (seconds).
const SYNTH_TTL: u32 = 300;

// ── Public interface ──────────────────────────────────────────────────────────

/// Result of a successful DNS query parse.
pub struct DnsQuery {
    pub transaction_id: u16,
    pub qname: String,
    pub qtype: u16,
    /// Raw bytes of the question section (for copying into the response verbatim).
    pub question_bytes: Vec<u8>,
}

/// Parse a raw DNS query from wire bytes.
///
/// Returns `None` when the message cannot be parsed (truncated, wrong opcode,
/// not a standard query, etc.).  Callers fall back to raw forwarding.
pub fn parse_dns_query(buf: &[u8]) -> Option<DnsQuery> {
    if buf.len() < 12 {
        return None;
    }

    let transaction_id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);

    // QR=0 (query), OPCODE=0 (QUERY)
    let qr = (flags >> 15) & 1;
    let opcode = (flags >> 11) & 0xf;
    if qr != 0 || opcode != 0 {
        return None;
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount == 0 {
        return None;
    }

    // Parse QNAME from offset 12.
    let (qname, name_end) = parse_qname(buf, 12)?;

    // Need QTYPE (2 bytes) + QCLASS (2 bytes) after name.
    if name_end + 4 > buf.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[name_end], buf[name_end + 1]]);

    // question section = name labels + QTYPE + QCLASS
    let question_bytes = buf[12..name_end + 4].to_vec();

    Some(DnsQuery { transaction_id, qname, qtype, question_bytes })
}

/// Handle an intercepted DNS query (UDP datagram or TCP-framed message).
///
/// Returns `Ok(Some(response_bytes))` when the query was handled.
/// Returns `Ok(None)` when the caller should fall back to raw forwarding.
pub async fn handle_dns_query(
    raw: &[u8],
    resolver: &Arc<DoHResolver>,
) -> Result<Option<Vec<u8>>, MirageError> {
    let query = match parse_dns_query(raw) {
        Some(q) => q,
        None => {
            warn!("dns_handler: failed to parse query, falling back to forward");
            return Ok(None);
        }
    };

    match query.qtype {
        QTYPE_A => {
            let addrs = resolver.resolve_a(&query.qname).await?;
            if addrs.is_empty() {
                debug!(qname = %query.qname, "dns_handler: no A records, falling back");
                return Ok(None);
            }
            info!(
                qname = %query.qname,
                qtype = "A",
                answers = ?addrs,
                "dns_handler: DNS query handled"
            );
            let resp = build_response_a(query.transaction_id, &query.question_bytes, &addrs);
            Ok(Some(resp))
        }
        QTYPE_AAAA => {
            let addrs = resolver.resolve_aaaa(&query.qname).await?;
            if addrs.is_empty() {
                debug!(qname = %query.qname, "dns_handler: no AAAA records, falling back");
                return Ok(None);
            }
            info!(
                qname = %query.qname,
                qtype = "AAAA",
                answers = ?addrs,
                "dns_handler: DNS query handled"
            );
            let resp = build_response_aaaa(query.transaction_id, &query.question_bytes, &addrs);
            Ok(Some(resp))
        }
        other => {
            debug!(
                qname = %query.qname,
                qtype = other,
                "dns_handler: unsupported qtype, falling back to forward"
            );
            Ok(None)
        }
    }
}

// ── DNS wire builders ─────────────────────────────────────────────────────────

fn build_response_a(txid: u16, question: &[u8], addrs: &[Ipv4Addr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + question.len() + addrs.len() * 16);
    write_response_header(&mut out, txid, 1, addrs.len() as u16);
    out.extend_from_slice(question);
    for addr in addrs {
        write_rr_a(&mut out, question, addr);
    }
    out
}

fn build_response_aaaa(txid: u16, question: &[u8], addrs: &[Ipv6Addr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + question.len() + addrs.len() * 28);
    write_response_header(&mut out, txid, 1, addrs.len() as u16);
    out.extend_from_slice(question);
    for addr in addrs {
        write_rr_aaaa(&mut out, question, addr);
    }
    out
}

/// Write a 12-byte DNS header for a standard response.
///
/// Flags: QR=1, OPCODE=0, AA=0, TC=0, RD=1, RA=1, RCODE=0.
fn write_response_header(out: &mut Vec<u8>, txid: u16, qdcount: u16, ancount: u16) {
    out.extend_from_slice(&txid.to_be_bytes());
    // Flags: QR=1, RD=1, RA=1
    out.extend_from_slice(&0x8180u16.to_be_bytes());
    out.extend_from_slice(&qdcount.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&ancount.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes());    // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes());    // ARCOUNT
}

/// Append an A resource record.  Uses a compression pointer (0xc00c) for the
/// owner name, pointing back to the QNAME in the question section (offset 12).
fn write_rr_a(out: &mut Vec<u8>, _question: &[u8], addr: &Ipv4Addr) {
    out.extend_from_slice(&0xc00cu16.to_be_bytes()); // NAME (pointer to offset 12)
    out.extend_from_slice(&QTYPE_A.to_be_bytes());   // TYPE
    out.extend_from_slice(&1u16.to_be_bytes());      // CLASS IN
    out.extend_from_slice(&SYNTH_TTL.to_be_bytes()); // TTL
    out.extend_from_slice(&4u16.to_be_bytes());      // RDLENGTH
    out.extend_from_slice(&addr.octets());           // RDATA
}

/// Append an AAAA resource record (same layout, 16-byte RDATA).
fn write_rr_aaaa(out: &mut Vec<u8>, _question: &[u8], addr: &Ipv6Addr) {
    out.extend_from_slice(&0xc00cu16.to_be_bytes()); // NAME (pointer to offset 12)
    out.extend_from_slice(&QTYPE_AAAA.to_be_bytes());// TYPE
    out.extend_from_slice(&1u16.to_be_bytes());      // CLASS IN
    out.extend_from_slice(&SYNTH_TTL.to_be_bytes()); // TTL
    out.extend_from_slice(&16u16.to_be_bytes());     // RDLENGTH
    out.extend_from_slice(&addr.octets());           // RDATA
}

// ── QNAME parser ─────────────────────────────────────────────────────────────

/// Parse a DNS QNAME at `offset` in `buf`.
///
/// Returns `(dotted_name, offset_after_null_label)` on success.
/// Does not follow compression pointers (queries should not have them).
fn parse_qname(buf: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut hops = 0usize;

    loop {
        if offset >= buf.len() {
            return None;
        }
        let len = buf[offset] as usize;
        // Compression pointer (top 2 bits set) — not expected in a query.
        if len & 0xc0 == 0xc0 {
            return None;
        }
        if len == 0 {
            offset += 1;
            break;
        }
        offset += 1;
        if offset + len > buf.len() {
            return None;
        }
        let label = std::str::from_utf8(&buf[offset..offset + len]).ok()?;
        labels.push(label.to_owned());
        offset += len;
        hops += 1;
        if hops > 128 {
            return None;
        }
    }

    Some((labels.join("."), offset))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Real captured DNS query for `google.com`, qtype A.
    /// Constructed from wire format manually.
    fn make_query_a(txid: u16, name: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&txid.to_be_bytes());
        buf.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
        buf.extend_from_slice(&1u16.to_be_bytes());      // QDCOUNT=1
        buf.extend_from_slice(&0u16.to_be_bytes());      // ANCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes());      // NSCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes());      // ARCOUNT
        encode_qname(&mut buf, name);
        buf.extend_from_slice(&QTYPE_A.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        buf
    }

    fn make_query_aaaa(txid: u16, name: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&txid.to_be_bytes());
        buf.extend_from_slice(&0x0100u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        encode_qname(&mut buf, name);
        buf.extend_from_slice(&QTYPE_AAAA.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf
    }

    fn make_query_mx(txid: u16, name: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&txid.to_be_bytes());
        buf.extend_from_slice(&0x0100u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        encode_qname(&mut buf, name);
        buf.extend_from_slice(&15u16.to_be_bytes()); // MX
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf
    }

    fn encode_qname(buf: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // null label
    }

    #[test]
    fn parse_dns_query_a() {
        let raw = make_query_a(0x1234, "google.com");
        let q = parse_dns_query(&raw).expect("should parse");
        assert_eq!(q.transaction_id, 0x1234);
        assert_eq!(q.qname, "google.com");
        assert_eq!(q.qtype, QTYPE_A);
    }

    #[test]
    fn parse_dns_query_aaaa() {
        let raw = make_query_aaaa(0xabcd, "google.com");
        let q = parse_dns_query(&raw).expect("should parse");
        assert_eq!(q.transaction_id, 0xabcd);
        assert_eq!(q.qname, "google.com");
        assert_eq!(q.qtype, QTYPE_AAAA);
    }

    #[test]
    fn build_dns_response_a_layout() {
        let raw = make_query_a(0x1234, "google.com");
        let q = parse_dns_query(&raw).unwrap();
        let addrs = vec!["142.250.80.46".parse::<Ipv4Addr>().unwrap()];
        let resp = build_response_a(q.transaction_id, &q.question_bytes, &addrs);

        // Header (12 bytes)
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0x1234);
        // flags QR=1 RD=1 RA=1
        assert_eq!(u16::from_be_bytes([resp[2], resp[3]]), 0x8180);
        // ANCOUNT=1
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);

        // Answer section starts after header + question.
        let ans_start = 12 + q.question_bytes.len();
        // NAME = compression pointer 0xc00c
        assert_eq!(u16::from_be_bytes([resp[ans_start], resp[ans_start + 1]]), 0xc00c);
        // TYPE = A
        assert_eq!(u16::from_be_bytes([resp[ans_start + 2], resp[ans_start + 3]]), QTYPE_A);
        // RDLENGTH = 4 (at offset +10 after 2B NAME + 2B TYPE + 2B CLASS + 4B TTL)
        assert_eq!(u16::from_be_bytes([resp[ans_start + 10], resp[ans_start + 11]]), 4);
        // IP octets
        assert_eq!(&resp[ans_start + 12..ans_start + 16], &[142, 250, 80, 46]);
    }

    #[test]
    fn build_dns_response_aaaa_layout() {
        let raw = make_query_aaaa(0x5678, "api64.ipify.org");
        let q = parse_dns_query(&raw).unwrap();
        let addr: Ipv6Addr = "2607:f2d8:4002:507::79".parse().unwrap();
        let resp = build_response_aaaa(q.transaction_id, &q.question_bytes, &[addr]);

        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0x5678);
        let ans_start = 12 + q.question_bytes.len();
        assert_eq!(u16::from_be_bytes([resp[ans_start + 2], resp[ans_start + 3]]), QTYPE_AAAA);
        // RDLENGTH = 16 (at offset +10 after 2B NAME + 2B TYPE + 2B CLASS + 4B TTL)
        assert_eq!(u16::from_be_bytes([resp[ans_start + 10], resp[ans_start + 11]]), 16);
    }

    #[test]
    fn parse_unsupported_qtype_returns_some_with_mx() {
        let raw = make_query_mx(0x0001, "example.com");
        let q = parse_dns_query(&raw).expect("MX query should parse");
        assert_eq!(q.qtype, 15); // MX
    }

    #[test]
    fn parse_rejects_response_packet() {
        let mut raw = make_query_a(0x0001, "example.com");
        // Flip QR bit to 1 (response)
        raw[2] |= 0x80;
        assert!(parse_dns_query(&raw).is_none());
    }

    #[test]
    fn parse_rejects_too_short() {
        let raw = [0u8; 5];
        assert!(parse_dns_query(&raw).is_none());
    }

    /// Integration-ish: handler returns None (fall-back) for MX qtype.
    #[tokio::test]
    async fn handler_falls_back_for_unsupported_qtype() {
        // We need a real DoHResolver to call handle_dns_query, but we can
        // shortcut: for MX the handler returns Ok(None) before touching the
        // resolver at all.
        let resolver = Arc::new(
            DoHResolver::new("https://1.1.1.1/dns-query", true)
                .expect("resolver build"),
        );
        let raw = make_query_mx(0x0002, "example.com");
        let result = handle_dns_query(&raw, &resolver).await.unwrap();
        assert!(result.is_none(), "MX must fall through to forward");
    }
}

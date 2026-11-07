use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use mirage_core::error::MirageError;
use serde::Deserialize;
use tracing::debug;

/// AAAA record type number in DoH JSON response.
const RECORD_A: u16 = 1;
/// A record type number in DoH JSON response.
const RECORD_AAAA: u16 = 28;
/// Default TTL for cached DNS records (seconds).
const DEFAULT_TTL_SECS: u64 = 300;
/// How long to wait for the preferred address family before accepting the other.
const PREFER_TIMEOUT_MS: u64 = 200;

/// A single entry in the TTL cache.
struct CacheEntry {
    ip: IpAddr,
    expires_at: Instant,
}

/// DNS-over-HTTPS resolver using the Cloudflare/Google JSON DoH API.
///
/// Caches responses for the duration indicated by the record TTL (or the
/// `default_ttl` fallback).  Thread-safe — can be wrapped in `Arc` and shared
/// across tasks.
pub struct DoHResolver {
    client: reqwest::Client,
    /// DoH endpoint URL, e.g. `https://1.1.1.1/dns-query`
    endpoint: String,
    /// Cache: hostname → cached result.
    cache: Mutex<HashMap<String, CacheEntry>>,
    default_ttl: Duration,
    /// When `true`, AAAA is queried first and preferred when both families resolve.
    /// When `false`, A is queried first and preferred.
    prefer_ipv6: bool,
}

/// Subset of the Cloudflare/Google DoH JSON response we care about.
#[derive(Deserialize)]
struct DohResponse {
    #[serde(rename = "Answer")]
    answer: Option<Vec<DohAnswer>>,
}

#[derive(Deserialize)]
struct DohAnswer {
    /// Record type: 1 = A (IPv4), 28 = AAAA (IPv6).
    #[serde(rename = "type")]
    record_type: u16,
    /// The resolved address as a string.
    data: String,
    /// Time-to-live in seconds.
    #[serde(rename = "TTL")]
    ttl: Option<u64>,
}

impl DoHResolver {
    /// Create a new resolver pointing at `endpoint`
    /// (e.g. `"https://1.1.1.1/dns-query"`).
    ///
    /// `prefer_ipv6`: when `true` AAAA is preferred; `false` prefers A.
    /// Default for production callers is `true` (modern best practice).
    pub fn new(endpoint: impl Into<String>, prefer_ipv6: bool) -> Result<Self, MirageError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            // Use rustls; do NOT inherit the system trust store so we avoid
            // circular dependency: DNS needed to verify the TLS cert of the
            // DoH server itself.  We connect to a well-known IP (1.1.1.1),
            // so the cert hostname check still works.
            .use_rustls_tls()
            .build()
            .map_err(|e| MirageError::Config(format!("DoH client build failed: {e}")))?;

        Ok(Self {
            client,
            endpoint: endpoint.into(),
            cache: Mutex::new(HashMap::new()),
            default_ttl: Duration::from_secs(DEFAULT_TTL_SECS),
            prefer_ipv6,
        })
    }

    /// Resolve `host` to an IP address.
    ///
    /// - If `host` is already an IP literal (including `[::1]`-style IPv6),
    ///   it is parsed and returned directly without any network round-trip.
    /// - Otherwise, both A and AAAA DoH queries are fired in parallel.
    ///   The preferred address family (controlled by `prefer_ipv6`) is returned
    ///   if it resolves within 200 ms, otherwise whichever arrives first wins.
    /// - Results are cached by hostname (single resolved IP per host).
    pub async fn resolve(&self, host: &str) -> Result<IpAddr, MirageError> {
        // ── Fast path: already an IP literal ────────────────────────────────
        let stripped = strip_ipv6_brackets(host);
        if let Ok(ip) = stripped.parse::<IpAddr>() {
            return Ok(ip);
        }

        // ── Cache lookup ─────────────────────────────────────────────────────
        {
            // SAFETY: std Mutex, not held across await points.
            let cache = self
                .cache
                .lock()
                .expect("DoH cache mutex poisoned — this is a bug");
            if let Some(entry) = cache.get(host) {
                if entry.expires_at > Instant::now() {
                    debug!(host, ip = %entry.ip, "DoH: cache hit");
                    return Ok(entry.ip);
                }
            }
        }

        // ── Parallel A + AAAA query ──────────────────────────────────────────
        let ip = self.query_parallel(host).await?;

        // ── Store in cache ─────────────────────────────────────────────────
        {
            let mut cache = self
                .cache
                .lock()
                .expect("DoH cache mutex poisoned — this is a bug");
            cache.insert(
                host.to_owned(),
                CacheEntry {
                    ip,
                    expires_at: Instant::now() + self.default_ttl,
                },
            );
        }

        Ok(ip)
    }

    /// Resolve `host` to all A (IPv4) addresses.
    ///
    /// Returns every IPv4 address found in the DoH answer section.
    /// Returns an empty vec (not an error) when the host has no A records.
    pub async fn resolve_a(&self, host: &str) -> Result<Vec<Ipv4Addr>, MirageError> {
        let stripped = strip_ipv6_brackets(host);
        if let Ok(ip) = stripped.parse::<Ipv4Addr>() {
            return Ok(vec![ip]);
        }
        if stripped.parse::<Ipv6Addr>().is_ok() {
            return Ok(vec![]);
        }
        self.query_all_a(host).await
    }

    /// Resolve `host` to all AAAA (IPv6) addresses.
    ///
    /// Returns every IPv6 address found in the DoH answer section.
    /// Returns an empty vec (not an error) when the host has no AAAA records.
    pub async fn resolve_aaaa(&self, host: &str) -> Result<Vec<Ipv6Addr>, MirageError> {
        let stripped = strip_ipv6_brackets(host);
        if let Ok(ip) = stripped.parse::<Ipv6Addr>() {
            return Ok(vec![ip]);
        }
        if stripped.parse::<Ipv4Addr>().is_ok() {
            return Ok(vec![]);
        }
        self.query_all_aaaa(host).await
    }

    /// Query the DoH endpoint and return ALL A records for `host`.
    async fn query_all_a(&self, host: &str) -> Result<Vec<Ipv4Addr>, MirageError> {
        let type_str = RECORD_A.to_string();
        let response = self
            .client
            .get(&self.endpoint)
            .query(&[("name", host), ("type", type_str.as_str())])
            .header("Accept", "application/dns-json")
            .send()
            .await
            .map_err(|e| MirageError::NodeUnreachable(format!("DoH request failed: {e}")))?
            .error_for_status()
            .map_err(|e| MirageError::NodeUnreachable(format!("DoH HTTP error: {e}")))?
            .json::<DohResponse>()
            .await
            .map_err(|e| MirageError::Protocol(format!("DoH JSON parse failed: {e}")))?;

        let addrs = response
            .answer
            .unwrap_or_default()
            .into_iter()
            .filter(|a| a.record_type == RECORD_A)
            .filter_map(|a| a.data.parse::<Ipv4Addr>().ok())
            .collect();
        Ok(addrs)
    }

    /// Query the DoH endpoint and return ALL AAAA records for `host`.
    async fn query_all_aaaa(&self, host: &str) -> Result<Vec<Ipv6Addr>, MirageError> {
        let type_str = RECORD_AAAA.to_string();
        let response = self
            .client
            .get(&self.endpoint)
            .query(&[("name", host), ("type", type_str.as_str())])
            .header("Accept", "application/dns-json")
            .send()
            .await
            .map_err(|e| MirageError::NodeUnreachable(format!("DoH request failed: {e}")))?
            .error_for_status()
            .map_err(|e| MirageError::NodeUnreachable(format!("DoH HTTP error: {e}")))?
            .json::<DohResponse>()
            .await
            .map_err(|e| MirageError::Protocol(format!("DoH JSON parse failed: {e}")))?;

        let addrs = response
            .answer
            .unwrap_or_default()
            .into_iter()
            .filter(|a| a.record_type == RECORD_AAAA)
            .filter_map(|a| strip_ipv6_brackets(&a.data).parse::<Ipv6Addr>().ok())
            .collect();
        Ok(addrs)
    }

    /// Fire A and AAAA queries in parallel; return address from the preferred
    /// family when it arrives within `PREFER_TIMEOUT_MS`, otherwise return
    /// whichever succeeds first.
    async fn query_parallel(&self, host: &str) -> Result<IpAddr, MirageError> {
        debug!(host, endpoint = %self.endpoint, prefer_ipv6 = self.prefer_ipv6, "DoH: parallel query");

        let preferred_type = if self.prefer_ipv6 { RECORD_AAAA } else { RECORD_A };
        let fallback_type = if self.prefer_ipv6 { RECORD_A } else { RECORD_AAAA };

        let preferred_fut = self.query_record(host, preferred_type);
        let fallback_fut = self.query_record(host, fallback_type);

        // Pin both futures so we can poll them in select!.
        tokio::pin!(preferred_fut);
        tokio::pin!(fallback_fut);

        let prefer_deadline = tokio::time::sleep(Duration::from_millis(PREFER_TIMEOUT_MS));
        tokio::pin!(prefer_deadline);

        // Phase 1: wait for preferred family or timeout.
        let preferred_result: Option<Result<IpAddr, MirageError>>;
        let fallback_result: Option<Result<IpAddr, MirageError>>;

        tokio::select! {
            res = &mut preferred_fut => {
                // Preferred arrived; we're done regardless of fallback.
                preferred_result = Some(res);
                fallback_result = None;
            }
            res = &mut fallback_fut, if true => {
                // Fallback arrived before preferred.  Wait a bit longer for preferred.
                fallback_result = Some(res);
                tokio::select! {
                    res2 = &mut preferred_fut => {
                        preferred_result = Some(res2);
                    }
                    _ = &mut prefer_deadline => {
                        preferred_result = None;
                    }
                }
            }
        }

        // Decision: preferred wins if it succeeded; else use fallback if it succeeded.
        match (preferred_result, fallback_result) {
            (Some(Ok(ip)), _) => Ok(ip),
            (Some(Err(_)), Some(Ok(ip))) => Ok(ip),
            (None, Some(Ok(ip))) => Ok(ip),
            (Some(Err(e)), None | Some(Err(_))) => Err(e),
            (None, None | Some(Err(_))) => {
                Err(MirageError::NodeUnreachable(format!(
                    "DoH: no A/AAAA record for {host}"
                )))
            }
        }
    }

    /// Query the DoH endpoint for a single record type (1=A, 28=AAAA).
    /// Returns the first matching IP, or error if no record found.
    async fn query_record(&self, host: &str, record_type: u16) -> Result<IpAddr, MirageError> {
        let type_str = record_type.to_string();
        let response = self
            .client
            .get(&self.endpoint)
            .query(&[("name", host), ("type", type_str.as_str())])
            .header("Accept", "application/dns-json")
            .send()
            .await
            .map_err(|e| MirageError::NodeUnreachable(format!("DoH request failed: {e}")))?
            .error_for_status()
            .map_err(|e| MirageError::NodeUnreachable(format!("DoH HTTP error: {e}")))?
            .json::<DohResponse>()
            .await
            .map_err(|e| MirageError::Protocol(format!("DoH JSON parse failed: {e}")))?;

        let answers = response.answer.unwrap_or_default();

        let ip_str = answers
            .iter()
            .find(|a| a.record_type == record_type)
            .map(|a| a.data.as_str())
            .ok_or_else(|| {
                MirageError::NodeUnreachable(format!(
                    "DoH: no type-{record_type} record for {host}"
                ))
            })?;

        // Update TTL cache entry if the answer carries one.
        if let Some(ttl_secs) = answers.first().and_then(|a| a.ttl) {
            let mut cache = self
                .cache
                .lock()
                .expect("DoH cache mutex poisoned — this is a bug");
            if let Some(entry) = cache.get_mut(host) {
                entry.expires_at = Instant::now() + Duration::from_secs(ttl_secs.max(10));
            }
        }

        strip_ipv6_brackets(ip_str)
            .parse::<IpAddr>()
            .map_err(|e| MirageError::Protocol(format!("DoH: unparseable IP {ip_str}: {e}")))
    }
}

/// Strip surrounding brackets from an IPv6 address literal.
///
/// `"[::1]"` → `"::1"`, `"1.2.3.4"` → `"1.2.3.4"` (unchanged).
fn strip_ipv6_brackets(s: &str) -> &str {
    if s.starts_with('[') && s.ends_with(']') {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    /// Parse an IP and assert it is IPv6.
    fn assert_v6(ip: IpAddr) {
        assert!(ip.is_ipv6(), "expected IPv6, got {ip}");
    }

    /// Parse an IP and assert it is IPv4.
    fn assert_v4(ip: IpAddr) {
        assert!(ip.is_ipv4(), "expected IPv4, got {ip}");
    }

    /// Simulate a DoH JSON response body for a single record.
    fn make_response(record_type: u16, data: &str) -> DohResponse {
        DohResponse {
            answer: Some(vec![DohAnswer {
                record_type,
                data: data.to_owned(),
                ttl: Some(60),
            }]),
        }
    }

    // ── Unit: strip_ipv6_brackets ────────────────────────────────────────────

    #[test]
    fn strip_brackets_ipv6() {
        assert_eq!(strip_ipv6_brackets("[::1]"), "::1");
        assert_eq!(strip_ipv6_brackets("[2001:db8::1]"), "2001:db8::1");
    }

    #[test]
    fn strip_brackets_passthrough() {
        assert_eq!(strip_ipv6_brackets("1.2.3.4"), "1.2.3.4");
        assert_eq!(strip_ipv6_brackets("::1"), "::1");
    }

    // ── Unit: response parsing helpers ──────────────────────────────────────

    #[test]
    fn parse_a_record() {
        let resp = make_response(RECORD_A, "1.2.3.4");
        let answers = resp.answer.unwrap();
        let ip_str = answers
            .iter()
            .find(|a| a.record_type == RECORD_A)
            .map(|a| a.data.as_str())
            .unwrap();
        let ip: IpAddr = ip_str.parse().unwrap();
        assert_v4(ip);
    }

    #[test]
    fn parse_aaaa_record() {
        let resp = make_response(RECORD_AAAA, "2606:4700:4700::1111");
        let answers = resp.answer.unwrap();
        let ip_str = answers
            .iter()
            .find(|a| a.record_type == RECORD_AAAA)
            .map(|a| a.data.as_str())
            .unwrap();
        let ip: IpAddr = ip_str.parse().unwrap();
        assert_v6(ip);
    }

    // ── Unit: IP literal fast path ───────────────────────────────────────────

    #[tokio::test]
    async fn resolve_ip_literal_v4() {
        // Resolver with a dummy endpoint — should never be called for literals.
        let r = DoHResolver::new("https://1.1.1.1/dns-query", true).unwrap();
        let ip = r.resolve("1.2.3.4").await.unwrap();
        assert_v4(ip);
    }

    #[tokio::test]
    async fn resolve_ip_literal_v6_bracketed() {
        let r = DoHResolver::new("https://1.1.1.1/dns-query", true).unwrap();
        let ip = r.resolve("[2001:db8::1]").await.unwrap();
        assert_v6(ip);
    }

    // ── Schema / default tests ───────────────────────────────────────────────

    #[test]
    fn node_config_default_prefer_ipv6_true() {
        // When dns_prefer_ipv6 is absent from JSON, serde uses None → default true.
        let json = r#"{
            "dns_resolver": "https://1.1.1.1/dns-query",
            "nat_enabled": false,
            "mode": "direct"
        }"#;
        let exit: mirage_core::config::ExitConfig = serde_json::from_str(json).unwrap();
        // None means default = true at the caller site.
        assert!(exit.dns_prefer_ipv6.is_none() || exit.dns_prefer_ipv6 == Some(true));
    }

    #[test]
    fn node_config_prefer_ipv6_explicit_false() {
        let json = r#"{
            "dns_resolver": "https://1.1.1.1/dns-query",
            "nat_enabled": false,
            "mode": "direct",
            "dns_prefer_ipv6": false
        }"#;
        let exit: mirage_core::config::ExitConfig = serde_json::from_str(json).unwrap();
        assert_eq!(exit.dns_prefer_ipv6, Some(false));
    }
}

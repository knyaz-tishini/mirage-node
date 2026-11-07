//! Exit-target IP policy — SSRF guard for user-data exit paths.
//!
//! Applied AFTER DNS resolution, BEFORE `TcpStream::connect` / `UdpSocket::connect`.
//! The `TunnelControl` path (hardcoded loopback `127.0.0.1:19445`) is intentionally
//! exempt and must NOT call this function.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};

/// Process-wide exit-target policy. When `false` (the default), private /
/// CGNAT / unique-local ranges are also blocked (SSRF guard). Set to `true`
/// only when the node is explicitly deployed as an intranet exit.
///
/// Set ONCE at boot from `NodeToml.allow_private_exit_targets` via
/// [`set_allow_private_exit_targets`]. Until the setter runs it reads `false`,
/// so a missing wire-up fails CLOSED (keeps blocking private targets).
static ALLOW_PRIVATE_EXIT_TARGETS: AtomicBool = AtomicBool::new(false);

/// Apply the node-config exit-target policy at boot. Idempotent; last writer
/// wins. Default (never called) leaves the SSRF-safe `false`.
pub fn set_allow_private_exit_targets(allow: bool) {
    ALLOW_PRIVATE_EXIT_TARGETS.store(allow, Ordering::Relaxed);
    if allow {
        tracing::warn!(
            "[exit-policy] allow_private_exit_targets=TRUE — private/CGNAT/ULA \
             ranges are now valid exit targets (intranet-exit mode; SSRF guard relaxed)"
        );
    }
}

/// Returns `true` if `ip` must never be used as a user-data exit target.
///
/// Unconditionally blocks: loopback, link-local (169.254/16, fe80::/10),
/// unspecified, and the AWS/GCP/Azure metadata address 169.254.169.254.
///
/// When `allow_private` is `false` (the default) also blocks:
/// RFC-1918 private ranges (10/8, 172.16/12, 192.168/16), CGNAT (100.64/10),
/// and IPv6 unique-local (fc00::/7).
///
/// IPv4-mapped IPv6 addresses are recursively checked as their IPv4 equivalent.
pub fn is_blocked_exit_target(ip: IpAddr, allow_private: bool) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_link_local() {
                return true;
            }
            // Belt-and-suspenders: explicit metadata address check.
            if v4.octets() == [169, 254, 169, 254] {
                return true;
            }
            if !allow_private && v4.is_private() {
                return true;
            }
            // CGNAT 100.64/10
            let o = v4.octets();
            if !allow_private && o[0] == 100 && (o[1] & 0xC0) == 64 {
                return true;
            }
            false
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return true;
            }
            // Link-local fe80::/10
            let seg0 = v6.segments()[0];
            if (seg0 & 0xffc0) == 0xfe80 {
                return true;
            }
            // Unique-local fc00::/7
            if !allow_private && (seg0 & 0xfe00) == 0xfc00 {
                return true;
            }
            // IPv4-mapped — re-check embedded v4 address.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked_exit_target(IpAddr::V4(v4), allow_private);
            }
            false
        }
    }
}

/// Check `ip` using the module-level `ALLOW_PRIVATE_EXIT_TARGETS` constant.
///
/// Returns `true` when the address is blocked (caller should reject the connection).
pub fn is_blocked(ip: IpAddr) -> bool {
    is_blocked_exit_target(ip, ALLOW_PRIVATE_EXIT_TARGETS.load(Ordering::Relaxed))
}

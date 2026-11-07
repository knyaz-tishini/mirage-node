//! Outbound dial helpers — v2 per-leg layering.
//!
//! Все исходящие TCP-соединения от ноды к next-hop'у должны идти
//! через эти функции. Если `outgoing_layer.camouflage` задан —
//! оборачиваем stream в client camouflage (TLS / WS / Xhttp /
//! Reality). Это симметрично тому что server-side strip'ает на
//! ingress: cli→entry→hop ходят с РАЗНЫМ camouflage на каждой
//! ноге, каждая нода умеет снять свою и накатить свою на
//! следующую.
//!
//! `outgoing_layer.byte_cipher` here пока не применяется — byte
//! cipher для нативного Mirage чейна семантически на ingress
//! (нода peel'ит свою magic), не на outbound. Если потребуется
//! prepend-magic на outbound (для compatibility с client'ами
//! ожидающими magic на L2) — добавится здесь же.

use std::net::SocketAddr;

use mirage_core::error::MirageError;
use mirage_core::mirage::wire::LayerSpec;
use mirage_protocol::camouflage::pipeline::{wrap_tcp_client, BidiStream};
use tokio::net::TcpStream;
use tracing::debug;

// `dial_with_outgoing_layer` stood here and went with the relay modes it
// served (2026-09-02): its three callers were `listener.rs`'s byte-pump arm,
// `relay/transparent.rs` and `relay/crypto_verify.rs`, all removed. Nothing
// else in the crate dialled an upstream through an outgoing layer, because
// nothing else forwards on a hop's behalf — an onion hop dials its next hop
// through the chain binding, not through this.


/// Bare connect — для случаев когда caller знает что outgoing
/// layering не применяется (foreign-wire entrypoints, decoy
/// fallback, и т.д.). Просто `TcpStream::connect` с
/// `MirageError::Io` маппингом.
pub async fn dial_bare(addr: SocketAddr) -> Result<TcpStream, MirageError> {
    TcpStream::connect(addr).await.map_err(MirageError::Io)
}

/// Резолв `UpstreamRef` в конкретный `(SocketAddr, pubkey)`.
///
/// `Concrete{addr}` — addr парсится напрямую; pubkey = нули
/// (concrete refs не несут pubkey клиенту).
/// `PeerListener{node_id, listener_id}` — резолвится через
/// `peer_table.lookup(node_id)`; pubkey берётся из peer entry.
/// `listener_id` сегодня игнорируется (peer entry не делит ноду
/// на listener'ы — это per-mesh, не per-listener-port view);
/// зарезервирован для будущего расширения peer_table.
pub fn resolve_upstream(
    upstream: &mirage_core::mirage::wire::UpstreamRef,
    peer_table: &mirage_core::mirage::mesh::PeerTable,
) -> Result<(SocketAddr, [u8; 32]), MirageError> {
    use mirage_core::mirage::wire::UpstreamRef;
    match upstream {
        UpstreamRef::Concrete { addr, .. } => {
            let parsed: SocketAddr = addr.parse().map_err(|e| {
                MirageError::Config(format!("UpstreamRef::Concrete addr {addr}: {e}"))
            })?;
            Ok((parsed, [0u8; 32]))
        }
        UpstreamRef::PeerListener { node_id, .. } => {
            let peer = peer_table.lookup_by_str(node_id).ok_or_else(|| {
                MirageError::NodeUnreachable(format!(
                    "peer {node_id} not in peer_table — monitor push may be stale"
                ))
            })?;
            let parsed: SocketAddr = peer.addr.parse().map_err(|e| {
                MirageError::Config(format!("peer {node_id} addr {}: {e}", peer.addr))
            })?;
            let mut pk = [0u8; 32];
            if hex::decode_to_slice(&peer.pubkey_hex, &mut pk).is_err() {
                tracing::warn!(%node_id, "peer pubkey_hex malformed, using zero");
            }
            Ok((parsed, pk))
        }
    }
}

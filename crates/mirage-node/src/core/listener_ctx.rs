//! `ListenerCtx` — identity tuple прокидываемый через handler
//! сигнатуры до dial-сайта.
//!
//! См. `mirage2node/docs/v2-identity-hierarchy.md`. Ключ
//! `(mesh_id, node_id, listener_id, chain_id?)` нужен на dial-сайте
//! чтобы:
//! - найти ChainBinding в `runtime.chain_bindings.load()` (отсюда
//!   outgoing camouflage / byte_cipher для next-hop dial);
//! - резолвить `UpstreamRef::PeerListener { node_id, listener_id }`
//!   через `runtime.peer_table.load()`;
//! - стампить mesh_id в любые исходящие записи (мониторские stats,
//!   логи).
//!
//! `monitor_id` тут НЕТ — нода знает только своего куратора, а в
//! pure-data-plane handler'е он не нужен.

use std::sync::Arc;

/// Identity / config-resolution context для одного listener'a.
///
/// Owned (не &str) чтобы можно было хранить в Arc и прокидывать
/// между task'ами без lifetime acrobatics. Cheap clone.
#[derive(Debug, Clone)]
pub struct ListenerCtx {
    pub mesh_id: Arc<str>,
    pub node_id: Arc<str>,
    pub listener_id: Arc<str>,
    pub chain_id: Option<Arc<str>>,
}

impl ListenerCtx {
    pub fn new(
        mesh_id: impl Into<Arc<str>>,
        node_id: impl Into<Arc<str>>,
        listener_id: impl Into<Arc<str>>,
        chain_id: Option<impl Into<Arc<str>>>,
    ) -> Self {
        Self {
            mesh_id: mesh_id.into(),
            node_id: node_id.into(),
            listener_id: listener_id.into(),
            chain_id: chain_id.map(Into::into),
        }
    }

    /// Empty context — для legacy spawn paths которые не имеют
    /// listener_id (main.rs JSON-NodeConfig путь). Под v2 factory
    /// paths каждый listener строит свой ctx из spec.
    pub fn placeholder() -> Self {
        Self {
            mesh_id: Arc::from(""),
            node_id: Arc::from(""),
            listener_id: Arc::from(""),
            chain_id: None,
        }
    }
}

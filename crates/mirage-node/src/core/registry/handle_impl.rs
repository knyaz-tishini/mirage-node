//! Generic [`ListenerHandle`] implementation for spawn-and-cancel listener
//! kinds.
//!
//! Most listener kinds in `mirage-node` fit one shape: bind a socket, spawn
//! a tokio task that runs `accept` in a loop, hand back something that can
//! cancel the task and report the bound address. `TaskListenerHandle`
//! captures that shape so concrete factories (TCP NodeListener, UDP
//! listeners, terminators, entrypoints, decoy, udp_relay) don't each
//! re-implement the shutdown / stats plumbing.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;

use super::handle::{ListenerHandle, ListenerStats, ReconfigureOutcome};
use super::spec::{ListenerSpec, SpecFingerprint};
use super::spec::ListenerId;

/// Pluggable reconfigure callback installed by concrete factories.
///
/// Receives the bound listener's last-applied spec (under `current`) and
/// the candidate `new_spec`. Returns `Applied` if it swapped the runtime
/// slots in-place; `RebindRequired` if any socket-affecting axis differs.
///
/// Boxed as `Fn` not `FnOnce` because reconfigure may be called many
/// times over the listener's lifetime.
pub type ReconfigureFn = Arc<
    dyn for<'a> Fn(
            &'a ListenerSpec,
            &'a ListenerSpec,
        ) -> Pin<
            Box<
                dyn Future<
                        Output = Result<
                            ReconfigureOutcome,
                            Box<dyn std::error::Error + Send + Sync>,
                        >,
                    > + Send
                    + 'a,
            >,
        > + Send
        + Sync,
>;

/// Counters updated by the listener task; read by [`stats`].
///
/// All fields are atomic so the task can update without locking against
/// the registry's stats-push call.
#[derive(Debug, Default)]
pub struct AtomicListenerStats {
    pub bytes_in: std::sync::atomic::AtomicU64,
    pub bytes_out: std::sync::atomic::AtomicU64,
    pub active_conns: std::sync::atomic::AtomicU32,
    pub accepted_total: std::sync::atomic::AtomicU64,
    pub rejected_total: std::sync::atomic::AtomicU64,
}

impl AtomicListenerStats {
    pub fn snapshot(&self) -> ListenerStats {
        use std::sync::atomic::Ordering::Relaxed;
        ListenerStats {
            bytes_in: self.bytes_in.load(Relaxed),
            bytes_out: self.bytes_out.load(Relaxed),
            active_conns: self.active_conns.load(Relaxed),
            accepted_total: self.accepted_total.load(Relaxed),
            rejected_total: self.rejected_total.load(Relaxed),
        }
    }
}

/// One spawned listener task + the knobs needed to shut it down.
///
/// `cancel.notify_waiters()` is the shutdown signal; the listener task is
/// expected to select between `cancel.notified()` and its accept loop.
/// `bound_addr` is captured once at bind time — listeners that bind
/// multiple sockets (dual-stack v4+v6) report the primary one here and
/// own the other internally.
pub struct TaskListenerHandle {
    id: ListenerId,
    bound_addr: SocketAddr,
    cancel: Arc<Notify>,
    stats: Arc<AtomicListenerStats>,
    /// Current spec — swappable on a successful `reconfigure(Applied)`.
    current_spec: ArcSwap<ListenerSpec>,
    /// Concrete factory installs this to declare what hot-axes it
    /// supports. None = every diff is RebindRequired.
    reconfigure_fn: Option<ReconfigureFn>,
    /// Joined on shutdown. Wrapped in `Mutex<Option<…>>` so `shutdown`
    /// can take the handle even though `&self` is shared.
    task: Mutex<Option<JoinHandle<()>>>,
}

impl TaskListenerHandle {
    pub fn new(
        id: ListenerId,
        bound_addr: SocketAddr,
        cancel: Arc<Notify>,
        stats: Arc<AtomicListenerStats>,
        task: JoinHandle<()>,
        spec: ListenerSpec,
        reconfigure_fn: Option<ReconfigureFn>,
    ) -> Self {
        Self {
            id,
            bound_addr,
            cancel,
            stats,
            current_spec: ArcSwap::new(Arc::new(spec)),
            reconfigure_fn,
            task: Mutex::new(Some(task)),
        }
    }
}

#[async_trait]
impl ListenerHandle for TaskListenerHandle {
    fn id(&self) -> &ListenerId {
        &self.id
    }

    fn bound_addr(&self) -> SocketAddr {
        self.bound_addr
    }

    fn stats(&self) -> ListenerStats {
        self.stats.snapshot()
    }

    fn spec_fingerprint(&self) -> SpecFingerprint {
        self.current_spec.load().fingerprint
    }

    fn current_spec(&self) -> ListenerSpec {
        ListenerSpec::clone(&self.current_spec.load())
    }

    async fn reconfigure(
        &self,
        new_spec: &ListenerSpec,
    ) -> Result<ReconfigureOutcome, Box<dyn std::error::Error + Send + Sync>> {
        let Some(reconfigure) = self.reconfigure_fn.as_ref() else {
            return Ok(ReconfigureOutcome::RebindRequired);
        };
        let current = self.current_spec.load();
        let outcome = reconfigure(&current, new_spec).await?;
        if outcome == ReconfigureOutcome::Applied {
            self.current_spec.store(Arc::new(new_spec.clone()));
        }
        Ok(outcome)
    }

    async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Signal the listener task to stop. `notify_one` stores a permit so the
        // signal is not lost if fired between loop iterations (i.e. the task is
        // executing post-accept code and has not yet re-entered `select!`).
        // `notify_waiters` would silently drop the signal in that window, leaving
        // the accept task blocked on `listener.accept()` until the next inbound
        // connection unblocks it — which means the TcpListener socket would not
        // release the port until a stray connection arrives.
        self.cancel.notify_one();

        let task_opt = {
            let mut guard = self.task.lock().await;
            guard.take()
        };

        match task_opt {
            Some(handle) => match handle.await {
                Ok(()) => Ok(()),
                Err(join_err) if join_err.is_cancelled() => Ok(()),
                Err(join_err) => Err(format!("listener task join error: {join_err}").into()),
            },
            None => {
                // Already shut down — idempotent success.
                Ok(())
            }
        }
    }
}

/// `ListenerHandle` for kinds whose underlying loop owns its socket and
/// has no cooperative cancellation point.
///
/// Common case: a driver loop in another crate (e.g.
/// `mirage_protocol::driver::run_server_udp`) holds the UDP socket and
/// does its own `recv_from` in a tight loop. Wrapping it in a `select!`
/// against `cancel.notified()` would mean forking the driver, so we just
/// `abort()` the task on shutdown; the OS closes the socket via Drop.
///
/// Use this when:
/// - the listener task does NOT poll a `Notify` for cancellation, and
/// - aborting mid-iteration is safe (no half-written critical state).
///
/// Most relay/exit handlers are spawned per-tunnel from the listener
/// task; aborting the listener just stops accepting *new* tunnels. The
/// per-tunnel tasks continue to completion under the runtime's
/// `active_tunnels` counter.
pub struct AbortListenerHandle {
    id: ListenerId,
    bound_addr: SocketAddr,
    stats: Arc<AtomicListenerStats>,
    current_spec: ArcSwap<ListenerSpec>,
    reconfigure_fn: Option<ReconfigureFn>,
    /// All spawned tasks for this listener (driver + dispatch +
    /// auxiliaries). Drained on `shutdown`; `abort()` is called on each.
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl AbortListenerHandle {
    pub fn new(
        id: ListenerId,
        bound_addr: SocketAddr,
        stats: Arc<AtomicListenerStats>,
        tasks: Vec<JoinHandle<()>>,
        spec: ListenerSpec,
        reconfigure_fn: Option<ReconfigureFn>,
    ) -> Self {
        Self {
            id,
            bound_addr,
            stats,
            current_spec: ArcSwap::new(Arc::new(spec)),
            reconfigure_fn,
            tasks: Mutex::new(tasks),
        }
    }
}

#[async_trait]
impl ListenerHandle for AbortListenerHandle {
    fn id(&self) -> &ListenerId {
        &self.id
    }

    fn bound_addr(&self) -> SocketAddr {
        self.bound_addr
    }

    fn stats(&self) -> ListenerStats {
        self.stats.snapshot()
    }

    fn spec_fingerprint(&self) -> SpecFingerprint {
        self.current_spec.load().fingerprint
    }

    fn current_spec(&self) -> ListenerSpec {
        ListenerSpec::clone(&self.current_spec.load())
    }

    async fn reconfigure(
        &self,
        new_spec: &ListenerSpec,
    ) -> Result<ReconfigureOutcome, Box<dyn std::error::Error + Send + Sync>> {
        let Some(reconfigure) = self.reconfigure_fn.as_ref() else {
            return Ok(ReconfigureOutcome::RebindRequired);
        };
        let current = self.current_spec.load();
        let outcome = reconfigure(&current, new_spec).await?;
        if outcome == ReconfigureOutcome::Applied {
            self.current_spec.store(Arc::new(new_spec.clone()));
        }
        Ok(outcome)
    }

    async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let drained = {
            let mut guard = self.tasks.lock().await;
            std::mem::take(&mut *guard)
        };

        for task in &drained {
            task.abort();
        }

        // Best-effort join so the await graph clears and sockets release
        // their fds before we report success. Aborted tasks return
        // `is_cancelled()` — that is the success path here.
        for task in drained {
            match task.await {
                Ok(()) => {}
                Err(e) if e.is_cancelled() => {}
                Err(e) => {
                    tracing::warn!(id = %self.id, error = %e, "listener task join error after abort");
                }
            }
        }

        Ok(())
    }
}

# Listener: "tunnel closed" error — root cause analysis

## Where the log line is emitted

`listener.rs:113`

```rust
warn!(%peer_addr, "connection error: {e}");
```

This is the catch-all `Err` branch inside the `tokio::spawn` closure in `NodeListener::run`.
Every error returned from `handle_connection` reaches this line — there is no other
place in the listener that logs `connection error:`.

`MirageError::TunnelClosed` has the Display text `"tunnel closed"` (defined in
`mirage-core/src/error.rs:17-18`), so the full log line is:

```
WARN peer_addr=203.0.113.16:XXXXX connection error: tunnel closed
```

## Code paths that produce `MirageError::TunnelClosed`

All paths that can bubble up through `handle_connection` → `dispatch_tunnel` → `handle_exit`:

| File | Line | Condition |
|------|------|-----------|
| `exit/direct.rs:112-113` | `handle_exit` reads first byte, `recv` returns `n == 0` | Client sent EOF immediately after handshake |
| `exit/direct.rs:156-157` | `handle_exit_with_prefix` reads address bytes, stream already closed | Same |
| `exit/direct.rs:200-201` | Second read for address, zero bytes | Same |
| `client-core/pool.rs:351` | `TunnelLease::send` called after `take_tunnel` returned `None` | Client side only — not relevant on server |

The dominant server-side path: **client completes the Mirage ECDH handshake (so
`AcceptResult::Tunnel` is returned), but then closes the TCP connection before
sending the first data byte**. `handle_exit` calls `tunnel.recv(&mut first)`,
gets `n == 0`, and returns `TunnelClosed`.

## Handshake timeout — does one exist?

**No.** `run_server_handshake` in `mirage-protocol/src/core/handshake.rs` does a plain
`stream.read_exact(&mut msg).await?` with no `tokio::time::timeout` wrapper.
If the client connects and sends nothing, the server task blocks forever.
This means:

- Idle keep-alive connections from the client pool that never send a target address
  hold a server task open until the TCP session is torn down externally.
- When the OS or L1 relay tears those sessions down (NAT timeout, relay restart,
  etc.) the server sees EOF → `TunnelClosed`.

## Connection limit / max_connections

**None.** The listener loop in `NodeListener::run` (lines 78–117) has no
`active_tunnels` threshold check:

```rust
counter.fetch_add(1, Ordering::Relaxed);
// spawn unconditionally — no capacity guard
if let Err(e) = handle_connection(...).await { … }
counter.fetch_sub(1, Ordering::Relaxed);
```

`active_tunnels` is an `AtomicUsize` maintained for metrics only. Every accepted
TCP connection spawns a new Tokio task. There is no backpressure, no
`max_connections` config field, and no semaphore.

## TunnelPool size on the client side

`main.rs` in `mirage-client-desktop` **always** creates a `TunnelPool` regardless
of `use_mux`:

```rust
let pool = TunnelPool::new(chain.clone(), Arc::clone(&chain_protocols), pool_cfg).await?;

let mux_pool: Option<Arc<MuxPool>> = if config.use_mux {
    let mux = MuxPool::new(chain, chain_protocols, config.pool.clone()).await?;
    Some(mux)
} else {
    None
};
```

Both pools receive the **same** `config.pool` / `TunnelPoolConfig`.
Default `pool_size` = **3** (`mirage-core/src/config.rs:818`).

So when `use_mux = true`:
- `TunnelPool` holds 3 warm classic tunnels (3 open TCP connections to L1).
- `MuxPool` holds up to `pool_size.max(1).min(8)` mux sessions
  (capped at 8, default 3), each a separate TCP connection to L1.
- Total open TCP connections from one client: **6** (3 + 3), not 200.

The "200 slots" hypothesis is **incorrect** — there is no 200 anywhere in the code.

## L1 as bottleneck (peer_addr = 203.0.113.16)

The L2 exit sees `peer_addr = 203.0.113.16` which is L1. This means:

1. Client → L1 (TCP connection, auth, relay)
2. L1 → L2 (TCP connection, auth, forward)

The `TunnelClosed` at L2 occurs after L2's handshake succeeds. This can happen
because:

a. **L1 relay tears down the tunnel before the client sends data.** If L1's
   upstream pool slot is recycled (idle timeout) or the L1→L2 connection is
   dropped by OS/network, L2 sees EOF on what looks like a freshly authenticated
   tunnel.

b. **L1 upstream pool idle-timeout.** L1 has its own `upstream_pool_size` (default 2)
   of pre-warmed L1→L2 tunnels. When the client-side slot idles out and L1's
   upstream tunnel is reused, timing races can produce EOF at L2.

c. **Client pool reconnects flood L1→L2.** Each pool-level reconnect creates a new
   L1→L2 tunnel. If the client disconnects without using the tunnel (e.g. SOCKS5
   request cancelled), L2 receives a fully authenticated connection that immediately
   sends EOF → `TunnelClosed`.

## Summary

| Question | Answer |
|----------|--------|
| Where is the log? | `listener.rs:113` `warn!` in the spawned task |
| What variant? | `MirageError::TunnelClosed` from `exit/direct.rs:113` |
| When? | After successful handshake, client/L1 sends EOF before first data byte |
| Handshake timeout? | **No** — `read_exact` has no timeout |
| Max connections? | **None** — no semaphore, no cap |
| Client pool size with use_mux? | 3 classic + up to 3 mux = **6 TCP connections**, not 200 |
| Is L1 the bottleneck? | **Possibly yes** — L1 upstream pool idle-timeout or relay restart drops L1→L2 tunnels, causing L2 to see authenticated connections that immediately EOF |

## Recommended fixes

1. **Add handshake timeout.** Wrap `run_server_handshake` and the first
   `tunnel.recv` in `tokio::time::timeout(Duration::from_secs(30), ...)`.
   Currently a client that connects and stalls holds a task forever.

2. **Downgrade `TunnelClosed` from `warn` to `debug`.** It is a normal event when
   keep-alive tunnels are recycled. Seeing it in logs is noise, not a bug.

3. **Investigate L1 upstream pool idle_timeout_secs.** If L1's `upstream_pool_max_idle_secs`
   (default 90 s) < L2 session lifetime, L1 will silently drop the L1→L2 leg,
   and L2 gets EOF. Raise L1's idle timeout or add a keepalive ping.

4. **Drop the classic `TunnelPool` when `use_mux=true`.** Currently both pools are
   created and both hold open connections. The classic pool's idle tunnels never
   carry traffic when mux is in use but still consume L2 handshake slots and produce
   `TunnelClosed` noise on recycling.

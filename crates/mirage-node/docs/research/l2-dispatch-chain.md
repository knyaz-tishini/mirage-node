# L2 Dispatch Chain: TCP Accept → handle_exit

## Full chain

```
TcpListener::accept()
  └─ tokio::spawn → handle_connection()
       ├─ [onion peel fast path]   stream.peek(1) — does NOT consume
       ├─ [onion exit fast path]   stream.peek(1) — does NOT consume
       ├─ [transparent relay]      forward immediately — no peek
       ├─ [L1 unwrap / byte-cipher]
       │    YES: stream.read(PEEK_BYTES+32) — CONSUMES bytes → unwrap_peeked()
       │    NO:  stream.peek(PEEK_BYTES)    — does NOT consume
       └─ protocol chain loop
            protocol.accept(stream, &peeked) → AcceptResult::Tunnel(tunnel)
              └─ dispatch_tunnel()
                   NodeMode::Exit  → handle_exit(tunnel, doh)
                   NodeMode::Relay → handle_relay / handle_relay_pooled
                   NodeMode::Hybrid (no upstreams) → handle_exit(tunnel, doh)
```

## What handle_exit sees

`handle_exit` receives a `Box<dyn Tunnel>`.  By the time it is called:

1. The TCP bytes have already been processed by `protocol.accept()`.
2. The `Tunnel` trait abstracts over decrypted / deframed application data.
   - `Tunnel::recv()` returns **application-layer plaintext**, not raw TCP bytes.
   - The protocol layer (e.g. Mirage Phase-1 crypto) has already handled
     handshake, key exchange, and decryption before `AcceptResult::Tunnel` is
     returned.

So `tunnel.recv()` in `handle_exit` delivers the **first application bytes
sent by the client after the crypto handshake** — no cipher overhead, no
framing headers from the wire protocol.

## Auto-detect logic in handle_exit

```
handle_exit:
  tunnel.recv(&mut first[..1])   ← consumes 1 byte from tunnel
  if first[0] == 0x01  →  run_mux_session(tunnel, prefix=&[0x01], …)
  else                 →  handle_exit_with_prefix(tunnel, prefix=&[first[0]], …)
```

Key invariant: the consumed byte is **always passed as `prefix`** to the
downstream helper, so no application byte is ever silently dropped.

### Mux path (`first[0] == 0x01`)

`run_mux_session` wraps the tunnel in `MuxCompat`:
- Creates a `tokio::io::duplex(65536)` channel.
- Background task prepends `prefix` bytes (`[0x01]`) before relaying further
  tunnel reads — so `MuxSession` sees a complete, unmodified mux stream.
- `MuxSession::accept_stream()` loop spawns a task per logical stream.
- Each mux stream sends a UTF-8 `host:port` address frame first, then raw data.

### Classic path (`first[0] != 0x01`)

`handle_exit_with_prefix`:
- Reads the rest of the address frame into a 512-byte buffer, with `prefix`
  prepended at `buf[0]`.
- Parses UTF-8 `host:port`, connects TCP, then `copy_tunnel_to_tcp` loops.

## Buffering / peeking — risk map

| Stage | Method | Consumes? | Notes |
|-------|--------|-----------|-------|
| Onion fast paths | `stream.peek(1)` | NO | Byte stays in kernel buffer |
| L1 byte-cipher OFF | `stream.peek(PEEK_BYTES)` | NO | Byte stays in kernel buffer |
| L1 byte-cipher ON | `stream.read(PEEK_BYTES+32)` | YES | Bytes stripped; unwrapped bytes carried forward as `peeked` Vec |
| `protocol.accept()` | internal to protocol | depends on impl | Protocol owns the stream; hands back `Tunnel` after full handshake |
| `handle_exit` first recv | `tunnel.recv(&mut [1])` | YES | Consumes 1 application byte; always forwarded as `prefix` |

**No byte is silently dropped.** Every consumed byte is either:
- Re-injected as `prefix` (handle_exit, MuxCompat),
- Carried forward in the `peeked` Vec (L1 unwrap path), or
- Still in the kernel buffer (peek paths).

## What the first `tunnel.recv()` byte actually is

The client must send, as its very first application frame after the crypto
handshake:

- `0x01` → mux session opener (mirage-mux framing)
- anything `>= 0x30` (printable ASCII) → classic direct-exit address, e.g.
  `"example.com:443\n"`

The comment in `direct.rs` states valid classic targets begin with a printable
ASCII character (`>= 0x30`), making `0x01` an unambiguous mux indicator.

## File references

- `src/main.rs` — startup, NodeListener construction, decoy listener wiring
- `src/core/listener.rs` — `handle_connection`, `dispatch_tunnel`, peek/L1 logic
- `src/exit/direct.rs` — `handle_exit`, `run_mux_session`, `MuxCompat`,
  `handle_exit_with_prefix`
- `src/exit/mod.rs` — re-exports `direct` and `onion`
- `src/core/tunnel_io.rs` — `copy_tunnel_to_tcp`, `tunnel_copy_bidirectional`
- `mirage2web/crates/mirage-protocol/src/traits.rs` — `Tunnel` trait definition
  (recv = decrypted application bytes, not raw wire bytes)

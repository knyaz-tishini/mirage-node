// The plaintext /admin + /metrics HTTP server (auth.rs, handlers.rs, server.rs)
// was REMOVED 2026-06-26: it was dead code (never spawned — runtime reconfig
// flows over the monitor control WS via PushListenerSet, and the sentry's
// /metrics poll was never enabled), and an in-VPS plaintext-link audit flagged
// the (dead) bind as a ZT surface. builder.rs (build_protocols) + types.rs stay
// — they are the live config→runtime path used by configurator_main.
pub mod builder;
pub mod types;

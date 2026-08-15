//! `thornode-pulse-wire` — the canonical Pulse wire-v2 contract and codec,
//! and nothing else.
//!
//! Split out of `pulse-core` so the client SDKs can depend on the protocol
//! without depending on the server's decode engine. `pulse-core` re-exports
//! both modules, so every `pulse_core::frame::…` / `pulse_core::derive::…`
//! path in the server keeps working unchanged.
//!
//! This crate has **no dependencies** and must keep it that way: it is
//! published to customers, and its Go and Python counterparts
//! (`clients/go/frame.go`, `clients/python/thornode_pulse/frame.py`) mirror
//! `frame` byte-for-byte. A dependency here is a dependency in every SDK.

pub mod derive;
pub mod frame;
pub mod protocol;

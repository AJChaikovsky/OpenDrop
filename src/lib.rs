//! OpenDrop core: peer-to-peer file sharing over the local network.
//!
//! The library holds all networking logic so the CLI (`main.rs`) today, and the
//! Tauri desktop app later, can reuse it without changes.

pub mod discovery;
pub mod identity;
pub mod network;
pub mod pairing;
pub mod protocol;
pub mod transfer;

/// Default TCP port an OpenDrop device listens on.
pub const DEFAULT_PORT: u16 = 45454;

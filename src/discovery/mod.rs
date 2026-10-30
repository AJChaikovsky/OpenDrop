//! Device discovery over mDNS (`_opendrop._tcp.local.`).
//!
//! Phase 1, Task 2. Not implemented yet: for now peers are reached by a
//! manually entered IP address.

/// mDNS service type every OpenDrop device will advertise.
pub const SERVICE_TYPE: &str = "_opendrop._tcp.local.";

//! Failures a local client can tell apart without parsing the sentence.
//!
//! The daemon wraps the errors a caller may want to act on in a
//! [`CodedError`]; the control API passes its [`ErrorCode`] along, so the MCP
//! server can answer `not_shared` instead of prose.

use crate::network::BoxError;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// No device by that id or name on this network, and none paired.
    UnknownDevice,
    /// Paired, but not on the network right now.
    DeviceOffline,
    /// The other device only answers paired devices.
    NotPaired,
    /// The other device doesn't share a file by that id (or name).
    NotShared,
    /// Several shared files have that name.
    AmbiguousFile,
    /// No transfer with that id.
    UnknownTransfer,
    /// The transfer already ended, so there is nothing to cancel.
    AlreadyFinished,
}

/// An error carrying an [`ErrorCode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodedError {
    pub code: ErrorCode,
    pub message: String,
}

impl fmt::Display for CodedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CodedError {}

/// A boxed error with `code`.
pub fn coded(code: ErrorCode, message: impl Into<String>) -> BoxError {
    Box::new(CodedError {
        code,
        message: message.into(),
    })
}

/// The code of `error`, if it has one.
pub fn code_of(error: &BoxError) -> Option<ErrorCode> {
    error.downcast_ref::<CodedError>().map(|e| e.code)
}

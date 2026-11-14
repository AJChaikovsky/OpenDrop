//! Messages between a device and the relay, as JSON text frames on the
//! WebSocket. Shared by the device side (`relay`) and the relay server
//! (`opendrop-relay`) so the two can't drift.

use serde::{Deserialize, Serialize};

/// Relay to device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    /// First message on every connection: random bytes (base64) that the
    /// device's signatures must cover.
    Challenge {
        nonce: String,
    },
    /// The sign-in link was emailed.
    LoginStarted,
    /// The link was opened: here is the account's session.
    LoginDone {
        account: String,
        session: String,
    },
    Registered {
        device_id: String,
    },
    DeviceList {
        devices: Vec<DeviceStatus>,
    },
    /// The device proved its key and now shows online.
    Welcome {
        account: String,
    },
    /// Send the file now, as binary frames.
    UploadReady,
    /// The file is in the assistant inbox.
    Uploaded {
        inbox_id: String,
        expires_ms: u64,
    },
    /// A new token for the hosted MCP server (shown once).
    Token {
        token: String,
    },
    TokensRevoked {
        count: u64,
    },
    /// The request was refused; the relay closes the connection after this.
    Error {
        code: String,
        message: String,
    },
}

/// Device to relay: one request per connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    /// Email a sign-in link; the relay answers `login_started`, then
    /// `login_done` once the link is opened.
    LoginStart {
        email: String,
    },
    /// Add this device to the session's account. `public_key` is base64;
    /// `signature` (base64) covers [`register_message`].
    Register {
        session: String,
        device_id: String,
        name: String,
        public_key: String,
        signature: String,
    },
    ListDevices {
        session: String,
    },
    /// Prove the device's key (`signature` covers [`hello_message`]) and stay
    /// connected; the device shows online until the connection ends.
    Hello {
        device_id: String,
        signature: String,
    },
    /// Put a file in the account's assistant inbox. `sha256` is hex;
    /// `signature` covers [`upload_message`]. After `upload_ready` the
    /// device sends exactly `size` bytes as binary frames.
    InboxUpload {
        device_id: String,
        name: String,
        size: u64,
        sha256: String,
        signature: String,
    },
    /// Make a token the assistant connector can use (until OAuth, in B3).
    CreateToken {
        session: String,
        label: String,
    },
    /// Revoke all of the account's connector tokens.
    RevokeTokens {
        session: String,
    },
}

/// One of the account's devices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceStatus {
    pub device_id: String,
    pub name: String,
    pub online: bool,
    /// When it was last connected, in milliseconds since the Unix epoch
    /// (0 if never).
    pub last_seen_ms: u64,
}

/// Error codes in [`ServerMsg::Error`].
pub mod codes {
    pub const BAD_REQUEST: &str = "bad_request";
    pub const BAD_SESSION: &str = "bad_session";
    pub const BAD_SIGNATURE: &str = "bad_signature";
    pub const UNKNOWN_DEVICE: &str = "unknown_device";
    pub const DEVICE_TAKEN: &str = "device_taken";
    pub const LOGIN_EXPIRED: &str = "login_expired";
    pub const RATE_LIMITED: &str = "rate_limited";
    pub const TOO_LARGE: &str = "too_large";
    pub const QUOTA: &str = "quota";
    pub const BAD_UPLOAD: &str = "bad_upload";
}

/// What a device signs to register to `account` on the connection whose
/// challenge was `nonce`.
pub fn register_message(account: &str, device_id: &str, nonce: &[u8]) -> Vec<u8> {
    let mut m = b"opendrop-relay-register\0".to_vec();
    m.extend_from_slice(account.as_bytes());
    m.push(0);
    m.extend_from_slice(device_id.as_bytes());
    m.push(0);
    m.extend_from_slice(nonce);
    m
}

/// What a device signs to connect as `device_id` on the connection whose
/// challenge was `nonce`.
pub fn hello_message(device_id: &str, nonce: &[u8]) -> Vec<u8> {
    let mut m = b"opendrop-relay-hello\0".to_vec();
    m.extend_from_slice(device_id.as_bytes());
    m.push(0);
    m.extend_from_slice(nonce);
    m
}

/// What a device signs to put a file in its account's inbox, on the
/// connection whose challenge was `nonce`.
pub fn upload_message(
    device_id: &str,
    name: &str,
    size: u64,
    sha256: &str,
    nonce: &[u8],
) -> Vec<u8> {
    let mut m = b"opendrop-relay-upload\0".to_vec();
    for part in [device_id, name, &size.to_string(), sha256] {
        m.extend_from_slice(part.as_bytes());
        m.push(0);
    }
    m.extend_from_slice(nonce);
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_use_snake_case_type_tags() {
        let json = serde_json::to_string(&ClientMsg::Hello {
            device_id: "device-1".into(),
            signature: "c2ln".into(),
        })
        .unwrap();
        assert_eq!(
            json,
            r#"{"type":"hello","device_id":"device-1","signature":"c2ln"}"#
        );
        let msg: ServerMsg = serde_json::from_str(r#"{"type":"login_started"}"#).unwrap();
        assert_eq!(msg, ServerMsg::LoginStarted);
    }

    #[test]
    fn hello_and_register_signatures_cover_different_bytes() {
        // A hello signature can never be passed off as a registration.
        assert_ne!(hello_message("d", b"n"), register_message("", "d", b"n"));
    }
}

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
    /// On a device's hello connection: someone asks for the file at `path`
    /// on this device. Answer with `job_answer`; after a yes, send the file
    /// on a new connection with `job_upload`.
    FetchAsk {
        job_id: String,
        requester: Requester,
        path: String,
        reason: String,
        /// Where the file will go: "the assistant" or another device's name.
        deliver_to: String,
    },
    /// On a device's hello connection: someone wants to see what is in
    /// `folder` (home when absent), or to find files named like `query`.
    /// Answer with `list_answer`, or `job_answer` to refuse.
    ListAsk {
        job_id: String,
        requester: Requester,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        folder: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        query: Option<String>,
    },
    /// On a device's hello connection: a file for this device is waiting at
    /// the relay. Answer with `job_answer`; after a yes, collect it on a new
    /// connection with `job_download`. `request_id` is set when this device
    /// asked for the file itself.
    Deliver {
        job_id: String,
        requester: Requester,
        from_device: String,
        name: String,
        size: u64,
        sha256: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
    },
    /// On a device's hello connection: the answer to its `remote_list`.
    ListResult {
        request_id: String,
        device_name: String,
        folder: String,
        entries: Vec<RemoteEntry>,
        truncated: bool,
    },
    /// On a device's hello connection: its `remote_fetch` or `remote_list`
    /// didn't work out (declined, offline, not found...).
    RequestFailed {
        request_id: String,
        code: String,
        message: String,
    },
    /// A job's file reached the relay.
    JobUploaded,
    /// On a `job_download` connection: the file follows as binary frames.
    DownloadReady {
        name: String,
        size: u64,
        sha256: String,
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
    /// On the hello connection: yes or no to a `fetch_ask`, `list_ask` or
    /// `deliver`. A no carries a code and a message for whoever asked.
    JobAnswer {
        job_id: String,
        accepted: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    /// On the hello connection: what a `list_ask` asked to see.
    ListAnswer {
        job_id: String,
        folder: String,
        entries: Vec<RemoteEntry>,
        truncated: bool,
    },
    /// On the hello connection: ask another device of the account (id or
    /// name) for the file at `path`. It arrives as a `deliver` carrying
    /// `request_id`, or a `request_failed` explains why not.
    RemoteFetch {
        request_id: String,
        device: String,
        path: String,
        #[serde(default)]
        reason: String,
    },
    /// On the hello connection: list a folder of another device, or find
    /// files there. Answered with `list_result` or `request_failed`.
    RemoteList {
        request_id: String,
        device: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        folder: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        query: Option<String>,
    },
    /// Send the file a `fetch_ask` approved. `signature` covers
    /// [`job_upload_message`]; after `upload_ready`, exactly `size` bytes
    /// follow as binary frames, and the relay answers `job_uploaded`.
    JobUpload {
        device_id: String,
        job_id: String,
        name: String,
        size: u64,
        sha256: String,
        signature: String,
    },
    /// Collect the file a `deliver` announced. `signature` covers
    /// [`job_download_message`]; the relay answers `download_ready`, then
    /// the bytes as binary frames.
    JobDownload {
        device_id: String,
        job_id: String,
        signature: String,
    },
}

/// Who is asking a device for something over the relay.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Requester {
    pub kind: RequesterKind,
    /// Stable for one requester: `device:<device id>`, `oauth:<client id>`
    /// or `token:<id>`. Standing access is given to this.
    pub id: String,
    /// What to call it, e.g. "Claude" or "AJ's MacBook Air".
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequesterKind {
    /// An AI assistant connected to the hosted MCP server.
    Assistant,
    /// Another device signed in to the same account.
    Device,
}

/// One entry of a remote folder listing or search.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteEntry {
    pub name: String,
    /// The full path on that device, to pass back in a fetch.
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    /// Last modified, Unix seconds (0 if unknown).
    pub modified: u64,
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
    pub const DECLINED: &str = "declined";
    pub const TIMEOUT: &str = "timeout";
    pub const OFFLINE: &str = "offline";
    pub const NOT_FOUND: &str = "not_found";
    pub const REFUSED: &str = "refused";
    pub const UNKNOWN_JOB: &str = "unknown_job";
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

/// What a device signs to send the file of job `job_id`.
pub fn job_upload_message(
    device_id: &str,
    job_id: &str,
    name: &str,
    size: u64,
    sha256: &str,
    nonce: &[u8],
) -> Vec<u8> {
    let mut m = b"opendrop-relay-job-upload\0".to_vec();
    for part in [device_id, job_id, name, &size.to_string(), sha256] {
        m.extend_from_slice(part.as_bytes());
        m.push(0);
    }
    m.extend_from_slice(nonce);
    m
}

/// What a device signs to collect the file of job `job_id`.
pub fn job_download_message(device_id: &str, job_id: &str, nonce: &[u8]) -> Vec<u8> {
    let mut m = b"opendrop-relay-job-download\0".to_vec();
    for part in [device_id, job_id] {
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

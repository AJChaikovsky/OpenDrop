//! The device side of the OpenDrop relay (Phase 9, option B; design doc
//! `docs/design/ai-file-requests.md`, "Option B").
//!
//! The relay is opt-in: a device only talks to it after `opendrop relay
//! login`, which saves `relay.json` in the config folder. From then on the
//! daemon keeps one outbound WebSocket to the relay (home and phone networks
//! sit behind NAT), proves who it is with its Ed25519 key, and so shows as
//! online to the account's other devices and, in later stages, to the
//! hosted assistant connector.
//!
//! Every exchange runs over the same WebSocket endpoint (`/v1/ws`): the relay
//! opens with a random challenge, and the device sends one request (start a
//! login, register itself, list devices, or say hello and stay connected).
//! Signatures always cover that challenge, so a captured message can't be
//! replayed on another connection.

pub mod proto;

use crate::identity::{DeviceIdentity, write_private};
use crate::network::BoxError;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use futures_util::{SinkExt, StreamExt};
use proto::{ClientMsg, DeviceStatus, ServerMsg};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

/// File in the config folder that holds the relay sign-in.
pub const CONFIG_FILE: &str = "relay.json";

/// How long the device waits for the relay to answer a request.
const REPLY_TIMEOUT: Duration = Duration::from_secs(15);

/// How long `login` waits for the user to open the sign-in link.
pub const LOGIN_TIMEOUT: Duration = Duration::from_secs(16 * 60);

/// Reconnect delays: 1 s, doubling up to this.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// A saved relay sign-in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// The relay's base URL, e.g. `https://relay.example.com`.
    pub url: String,
    /// The account's email address.
    pub account: String,
    /// Proves the account to the relay (for listing devices); keep secret.
    pub session: String,
}

impl Config {
    pub fn path(config_dir: &Path) -> PathBuf {
        config_dir.join(CONFIG_FILE)
    }

    /// The saved sign-in, or `None` when this device hasn't signed in
    /// (the relay is off).
    pub fn load(config_dir: &Path) -> Result<Option<Self>, BoxError> {
        let path = Self::path(config_dir);
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes).map_err(|e| {
                format!(
                    "{} is damaged ({e}); run `opendrop relay logout`",
                    path.display()
                )
            })?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("cannot read {}: {e}", path.display()).into()),
        }
    }

    /// Save it, readable only by this user (it holds the session).
    pub fn save(&self, config_dir: &Path) -> Result<(), BoxError> {
        std::fs::create_dir_all(config_dir)?;
        let path = Self::path(config_dir);
        let _ = std::fs::remove_file(&path);
        write_private(&path, &serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    /// Forget the sign-in: the device stops using the relay.
    pub fn remove(config_dir: &Path) -> Result<bool, BoxError> {
        match std::fs::remove_file(Self::path(config_dir)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
}

/// The WebSocket address for a relay base URL.
pub fn ws_url(base: &str) -> Result<String, BoxError> {
    let base = base.trim_end_matches('/');
    let rest = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if base.starts_with("ws://") || base.starts_with("wss://") {
        base.to_owned()
    } else {
        return Err(
            format!("the relay address must start with https:// or http:// (got {base})").into(),
        );
    };
    Ok(format!("{rest}/v1/ws"))
}

/// One connection to the relay, past its challenge.
struct Connection {
    socket: Socket,
    nonce: Vec<u8>,
}

impl Connection {
    async fn open(base: &str) -> Result<Self, BoxError> {
        let url = ws_url(base)?;
        let (socket, _) =
            tokio::time::timeout(REPLY_TIMEOUT, tokio_tungstenite::connect_async(&url))
                .await
                .map_err(|_| format!("the relay at {base} didn't answer"))?
                .map_err(|e| format!("cannot reach the relay at {base}: {e}"))?;
        let mut connection = Self {
            socket,
            nonce: Vec::new(),
        };
        match connection.receive(REPLY_TIMEOUT).await? {
            ServerMsg::Challenge { nonce } => {
                connection.nonce = B64
                    .decode(nonce)
                    .map_err(|_| "the relay sent a malformed challenge")?;
                Ok(connection)
            }
            other => Err(unexpected(&other)),
        }
    }

    async fn send(&mut self, msg: &ClientMsg) -> Result<(), BoxError> {
        self.socket
            .send(Message::text(serde_json::to_string(msg)?))
            .await?;
        Ok(())
    }

    /// The next message from the relay; an `error` message becomes an error.
    async fn receive(&mut self, timeout: Duration) -> Result<ServerMsg, BoxError> {
        loop {
            let frame = tokio::time::timeout(timeout, self.socket.next())
                .await
                .map_err(|_| "the relay stopped answering")?;
            match frame {
                None | Some(Ok(Message::Close(_))) => {
                    return Err("the relay closed the connection".into());
                }
                Some(Err(e)) => return Err(format!("relay connection failed: {e}").into()),
                Some(Ok(Message::Text(text))) => {
                    let msg: ServerMsg = serde_json::from_str(&text)
                        .map_err(|e| format!("unexpected message from the relay: {e}"))?;
                    if let ServerMsg::Error { message, .. } = msg {
                        return Err(format!("the relay refused: {message}").into());
                    }
                    return Ok(msg);
                }
                // Pings are answered by the WebSocket library while reading.
                Some(Ok(_)) => continue,
            }
        }
    }
}

fn unexpected(msg: &ServerMsg) -> BoxError {
    format!("unexpected reply from the relay: {msg:?}").into()
}

/// Sign in to the relay at `url` as `email` and register this device to the
/// account. The relay emails a sign-in link; `on_link_sent` runs once it has
/// (to tell the user to open it), and this returns once they have.
pub async fn login(
    url: &str,
    email: &str,
    identity: &DeviceIdentity,
    on_link_sent: impl FnOnce(),
) -> Result<Config, BoxError> {
    let mut connection = Connection::open(url).await?;
    connection
        .send(&ClientMsg::LoginStart {
            email: email.trim().to_owned(),
        })
        .await?;
    match connection.receive(REPLY_TIMEOUT).await? {
        ServerMsg::LoginStarted => on_link_sent(),
        other => return Err(unexpected(&other)),
    }
    let (account, session) = match connection.receive(LOGIN_TIMEOUT).await {
        Ok(ServerMsg::LoginDone { account, session }) => (account, session),
        Ok(other) => return Err(unexpected(&other)),
        Err(e) if e.to_string().contains("stopped answering") => {
            return Err("the sign-in link wasn't opened in time; run the command again".into());
        }
        Err(e) => return Err(e),
    };
    let config = Config {
        url: url.trim_end_matches('/').to_owned(),
        account,
        session,
    };
    register(&mut connection, &config, identity).await?;
    Ok(config)
}

async fn register(
    connection: &mut Connection,
    config: &Config,
    identity: &DeviceIdentity,
) -> Result<(), BoxError> {
    let signature = identity.sign(&proto::register_message(
        &config.account,
        &identity.id,
        &connection.nonce,
    ));
    connection
        .send(&ClientMsg::Register {
            session: config.session.clone(),
            device_id: identity.id.clone(),
            name: identity.name.clone(),
            public_key: B64.encode(identity.public_key()),
            signature: B64.encode(signature),
        })
        .await?;
    match connection.receive(REPLY_TIMEOUT).await? {
        ServerMsg::Registered { .. } => Ok(()),
        other => Err(unexpected(&other)),
    }
}

/// The account's devices as the relay sees them.
pub async fn devices(config: &Config) -> Result<Vec<DeviceStatus>, BoxError> {
    let mut connection = Connection::open(&config.url).await?;
    connection
        .send(&ClientMsg::ListDevices {
            session: config.session.clone(),
        })
        .await?;
    match connection.receive(REPLY_TIMEOUT).await? {
        ServerMsg::DeviceList { devices } => Ok(devices),
        other => Err(unexpected(&other)),
    }
}

/// Bytes per binary frame when uploading (the relay takes frames up to
/// 64 KiB).
const UPLOAD_CHUNK: usize = 32 * 1024;

/// A file that reached the assistant inbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uploaded {
    pub inbox_id: String,
    pub sha256: String,
    pub size: u64,
    pub expires_ms: u64,
}

/// Put the file at `path` in the account's assistant inbox, as this device.
pub async fn upload(
    config: &Config,
    identity: &DeviceIdentity,
    path: &Path,
) -> Result<Uploaded, BoxError> {
    use sha2::{Digest, Sha256};
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| format!("{} isn't a file", path.display()))?;
    let data = tokio::fs::read(path)
        .await
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let size = data.len() as u64;
    let sha256: String = Sha256::digest(&data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut connection = Connection::open(&config.url).await?;
    let signature = identity.sign(&proto::upload_message(
        &identity.id,
        &name,
        size,
        &sha256,
        &connection.nonce,
    ));
    connection
        .send(&ClientMsg::InboxUpload {
            device_id: identity.id.clone(),
            name,
            size,
            sha256: sha256.clone(),
            signature: B64.encode(signature),
        })
        .await?;
    match connection.receive(REPLY_TIMEOUT).await? {
        ServerMsg::UploadReady => {}
        other => return Err(unexpected(&other)),
    }
    for chunk in data.chunks(UPLOAD_CHUNK) {
        connection
            .socket
            .send(Message::binary(chunk.to_vec()))
            .await?;
    }
    match connection.receive(REPLY_TIMEOUT).await? {
        ServerMsg::Uploaded {
            inbox_id,
            expires_ms,
        } => Ok(Uploaded {
            inbox_id,
            sha256,
            size,
            expires_ms,
        }),
        other => Err(unexpected(&other)),
    }
}

/// A new token for the hosted MCP server; the relay shows it only once.
pub async fn create_token(config: &Config, label: &str) -> Result<String, BoxError> {
    let mut connection = Connection::open(&config.url).await?;
    connection
        .send(&ClientMsg::CreateToken {
            session: config.session.clone(),
            label: label.to_owned(),
        })
        .await?;
    match connection.receive(REPLY_TIMEOUT).await? {
        ServerMsg::Token { token } => Ok(token),
        other => Err(unexpected(&other)),
    }
}

/// Revoke every MCP token of the account; returns how many there were.
pub async fn revoke_tokens(config: &Config) -> Result<u64, BoxError> {
    let mut connection = Connection::open(&config.url).await?;
    connection
        .send(&ClientMsg::RevokeTokens {
            session: config.session.clone(),
        })
        .await?;
    match connection.receive(REPLY_TIMEOUT).await? {
        ServerMsg::TokensRevoked { count } => Ok(count),
        other => Err(unexpected(&other)),
    }
}

/// Where the device's relay connection stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Connecting,
    /// Connected and recognized: the device shows online.
    Online,
    /// Not connected; retrying after a delay.
    Offline {
        error: String,
    },
}

/// Connect and stay connected, reconnecting with backoff, until the task is
/// dropped. Status changes go to `status`.
pub async fn run(config: Config, identity: DeviceIdentity, status: watch::Sender<Status>) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let _ = status.send(Status::Connecting);
        let error = match stay_connected(&config, &identity, &status).await {
            // It was up, so the next try starts quickly again.
            Ok(()) => {
                backoff = Duration::from_secs(1);
                "the relay closed the connection".to_owned()
            }
            Err(e) => e.to_string(),
        };
        let _ = status.send(Status::Offline { error });
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// One connection: say hello, then read (which answers the relay's pings)
/// until it ends. `Ok` means it was accepted and later closed.
async fn stay_connected(
    config: &Config,
    identity: &DeviceIdentity,
    status: &watch::Sender<Status>,
) -> Result<(), BoxError> {
    let mut connection = Connection::open(&config.url).await?;
    let signature = identity.sign(&proto::hello_message(&identity.id, &connection.nonce));
    connection
        .send(&ClientMsg::Hello {
            device_id: identity.id.clone(),
            signature: B64.encode(signature),
        })
        .await?;
    match connection.receive(REPLY_TIMEOUT).await? {
        ServerMsg::Welcome { .. } => {}
        other => return Err(unexpected(&other)),
    }
    let _ = status.send(Status::Online);
    // No reply timeout here: the relay pings, and drops us if we don't
    // answer. Reading with no deadline answers those pings.
    loop {
        match connection.socket.next().await {
            None | Some(Ok(Message::Close(_))) => return Ok(()),
            Some(Err(_)) => return Ok(()),
            Some(Ok(_)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_addresses_become_websocket_urls() {
        assert_eq!(
            ws_url("https://relay.example.com/").unwrap(),
            "wss://relay.example.com/v1/ws"
        );
        assert_eq!(
            ws_url("http://127.0.0.1:8787").unwrap(),
            "ws://127.0.0.1:8787/v1/ws"
        );
        assert!(ws_url("relay.example.com").is_err());
    }

    #[test]
    fn config_round_trips_and_logout_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Config::load(dir.path()).unwrap(), None);
        let config = Config {
            url: "http://127.0.0.1:8787".into(),
            account: "a@example.com".into(),
            session: "s".into(),
        };
        config.save(dir.path()).unwrap();
        config.save(dir.path()).unwrap();
        assert_eq!(Config::load(dir.path()).unwrap(), Some(config));
        assert!(Config::remove(dir.path()).unwrap());
        assert!(!Config::remove(dir.path()).unwrap());
    }
}

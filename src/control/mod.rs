//! Local control API: how the CLI (and later the MCP server) talk to a
//! running daemon on the same machine.
//!
//! It uses the wire protocol's framing (4-byte length + JSON) with its own
//! message set, one request and one response at a time:
//!
//! ```text
//! client                         daemon
//!   | --- {"type":"list_devices"} --> |
//!   | <-- {"type":"devices",...} ---- |
//! ```
//!
//! Only the OS user running the daemon can connect. On macOS and Linux it
//! listens on a Unix socket (`0600`, in a `0700` folder in the config dir)
//! and checks each client's uid; on Windows it is a named pipe whose ACL
//! grants access to that user (and SYSTEM) only, refusing remote clients.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
use windows as platform;

pub use platform::Endpoint;

use crate::daemon::{Daemon, DeviceInfo, Transfer};
use crate::network::BoxError;
use crate::protocol::{ProtocolError, read_frame, write_frame};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;

/// How long a client waits for the daemon's answer.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    ListDevices,
    ListTransfers,
    GetTransfer { transfer_id: String },
    CancelTransfer { transfer_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Devices {
        devices: Vec<DeviceInfo>,
    },
    Transfers {
        transfers: Vec<Transfer>,
    },
    Transfer {
        transfer: Transfer,
    },
    /// The cancel reached whoever runs the transfer; poll for `cancelled`.
    CancelRequested {
        transfer_id: String,
    },
    Error {
        message: String,
    },
}

/// Answer one request from the daemon's state.
pub async fn handle(daemon: &Daemon, request: Request) -> Response {
    match request {
        Request::ListDevices => Response::Devices {
            devices: daemon.devices(),
        },
        Request::ListTransfers => Response::Transfers {
            transfers: daemon.transfers.list(),
        },
        Request::GetTransfer { transfer_id } => match daemon.transfers.get(&transfer_id) {
            Some(transfer) => Response::Transfer { transfer },
            None => error(format!("no transfer {transfer_id}")),
        },
        Request::CancelTransfer { transfer_id } => match daemon.transfers.cancel(&transfer_id) {
            Ok(()) => Response::CancelRequested { transfer_id },
            Err(e) => error(e.to_string()),
        },
    }
}

fn error(message: String) -> Response {
    Response::Error { message }
}

/// Serve one client connection until it hangs up (or the daemon stops).
async fn serve_client<S>(daemon: Weak<Daemon>, mut stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let Ok(payload) = read_frame(&mut stream).await else {
            return;
        };
        let Some(daemon) = daemon.upgrade() else {
            return;
        };
        let response = match serde_json::from_slice::<Request>(&payload) {
            Ok(request) => handle(&daemon, request).await,
            Err(e) => error(format!("bad request: {e}")),
        };
        drop(daemon);
        let Ok(payload) = serde_json::to_vec(&response) else {
            return;
        };
        if write_frame(&mut stream, &payload).await.is_err() {
            return;
        }
    }
}

/// Listen on `endpoint` and answer clients until the task is dropped.
pub async fn serve(daemon: Arc<Daemon>, endpoint: Endpoint) -> std::io::Result<()> {
    let (ready, _) = oneshot::channel();
    serve_ready(Arc::downgrade(&daemon), endpoint, ready).await
}

/// [`serve`], reporting on `ready` once the endpoint is bound (or why it
/// couldn't be). Holds the daemon weakly, so dropping it stops answering.
pub async fn serve_ready(
    daemon: Weak<Daemon>,
    endpoint: Endpoint,
    ready: oneshot::Sender<Result<(), String>>,
) -> std::io::Result<()> {
    platform::serve(endpoint, ready, move |stream| {
        tokio::spawn(serve_client(daemon.clone(), stream));
    })
    .await
}

/// A connection to a running daemon.
pub struct Client {
    stream: platform::ClientStream,
}

impl Client {
    /// Connect to the daemon using `config_dir` (the same `--config` it was
    /// started with).
    pub async fn connect(config_dir: &Path) -> Result<Self, BoxError> {
        Self::connect_to(&Endpoint::for_config_dir(config_dir)).await
    }

    pub async fn connect_to(endpoint: &Endpoint) -> Result<Self, BoxError> {
        let stream = platform::connect(endpoint).await.map_err(|e| {
            format!(
                "no OpenDrop daemon is answering at {endpoint} ({e}); start `opendrop listen` first"
            )
        })?;
        Ok(Self { stream })
    }

    pub async fn call(&mut self, request: &Request) -> Result<Response, BoxError> {
        let payload = serde_json::to_vec(request)?;
        let exchange = async {
            write_frame(&mut self.stream, &payload).await?;
            read_frame(&mut self.stream).await
        };
        let reply = tokio::time::timeout(CALL_TIMEOUT, exchange)
            .await
            .map_err(|_| "the daemon did not answer in time")?
            .map_err(|e| match e {
                ProtocolError::ConnectionClosed => "the daemon hung up".into(),
                other => BoxError::from(other.to_string()),
            })?;
        Ok(serde_json::from_slice(&reply)?)
    }
}

#[cfg(test)]
mod tests;

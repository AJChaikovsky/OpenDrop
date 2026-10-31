//! The long-running side of a device: one listener, discovery, and a table of
//! every transfer in and out.
//!
//! `opendrop listen` and the desktop app both run a [`Daemon`]. It wraps the
//! server's approval channel and receive events so each offered file shows up
//! in the [`TransferTable`] before anyone answers, and it records outgoing
//! sends it runs. Local clients (the CLI, later the MCP server) read the table
//! through the control API.

pub mod transfers;

pub use transfers::{Direction, Status, Transfer, TransferTable};

use crate::discovery::{Discovery, Peer};
use crate::network::client::{Connection, FileResult};
use crate::network::server::{self, Approval, FileRequest, ReceiveEvent, ReceiveEvents};
use crate::network::{BoxError, DeviceIdentity};
use crate::pairing::store::PairedDevices;
use crate::pairing::{PairPrompts, PairResults};
use crate::protocol::PROTOCOL_VERSION;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// How long to try each address of a device before moving on to the next.
/// Virtual adapters and stale addresses otherwise stall for the full OS
/// connect timeout.
pub const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Everything a daemon needs. Start from [`Options::new`].
#[derive(Debug, Clone)]
pub struct Options {
    pub identity: DeviceIdentity,
    /// Where accepted files are saved; created when the first file arrives.
    pub download_dir: PathBuf,
    /// TCP port to listen on (0 lets the OS pick).
    pub port: u16,
    /// Who decides on offered files. Every offer is recorded first.
    pub approval: Approval,
    /// Also report receive events here (the app's progress display).
    pub events: Option<ReceiveEvents>,
    pub paired: Arc<PairedDevices>,
    pub pair_prompts: Option<PairPrompts>,
    pub pair_results: Option<PairResults>,
    /// Advertise and browse over mDNS.
    pub discover: bool,
}

impl Options {
    pub fn new(identity: DeviceIdentity, download_dir: PathBuf, approval: Approval) -> Self {
        Self {
            identity,
            download_dir,
            port: crate::DEFAULT_PORT,
            approval,
            events: None,
            paired: Arc::new(PairedDevices::in_memory()),
            pair_prompts: None,
            pair_results: None,
            discover: true,
        }
    }
}

/// A nearby device as local clients see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub name: String,
    /// Where we'd connect, e.g. `192.168.1.20:45454`; `None` for a paired
    /// device that isn't on the network right now.
    pub address: Option<String>,
    pub online: bool,
    pub paired: bool,
    pub compatible: bool,
}

pub struct Daemon {
    pub identity: DeviceIdentity,
    /// The port actually listened on.
    pub port: u16,
    pub download_dir: PathBuf,
    pub paired: Arc<PairedDevices>,
    pub transfers: Arc<TransferTable>,
    discovery: Option<Discovery>,
    discovery_error: Option<String>,
    server: Mutex<Option<JoinHandle<std::io::Result<()>>>>,
}

impl Daemon {
    /// Bind the listener, start serving and (with `discover`) advertising.
    /// Must be called from within a Tokio runtime.
    pub async fn start(options: Options) -> Result<Arc<Self>, BoxError> {
        let Options {
            identity,
            download_dir,
            port,
            approval,
            events,
            paired,
            pair_prompts,
            pair_results,
            discover,
        } = options;
        let listener = TcpListener::bind(("0.0.0.0", port))
            .await
            .map_err(|e| format!("could not listen on port {port}: {e}"))?;
        let port = listener.local_addr()?.port();
        let transfers = Arc::new(TransferTable::new());

        let (requests, request_rx) = mpsc::channel(16);
        tokio::spawn(record_requests(
            request_rx,
            approval,
            Arc::clone(&transfers),
        ));
        let (receive_events, event_rx) = mpsc::unbounded_channel();
        tokio::spawn(record_receive_events(
            event_rx,
            events,
            Arc::clone(&transfers),
        ));
        let server = tokio::spawn(server::serve(
            listener,
            server::Options {
                events: Some(receive_events),
                paired: Arc::clone(&paired),
                pair_prompts,
                pair_results,
                ..server::Options::new(
                    identity.clone(),
                    download_dir.clone(),
                    Approval::Ask(requests),
                )
            },
        ));
        // Without mDNS the device still works by IP, so a failure here is
        // reported, not fatal.
        let (discovery, discovery_error) = if discover {
            match Discovery::start(&identity, Some(port)) {
                Ok(d) => (Some(d), None),
                Err(e) => (None, Some(e.to_string())),
            }
        } else {
            (None, None)
        };
        Ok(Arc::new(Self {
            identity,
            port,
            download_dir,
            paired,
            transfers,
            discovery,
            discovery_error,
            server: Mutex::new(Some(server)),
        }))
    }

    pub fn discovery(&self) -> Option<&Discovery> {
        self.discovery.as_ref()
    }

    /// Why mDNS isn't running, if it was asked for and failed to start.
    pub fn discovery_error(&self) -> Option<&str> {
        self.discovery_error.as_deref()
    }

    /// Nearby devices, then paired devices that aren't around right now.
    pub fn devices(&self) -> Vec<DeviceInfo> {
        let nearby = self
            .discovery
            .as_ref()
            .map_or_else(Vec::new, Discovery::peers);
        let mut devices: Vec<DeviceInfo> = nearby
            .iter()
            .map(|peer| DeviceInfo {
                device_id: peer.id.clone(),
                name: peer.name.clone(),
                address: peer.socket_addr().map(|a| a.to_string()),
                online: true,
                paired: self.paired.get(&peer.id).is_some(),
                compatible: peer.protocol_version == PROTOCOL_VERSION,
            })
            .collect();
        for device in self.paired.list() {
            if nearby.iter().all(|p| p.id != device.id) {
                devices.push(DeviceInfo {
                    device_id: device.id,
                    name: device.name,
                    address: None,
                    online: false,
                    paired: true,
                    compatible: true,
                });
            }
        }
        devices
    }

    /// The discovered device named `query` (id or name, ignoring case).
    pub fn find_peer(&self, query: &str) -> Option<Peer> {
        self.discovery
            .as_ref()?
            .peers()
            .into_iter()
            .find(|p| p.matches(query))
    }

    /// Send `path` to the first of `addrs` that answers, recording it in the
    /// transfer table. Returns the transfer id at once; the send runs in the
    /// background and can be cancelled through the table.
    pub async fn send_file(&self, addrs: &[SocketAddr], path: &Path) -> Result<String, BoxError> {
        let meta =
            std::fs::metadata(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if !meta.is_file() {
            return Err(format!("{} is not a file", path.display()).into());
        }
        let connection = connect(addrs, &self.identity, &self.paired).await?;
        let (id, cancelled) = self.transfers.begin(Transfer::new(
            Direction::Send,
            Some(connection.peer.id.clone()),
            connection.peer.name.clone(),
            file_name(path),
            meta.len(),
        ));
        tokio::spawn(run_send(
            Arc::clone(&self.transfers),
            id.clone(),
            connection,
            path.to_owned(),
            cancelled,
        ));
        Ok(id)
    }

    /// Wait until the listener stops (it only does on an accept error).
    pub async fn wait(&self) -> std::io::Result<()> {
        let server = self.server.lock().unwrap().take();
        match server {
            Some(handle) => handle
                .await
                .unwrap_or_else(|e| Err(std::io::Error::other(e))),
            None => std::future::pending().await,
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(server) = self.server.lock().unwrap().take() {
            server.abort();
        }
    }
}

/// Send one file over `connection`, keeping its row up to date. Cancelling
/// drops the connection, which the receiver sees as an interrupted transfer.
async fn run_send(
    transfers: Arc<TransferTable>,
    id: String,
    mut connection: Connection,
    path: PathBuf,
    cancelled: oneshot::Receiver<()>,
) {
    let progress = Arc::clone(&transfers);
    let progress_id = id.clone();
    let mut on_progress = |sent| {
        progress.update(&progress_id, |t| {
            t.status = Status::Transferring;
            t.bytes = sent;
        })
    };
    let send = connection.send_file(&path, &mut on_progress);
    tokio::select! {
        result = send => match result {
            Ok(FileResult::Delivered(outcome)) => transfers.update(&id, |t| {
                t.bytes = outcome.size;
                t.sha256 = Some(outcome.sha256);
                t.status = Status::Done;
            }),
            Ok(FileResult::Declined) => transfers.finish(&id, Status::Declined, None),
            Err(e) => transfers.finish(&id, Status::Failed, Some(e.to_string())),
        },
        _ = cancelled => transfers.finish(&id, Status::Cancelled, None),
    }
}

/// Record each offered file, then let `approval` decide (or the table's
/// cancel, which declines it).
async fn record_requests(
    mut requests: mpsc::Receiver<FileRequest>,
    approval: Approval,
    transfers: Arc<TransferTable>,
) {
    while let Some(request) = requests.recv().await {
        let (row, cancelled) = transfers.begin_with_id(
            request.transfer_id.clone(),
            Transfer::new(
                Direction::Receive,
                None,
                request.peer_name.clone(),
                request.name.clone(),
                request.size,
            ),
        );
        let transfers = Arc::clone(&transfers);
        let approval = approval.clone();
        tokio::spawn(async move {
            let FileRequest {
                transfer_id,
                peer_name,
                peer_addr,
                name,
                size,
                mut respond,
            } = request;
            let accept = match approval {
                Approval::AcceptAll => true,
                Approval::Ask(ask) => {
                    let (answer_tx, answer) = oneshot::channel();
                    let forwarded = FileRequest {
                        transfer_id: transfer_id.clone(),
                        peer_name,
                        peer_addr,
                        name,
                        size,
                        respond: answer_tx,
                    };
                    if ask.send(forwarded).await.is_err() {
                        false
                    } else {
                        tokio::select! {
                            answer = answer => answer.unwrap_or(false),
                            _ = cancelled => {
                                transfers.finish(&row, Status::Cancelled, None);
                                false
                            }
                            // The server stopped waiting (timeout, or the
                            // sender hung up).
                            _ = respond.closed() => false,
                        }
                    }
                }
            };
            if !accept {
                transfers.update(&row, |t| {
                    if !t.status.is_final() {
                        t.status = Status::Declined;
                    }
                });
            }
            let _ = respond.send(accept);
        });
    }
}

/// Keep incoming rows up to date, then pass each event on.
async fn record_receive_events(
    mut events: mpsc::UnboundedReceiver<ReceiveEvent>,
    forward: Option<ReceiveEvents>,
    transfers: Arc<TransferTable>,
) {
    while let Some(event) = events.recv().await {
        match &event {
            ReceiveEvent::Started {
                transfer_id,
                peer_name,
                name,
                size,
            } => {
                if transfers.get(transfer_id).is_none() {
                    transfers.begin_with_id(
                        transfer_id.clone(),
                        Transfer::new(
                            Direction::Receive,
                            None,
                            peer_name.clone(),
                            name.clone(),
                            *size,
                        ),
                    );
                }
                transfers.update(transfer_id, |t| t.status = Status::Transferring);
            }
            ReceiveEvent::Progress {
                transfer_id,
                received,
            } => transfers.update(transfer_id, |t| t.bytes = *received),
            ReceiveEvent::Saved {
                transfer_id,
                path,
                sha256,
            } => transfers.update(transfer_id, |t| {
                t.bytes = t.size;
                t.path = Some(path.clone());
                t.sha256 = Some(sha256.clone());
                t.status = Status::Done;
            }),
            ReceiveEvent::Failed { transfer_id, error } => {
                transfers.finish(transfer_id, Status::Failed, Some(error.clone()))
            }
        }
        if let Some(forward) = &forward {
            let _ = forward.send(event);
        }
    }
}

/// Open a connection to the first of `addrs` that answers.
pub async fn connect(
    addrs: &[SocketAddr],
    identity: &DeviceIdentity,
    paired: &PairedDevices,
) -> Result<Connection, BoxError> {
    let mut last_error = String::from("the device advertised no address");
    for addr in addrs {
        let addr = addr.to_string();
        let open = Connection::open_with(&addr, identity, paired);
        match tokio::time::timeout(CONNECT_TIMEOUT, open).await {
            Ok(Ok(connection)) => return Ok(connection),
            Ok(Err(e)) => last_error = format!("{addr}: {e}"),
            Err(_) => last_error = format!("{addr}: no answer"),
        }
    }
    Err(format!("could not reach the device ({last_error})").into())
}

fn file_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

#[cfg(test)]
mod tests;

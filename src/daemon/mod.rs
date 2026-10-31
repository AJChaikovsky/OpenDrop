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
use crate::error::{ErrorCode, coded};
use crate::identity::random_bytes;
use crate::network::client::{Connection, FileResult};
use crate::network::fetch::PendingFetches;
use crate::network::server::{self, Approval, FileRequest, ReceiveEvent, ReceiveEvents};
use crate::network::{BoxError, DeviceIdentity};
use crate::pairing::store::PairedDevices;
use crate::pairing::{PairPrompts, PairResults};
use crate::protocol::FetchDeclineReason;
use crate::protocol::PROTOCOL_VERSION;
use crate::share::{SharedFile, Shares};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
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
    /// Serve the local control API for this config dir (see `control`).
    pub control: Option<PathBuf>,
    /// What paired devices may list and fetch. Without it nothing is shared.
    pub shares: Option<Arc<Shares>>,
    /// Let unpaired devices list and fetch too (local demos only).
    pub allow_unpaired_fetch: bool,
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
            control: None,
            shares: None,
            allow_unpaired_fetch: false,
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

impl DeviceInfo {
    /// A discovered device. Peers speaking another protocol version are
    /// listed, but as incompatible.
    pub fn nearby(peer: &Peer, paired: &PairedDevices) -> Self {
        Self {
            device_id: peer.id.clone(),
            name: peer.name.clone(),
            address: peer.socket_addr().map(|a| a.to_string()),
            online: true,
            paired: paired.get(&peer.id).is_some(),
            compatible: peer.protocol_version == PROTOCOL_VERSION,
        }
    }
}

pub struct Daemon {
    pub identity: DeviceIdentity,
    /// The port actually listened on.
    pub port: u16,
    pub download_dir: PathBuf,
    pub paired: Arc<PairedDevices>,
    pub transfers: Arc<TransferTable>,
    fetches: Arc<PendingFetches>,
    discovery: Option<Discovery>,
    discovery_error: Option<String>,
    control_error: Mutex<Option<String>>,
    control: Mutex<Option<JoinHandle<std::io::Result<()>>>>,
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
            control,
            shares,
            allow_unpaired_fetch,
        } = options;
        let listener = TcpListener::bind(("0.0.0.0", port))
            .await
            .map_err(|e| format!("could not listen on port {port}: {e}"))?;
        let port = listener.local_addr()?.port();
        let transfers = Arc::new(TransferTable::new());
        let fetches = Arc::new(PendingFetches::new());

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
            Arc::clone(&fetches),
        ));
        let server = tokio::spawn(server::serve(
            listener,
            server::Options {
                events: Some(receive_events),
                paired: Arc::clone(&paired),
                pair_prompts,
                pair_results,
                shares,
                allow_unpaired_fetch,
                fetches: Arc::clone(&fetches),
                outgoing: Some(Arc::clone(&transfers)),
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
        let daemon = Arc::new(Self {
            identity,
            port,
            download_dir,
            paired,
            transfers,
            fetches,
            discovery,
            discovery_error,
            control_error: Mutex::new(None),
            control: Mutex::new(None),
            server: Mutex::new(Some(server)),
        });
        if let Some(config_dir) = control {
            let endpoint = crate::control::Endpoint::for_config_dir(&config_dir);
            // Bind before returning, so a client started right after us
            // finds the endpoint. Like mDNS, a failure here is reported but
            // doesn't stop the device from receiving files.
            let (bound_tx, bound) = oneshot::channel();
            let task = tokio::spawn(crate::control::serve_ready(
                Arc::downgrade(&daemon),
                endpoint,
                bound_tx,
            ));
            *daemon.control.lock().unwrap() = Some(task);
            if let Ok(Err(e)) = bound.await {
                *daemon.control_error.lock().unwrap() = Some(e);
            }
        }
        Ok(daemon)
    }

    pub fn discovery(&self) -> Option<&Discovery> {
        self.discovery.as_ref()
    }

    /// Why the control API isn't running, if it was asked for and failed.
    pub fn control_error(&self) -> Option<String> {
        self.control_error.lock().unwrap().clone()
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
            .map(|peer| DeviceInfo::nearby(peer, &self.paired))
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

    /// Where `device` can be reached: an IP (default port), IP:PORT, or a
    /// discovered device's id or name.
    pub fn addresses_of(&self, device: &str) -> Result<Vec<SocketAddr>, BoxError> {
        if let Ok(ip) = device.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, crate::DEFAULT_PORT)]);
        }
        if let Ok(addr) = device.parse::<SocketAddr>() {
            return Ok(vec![addr]);
        }
        if let Some(peer) = self.find_peer(device) {
            let addrs = peer.socket_addrs();
            if addrs.is_empty() {
                return Err(format!("\"{}\" advertised no usable address", peer.name).into());
            }
            return Ok(addrs);
        }
        let paired = self
            .paired
            .list()
            .into_iter()
            .any(|d| d.id == device || d.name.eq_ignore_ascii_case(device));
        Err(if paired {
            coded(
                ErrorCode::DeviceOffline,
                format!("\"{device}\" is paired but not on the network right now"),
            )
        } else {
            coded(
                ErrorCode::UnknownDevice,
                format!("no device named \"{device}\" on this network"),
            )
        })
    }

    /// The files `device` shares with us, and whether the list was cut
    /// short. Returns the device's name too.
    pub async fn list_shares(
        &self,
        device: &str,
        query: Option<&str>,
    ) -> Result<(String, Vec<SharedFile>, bool), BoxError> {
        let addrs = self.addresses_of(device)?;
        let mut connection = connect(&addrs, &self.identity, &self.paired).await?;
        let (files, truncated) = connection.list_shares(query).await?;
        Ok((connection.peer.name.clone(), files, truncated))
    }

    /// Ask `device` for shared file `file` (its id, path in the share, or
    /// unique name). Returns the transfer id at once: the row waits for the
    /// owner's approval, then follows the file in. The owner's user sees
    /// `reason` (and whether an assistant asked).
    pub async fn fetch(
        &self,
        device: &str,
        file: &str,
        reason: &str,
        via_assistant: bool,
    ) -> Result<String, BoxError> {
        let addrs = self.addresses_of(device)?;
        let mut connection = connect(&addrs, &self.identity, &self.paired).await?;
        let (files, truncated) = connection.list_shares(None).await?;
        let wanted = pick_shared_file(&files, file, truncated, &connection.peer.name)?;
        let fetch_id = format!("fetch-{}", &crate::transfer::hex(&random_bytes())[..16]);
        let (row, cancelled) = self.transfers.begin_with_id(
            fetch_id.clone(),
            Transfer::new(
                Direction::Receive,
                Some(connection.peer.id.clone()),
                connection.peer.name.clone(),
                wanted.name.clone(),
                wanted.size,
            ),
        );
        let arrived = self
            .fetches
            .expect(&fetch_id, &connection.peer.id, wanted.size);
        tokio::spawn(run_fetch(
            Arc::clone(&self.transfers),
            Arc::clone(&self.fetches),
            connection,
            FetchPlan {
                fetch_id,
                file_id: wanted.file_id,
                reason: reason.to_owned(),
                via_assistant,
                reply_port: self.port,
            },
            arrived,
            cancelled,
        ));
        Ok(row)
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
        if let Some(control) = self.control.lock().unwrap().take() {
            control.abort();
        }
    }
}

/// The shared file `query` names: its id, its path in the share, or its
/// name if only one file has it.
fn pick_shared_file(
    files: &[SharedFile],
    query: &str,
    truncated: bool,
    owner: &str,
) -> Result<SharedFile, BoxError> {
    if let Some(file) = files.iter().find(|f| f.file_id == query || f.path == query) {
        return Ok(file.clone());
    }
    let named: Vec<&SharedFile> = files
        .iter()
        .filter(|f| f.name.eq_ignore_ascii_case(query))
        .collect();
    match named.as_slice() {
        [file] => Ok((*file).clone()),
        [] if truncated => Err(coded(
            ErrorCode::NotShared,
            format!(
                "\"{owner}\" shares too many files to list them all and \"{query}\" wasn't among those listed; use its id or path"
            ),
        )),
        [] => Err(coded(
            ErrorCode::NotShared,
            format!("\"{owner}\" doesn't share a file named \"{query}\""),
        )),
        several => Err(coded(
            ErrorCode::AmbiguousFile,
            format!(
                "\"{owner}\" shares several files named \"{query}\"; use a path: {}",
                several
                    .iter()
                    .map(|f| f.path.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )),
    }
}

/// What a fetch asks the owner for.
struct FetchPlan {
    fetch_id: String,
    file_id: String,
    reason: String,
    via_assistant: bool,
    reply_port: u16,
}

/// How long after the owner's yes its offer may take to arrive.
const OFFER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Ask for the file and wait for the owner's answer; once it accepts, the
/// file arrives at our listener, whose events finish the row.
async fn run_fetch(
    transfers: Arc<TransferTable>,
    fetches: Arc<PendingFetches>,
    mut connection: Connection,
    plan: FetchPlan,
    arrived: oneshot::Receiver<String>,
    cancelled: oneshot::Receiver<()>,
) {
    let id = plan.fetch_id.clone();
    let ask = connection.request_fetch(
        &plan.fetch_id,
        &plan.file_id,
        &plan.reason,
        plan.via_assistant,
        plan.reply_port,
    );
    let answer = tokio::select! {
        answer = ask => answer,
        _ = cancelled => {
            fetches.forget(&id);
            transfers.finish(&id, Status::Cancelled, None);
            return;
        }
    };
    let declined = |reason: &str| {
        fetches.forget(&id);
        transfers.finish(&id, Status::Declined, Some(reason.to_owned()));
    };
    match answer {
        Ok(Ok(())) => {}
        Ok(Err(FetchDeclineReason::Declined)) => return declined("the owner declined"),
        Ok(Err(FetchDeclineReason::Timeout)) => {
            return declined("the owner didn't answer in time");
        }
        Ok(Err(FetchDeclineReason::NotShared)) => return declined("that file is no longer shared"),
        Ok(Err(FetchDeclineReason::NotPaired)) => {
            return declined("only paired devices can fetch; pair first");
        }
        Err(e) => {
            fetches.forget(&id);
            return transfers.finish(&id, Status::Failed, Some(e.to_string()));
        }
    }
    drop(connection);
    if tokio::time::timeout(OFFER_TIMEOUT, arrived).await.is_err() {
        fetches.forget(&id);
        transfers.finish(
            &id,
            Status::Failed,
            Some("approved, but the file never arrived (is a firewall blocking incoming connections?)".into()),
        );
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
        // A fetch request asks us to send one of our files.
        let (direction, peer_id) = match &request.fetch {
            Some(fetch) => (Direction::Send, Some(fetch.peer_id.clone())),
            None => (Direction::Receive, None),
        };
        let (row, cancelled) = transfers.begin_with_id(
            request.transfer_id.clone(),
            Transfer::new(
                direction,
                peer_id,
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
                fetch,
            } = request;
            let accept = match approval {
                // Auto-accept takes files in; sending one away always needs
                // a yes.
                Approval::AcceptAll => fetch.is_none(),
                Approval::Ask(ask) => {
                    let (answer_tx, answer) = oneshot::channel();
                    let forwarded = FileRequest {
                        transfer_id: transfer_id.clone(),
                        peer_name,
                        peer_addr,
                        name,
                        size,
                        respond: answer_tx,
                        fetch,
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
    fetches: Arc<PendingFetches>,
) {
    while let Some(event) = events.recv().await {
        // A file answering one of our fetches updates the fetch's row.
        let row = |transfer_id: &String| {
            fetches
                .fetch_for(transfer_id)
                .unwrap_or(transfer_id.clone())
        };
        match &event {
            ReceiveEvent::Started {
                transfer_id,
                peer_name,
                name,
                size,
            } => {
                let transfer_id = &row(transfer_id);
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
            } => transfers.update(&row(transfer_id), |t| t.bytes = *received),
            ReceiveEvent::Saved {
                transfer_id,
                path,
                sha256,
            } => transfers.update(&row(transfer_id), |t| {
                t.bytes = t.size;
                t.path = Some(path.clone());
                t.sha256 = Some(sha256.clone());
                t.status = Status::Done;
            }),
            ReceiveEvent::Failed { transfer_id, error } => {
                transfers.finish(&row(transfer_id), Status::Failed, Some(error.clone()))
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

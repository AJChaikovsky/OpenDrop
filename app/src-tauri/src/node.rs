//! The app's OpenDrop node: receives files (asking the UI first), finds peers,
//! sends files to them and pairs with them, reporting everything as
//! [`AppEvent`]s.
//!
//! Nothing here depends on Tauri, so it is tested on its own; `lib.rs` only
//! forwards events to the window and commands to the node.

use opendrop::daemon::{self, Daemon, Direction, Status, Transfer};
use opendrop::discovery::{Discovery, Peer, PeerEvent};
use opendrop::network::client::{Connection, FileResult};
use opendrop::network::server::{Approval, FileRequest, ReceiveEvent};
use opendrop::network::{BoxError, DeviceIdentity};
use opendrop::pairing::store::PairedDevices;
use opendrop::pairing::{PairOutcome, PairPrompt, PairPrompts, PairResult};
use opendrop::protocol::PROTOCOL_VERSION;
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
#[cfg(test)]
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, oneshot};

/// Progress events are sent at most this often per transfer (plus the last).
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// How long to try each advertised address before moving on to the next.
/// Virtual adapters and stale addresses otherwise stall a send for the full
/// OS connect timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// A nearby device as the UI shows it.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Device {
    pub id: String,
    pub name: String,
    /// Where we'd connect, e.g. `192.168.1.20:45454`.
    pub address: Option<String>,
    pub compatible: bool,
    /// We have this device's key from an earlier pairing.
    pub paired: bool,
}

impl Device {
    fn new(peer: &Peer, paired: &PairedDevices) -> Self {
        Self {
            id: peer.id.clone(),
            name: peer.name.clone(),
            address: peer.socket_addr().map(|a| a.to_string()),
            compatible: peer.protocol_version == PROTOCOL_VERSION,
            paired: paired.get(&peer.id).is_some(),
        }
    }
}

/// How a pairing attempt ended, as the UI words it.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PairStatus {
    Paired,
    /// Our user said no.
    Declined,
    /// The other device's user said no.
    DeclinedByPeer,
    TimedOut,
    Failed,
}

/// Everything the UI needs to hear about. Serialized as
/// `{"kind": "send_progress", ...}` for the frontend.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AppEvent {
    /// The full device list, sent whenever it changes.
    Devices {
        devices: Vec<Device>,
    },
    /// Someone wants to send us a file; answer with [`Node::respond`].
    IncomingRequest {
        transfer_id: String,
        peer_name: String,
        peer_ip: String,
        name: String,
        size: u64,
    },
    /// An incoming request was not answered in time or its sender gave up.
    IncomingExpired {
        transfer_id: String,
    },
    ReceiveStarted {
        transfer_id: String,
        peer_name: String,
        name: String,
        size: u64,
    },
    ReceiveProgress {
        transfer_id: String,
        bytes: u64,
        size: u64,
        bytes_per_sec: f64,
    },
    ReceiveDone {
        transfer_id: String,
        path: String,
        sha256: String,
    },
    ReceiveFailed {
        transfer_id: String,
        error: String,
    },
    /// A file we're sending, waiting for the receiver to accept it.
    SendWaiting {
        transfer_id: String,
        device_name: String,
        name: String,
        size: u64,
    },
    SendProgress {
        transfer_id: String,
        bytes: u64,
        size: u64,
        bytes_per_sec: f64,
    },
    SendDone {
        transfer_id: String,
        sha256: String,
    },
    SendDeclined {
        transfer_id: String,
    },
    SendFailed {
        transfer_id: String,
        error: String,
    },
    /// Show `code` and ask whether the other screen shows the same; answer
    /// with [`Node::respond_pair`]. `incoming` if the other device asked.
    PairCode {
        pair_id: String,
        device_id: String,
        device_name: String,
        code: String,
        incoming: bool,
    },
    /// The code was withdrawn before we answered: the other side declined
    /// or time ran out. A `PairDone` follows.
    PairExpired {
        pair_id: String,
    },
    /// A pairing attempt finished, whichever side started it.
    PairDone {
        device_id: String,
        device_name: String,
        status: PairStatus,
        error: Option<String>,
    },
}

pub type EventSink = Arc<dyn Fn(AppEvent) + Send + Sync>;

pub struct Node {
    pub identity: DeviceIdentity,
    pub port: u16,
    pub download_dir: PathBuf,
    pub paired: Arc<PairedDevices>,
    /// Listener, discovery and the transfer table, shared with the CLI's
    /// `listen`.
    pub daemon: Arc<Daemon>,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<bool>>>>,
    pending_pairs: Arc<Mutex<HashMap<String, oneshot::Sender<bool>>>>,
    pair_prompts: PairPrompts,
    sink: EventSink,
    next_send_id: AtomicU64,
    /// The runtime the node was started on, for work started from plain
    /// (non-async) methods: Tauri runs sync commands on the main thread,
    /// outside any runtime.
    runtime: tokio::runtime::Handle,
}

impl Node {
    /// Listen on `port` (0 lets the OS pick), save accepted files in
    /// `download_dir`, trust the devices in `paired`, and with `discover`
    /// advertise and browse over mDNS. Must be called from within a Tokio
    /// runtime.
    pub async fn start(
        identity: DeviceIdentity,
        paired: Arc<PairedDevices>,
        port: u16,
        download_dir: PathBuf,
        discover: bool,
        sink: EventSink,
    ) -> Result<Arc<Self>, BoxError> {
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let (requests, request_rx) = mpsc::channel(16);
        let (events, event_rx) = mpsc::unbounded_channel();
        tokio::spawn(forward_requests(
            request_rx,
            Arc::clone(&pending),
            sink.clone(),
        ));
        tokio::spawn(forward_receive_events(event_rx, sink.clone()));
        let pending_pairs = Arc::new(Mutex::new(HashMap::new()));
        let (pair_prompts, prompt_rx) = mpsc::channel(4);
        tokio::spawn(forward_pair_prompts(
            prompt_rx,
            Arc::clone(&pending_pairs),
            sink.clone(),
        ));
        let (pair_results, mut result_rx) = mpsc::unbounded_channel::<PairResult>();
        let results_sink = sink.clone();
        tokio::spawn(async move {
            while let Some(PairResult { peer, outcome }) = result_rx.recv().await {
                results_sink(pair_done(&peer.id, &peer.name, outcome));
            }
        });
        let daemon = Daemon::start(daemon::Options {
            port,
            events: Some(events),
            paired: Arc::clone(&paired),
            pair_prompts: Some(pair_prompts.clone()),
            pair_results: Some(pair_results),
            discover,
            ..daemon::Options::new(
                identity.clone(),
                download_dir.clone(),
                Approval::Ask(requests),
            )
        })
        .await?;
        if let Some(error) = daemon.discovery_error() {
            return Err(error.into());
        }
        let port = daemon.port;
        let discovery = daemon.discovery();
        // Every change to the nearby or paired devices resends the whole
        // list: it is short, and the UI stays a plain render of the latest.
        let mut nearby = discovery.map(Discovery::subscribe);
        let mut pairings = paired.subscribe();
        let list_paired = Arc::clone(&paired);
        let list_sink = sink.clone();
        tokio::spawn(async move {
            let mut peers: HashMap<String, Peer> = HashMap::new();
            loop {
                tokio::select! {
                    change = async { nearby.as_mut().unwrap().recv().await }, if nearby.is_some() => {
                        match change {
                            Ok(PeerEvent::Found(p) | PeerEvent::Updated(p)) => {
                                peers.insert(p.id.clone(), p);
                            }
                            Ok(PeerEvent::Lost(p)) => {
                                peers.remove(&p.id);
                            }
                            Err(broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(broadcast::error::RecvError::Closed) => nearby = None,
                        }
                    }
                    change = pairings.recv() => {
                        if let Err(broadcast::error::RecvError::Closed) = change {
                            break;
                        }
                    }
                }
                let list: Vec<Peer> = peers.values().cloned().collect();
                list_sink(AppEvent::Devices {
                    devices: devices(&list, &list_paired),
                });
            }
        });

        Ok(Arc::new(Self {
            identity,
            port,
            download_dir,
            paired,
            daemon,
            pending,
            pending_pairs,
            pair_prompts,
            sink,
            next_send_id: AtomicU64::new(1),
            runtime: tokio::runtime::Handle::current(),
        }))
    }

    /// Devices discovered so far.
    pub fn devices(&self) -> Vec<Device> {
        self.daemon
            .discovery()
            .map_or_else(Vec::new, |d| devices(&d.peers(), &self.paired))
    }

    /// Answer an [`AppEvent::IncomingRequest`]. Returns false if it had
    /// already expired or been answered.
    pub fn respond(&self, transfer_id: &str, accept: bool) -> bool {
        let respond = self.pending.lock().unwrap().remove(transfer_id);
        respond.is_some_and(|r| r.send(accept).is_ok())
    }

    /// Send `paths` to the discovered device `device_id`, one after another
    /// over one connection. Progress arrives as `Send*` events; the returned
    /// ids match them, in the order of `paths`.
    pub async fn send_to_device(
        &self,
        device_id: &str,
        paths: &[PathBuf],
    ) -> Result<Vec<String>, BoxError> {
        let addrs = self.addrs_of(device_id)?;
        self.send_to_addrs(&addrs, paths).await
    }

    fn addrs_of(&self, device_id: &str) -> Result<Vec<SocketAddr>, BoxError> {
        let peer = self
            .daemon
            .discovery()
            .and_then(|d| d.peers().into_iter().find(|p| p.id == device_id))
            .ok_or("that device is no longer on the network")?;
        Ok(peer.socket_addrs())
    }

    /// Start pairing with the discovered device `device_id`. Both screens
    /// get a `PairCode`; a `PairDone` reports how it ended.
    pub async fn pair_device(&self, device_id: &str) -> Result<(), BoxError> {
        let addrs = self.addrs_of(device_id)?;
        self.pair_with_addrs(&addrs).await
    }

    /// Like [`Node::pair_device`], with the first of `addrs` that answers.
    pub async fn pair_with_addrs(&self, addrs: &[SocketAddr]) -> Result<(), BoxError> {
        let mut connection = connect(addrs, &self.identity, &self.paired).await?;
        let (id, name) = (connection.peer.id.clone(), connection.peer.name.clone());
        if connection.paired {
            (self.sink)(pair_done(&id, &name, Ok(PairOutcome::Paired)));
            return Ok(());
        }
        let identity = self.identity.clone();
        let prompts = self.pair_prompts.clone();
        let paired = Arc::clone(&self.paired);
        let sink = self.sink.clone();
        tokio::spawn(async move {
            let outcome = connection
                .pair(&identity, &prompts, &paired)
                .await
                .map_err(|e| e.to_string());
            sink(pair_done(&id, &name, outcome));
        });
        Ok(())
    }

    /// Answer an [`AppEvent::PairCode`]: `true` if the codes match. Returns
    /// false if it had already been withdrawn or answered.
    pub fn respond_pair(&self, pair_id: &str, accept: bool) -> bool {
        let respond = self.pending_pairs.lock().unwrap().remove(pair_id);
        respond.is_some_and(|r| r.send(accept).is_ok())
    }

    /// Forget a paired device. If it is on the network, connect once so it
    /// hears about it right away (the handshake carries our paired flag)
    /// rather than at the next transfer. Returns whether it was paired.
    pub fn unpair_device(&self, device_id: &str) -> Result<bool, BoxError> {
        if !self.paired.remove(device_id)? {
            return Ok(false);
        }
        if let Ok(addrs) = self.addrs_of(device_id) {
            self.notify_unpaired(addrs);
        }
        Ok(true)
    }

    /// Connect once in the background so a device we just unpaired sees our
    /// `paired: false` and drops us too. Safe to call from any thread.
    fn notify_unpaired(&self, addrs: Vec<SocketAddr>) {
        let identity = self.identity.clone();
        let paired = Arc::clone(&self.paired);
        self.runtime.spawn(async move {
            let _ = connect(&addrs, &identity, &paired).await;
        });
    }

    /// Like [`Node::send_to_device`], to the first of `addrs` that answers.
    pub async fn send_to_addrs(
        &self,
        addrs: &[SocketAddr],
        paths: &[PathBuf],
    ) -> Result<Vec<String>, BoxError> {
        let files = paths
            .iter()
            .map(|path| {
                let meta = std::fs::metadata(path)
                    .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
                if !meta.is_file() {
                    return Err(format!(
                        "{} is a folder; only files can be sent for now",
                        file_name(path)
                    ));
                }
                Ok((path.clone(), meta.len(), self.new_send_id()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut connection = connect(addrs, &self.identity, &self.paired).await?;
        let ids = files.iter().map(|(_, _, id)| id.clone()).collect();
        let sink = self.sink.clone();
        let table = Arc::clone(&self.daemon.transfers);
        tokio::spawn(async move {
            for (path, size, id) in files {
                // The app has no cancel button yet, so the handle goes unused.
                let _ = table.begin_with_id(
                    id.clone(),
                    Transfer::new(
                        Direction::Send,
                        Some(connection.peer.id.clone()),
                        connection.peer.name.clone(),
                        file_name(&path),
                        size,
                    ),
                );
                sink(AppEvent::SendWaiting {
                    transfer_id: id.clone(),
                    device_name: connection.peer.name.clone(),
                    name: file_name(&path),
                    size,
                });
                let mut meter = Meter::new(size);
                let progress_sink = sink.clone();
                let progress_id = id.clone();
                let progress_table = Arc::clone(&table);
                let result = connection
                    .send_file(&path, &mut |sent| {
                        progress_table.update(&progress_id, |t| {
                            t.status = Status::Transferring;
                            t.bytes = sent;
                        });
                        if let Some(bytes_per_sec) = meter.update(sent) {
                            progress_sink(AppEvent::SendProgress {
                                transfer_id: progress_id.clone(),
                                bytes: sent,
                                size,
                                bytes_per_sec,
                            });
                        }
                    })
                    .await;
                match result {
                    Ok(FileResult::Delivered(outcome)) => {
                        table.update(&id, |t| {
                            t.bytes = outcome.size;
                            t.sha256 = Some(outcome.sha256.clone());
                            t.status = Status::Done;
                        });
                        sink(AppEvent::SendDone {
                            transfer_id: id,
                            sha256: outcome.sha256,
                        })
                    }
                    Ok(FileResult::Declined) => {
                        table.finish(&id, Status::Declined, None);
                        sink(AppEvent::SendDeclined { transfer_id: id })
                    }
                    Err(e) => {
                        table.finish(&id, Status::Failed, Some(e.to_string()));
                        // The connection is unusable now; fail the rest too.
                        sink(AppEvent::SendFailed {
                            transfer_id: id,
                            error: e.to_string(),
                        });
                        return;
                    }
                }
            }
        });
        Ok(ids)
    }

    fn new_send_id(&self) -> String {
        format!("send-{}", self.next_send_id.fetch_add(1, Ordering::Relaxed))
    }
}

fn devices(peers: &[Peer], paired: &PairedDevices) -> Vec<Device> {
    let mut devices: Vec<Device> = peers.iter().map(|p| Device::new(p, paired)).collect();
    devices.sort_by_key(|d| d.name.to_lowercase());
    devices
}

fn file_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

async fn connect(
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

/// Turn the server's approval requests into UI events, and expire them when
/// the server stops waiting.
async fn forward_requests(
    mut requests: mpsc::Receiver<FileRequest>,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<bool>>>>,
    sink: EventSink,
) {
    while let Some(request) = requests.recv().await {
        let FileRequest {
            transfer_id,
            peer_name,
            peer_addr,
            name,
            size,
            respond,
            // The app has no fetch wording yet; it asks as for any file.
            fetch: _,
        } = request;
        // The server drops its end after APPROVAL_TIMEOUT or if the sender
        // hangs up; we notice by holding a watch on it.
        let (guard_tx, guard_rx) = oneshot::channel::<bool>();
        pending
            .lock()
            .unwrap()
            .insert(transfer_id.clone(), guard_tx);
        sink(AppEvent::IncomingRequest {
            transfer_id: transfer_id.clone(),
            peer_name,
            peer_ip: peer_addr.ip().to_string(),
            name,
            size,
        });
        let pending = Arc::clone(&pending);
        let sink = sink.clone();
        tokio::spawn(async move {
            let mut respond = respond;
            tokio::select! {
                answer = guard_rx => {
                    let _ = respond.send(answer.unwrap_or(false));
                }
                _ = respond.closed() => {
                    pending.lock().unwrap().remove(&transfer_id);
                    sink(AppEvent::IncomingExpired { transfer_id });
                }
            }
        });
    }
}

fn pair_done(id: &str, name: &str, outcome: Result<PairOutcome, String>) -> AppEvent {
    let (status, error) = match outcome {
        Ok(PairOutcome::Paired) => (PairStatus::Paired, None),
        Ok(PairOutcome::Declined { by_peer: false }) => (PairStatus::Declined, None),
        Ok(PairOutcome::Declined { by_peer: true }) => (PairStatus::DeclinedByPeer, None),
        Ok(PairOutcome::TimedOut) => (PairStatus::TimedOut, None),
        Err(e) => (PairStatus::Failed, Some(e)),
    };
    AppEvent::PairDone {
        device_id: id.to_owned(),
        device_name: name.to_owned(),
        status,
        error,
    }
}

/// Turn pairing codes (from either side's pairing) into UI events, and
/// withdraw them when the pairing stops waiting.
async fn forward_pair_prompts(
    mut prompts: mpsc::Receiver<PairPrompt>,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<bool>>>>,
    sink: EventSink,
) {
    let mut next_id = 1u64;
    while let Some(PairPrompt {
        peer,
        code,
        incoming,
        respond,
    }) = prompts.recv().await
    {
        let pair_id = format!("pair-{next_id}");
        next_id += 1;
        let (guard_tx, guard_rx) = oneshot::channel::<bool>();
        pending.lock().unwrap().insert(pair_id.clone(), guard_tx);
        sink(AppEvent::PairCode {
            pair_id: pair_id.clone(),
            device_id: peer.id,
            device_name: peer.name,
            code,
            incoming,
        });
        let pending = Arc::clone(&pending);
        let sink = sink.clone();
        tokio::spawn(async move {
            let mut respond = respond;
            tokio::select! {
                answer = guard_rx => {
                    let _ = respond.send(answer.unwrap_or(false));
                }
                _ = respond.closed() => {
                    pending.lock().unwrap().remove(&pair_id);
                    sink(AppEvent::PairExpired { pair_id });
                }
            }
        });
    }
}

async fn forward_receive_events(
    mut events: mpsc::UnboundedReceiver<ReceiveEvent>,
    sink: EventSink,
) {
    let mut meters: HashMap<String, Meter> = HashMap::new();
    while let Some(event) = events.recv().await {
        match event {
            ReceiveEvent::Started {
                transfer_id,
                peer_name,
                name,
                size,
            } => {
                meters.insert(transfer_id.clone(), Meter::new(size));
                sink(AppEvent::ReceiveStarted {
                    transfer_id,
                    peer_name,
                    name,
                    size,
                });
            }
            ReceiveEvent::Progress {
                transfer_id,
                received,
            } => {
                let Some(meter) = meters.get_mut(&transfer_id) else {
                    continue;
                };
                if let Some(bytes_per_sec) = meter.update(received) {
                    sink(AppEvent::ReceiveProgress {
                        size: meter.size,
                        transfer_id,
                        bytes: received,
                        bytes_per_sec,
                    });
                }
            }
            ReceiveEvent::Saved {
                transfer_id,
                path,
                sha256,
            } => {
                meters.remove(&transfer_id);
                sink(AppEvent::ReceiveDone {
                    transfer_id,
                    path: path.display().to_string(),
                    sha256,
                });
            }
            ReceiveEvent::Failed { transfer_id, error } => {
                meters.remove(&transfer_id);
                sink(AppEvent::ReceiveFailed { transfer_id, error });
            }
        }
    }
}

/// Throttles progress for one transfer and measures its speed.
struct Meter {
    size: u64,
    /// Set by the first update: bytes only flow once the receiver accepts,
    /// so the wait for approval doesn't count against the speed.
    started: Option<Instant>,
    last_sent: Option<Instant>,
}

impl Meter {
    fn new(size: u64) -> Self {
        Self {
            size,
            started: None,
            last_sent: None,
        }
    }

    /// Bytes per second so far, if an event is due for `bytes` (always for
    /// the final byte count).
    fn update(&mut self, bytes: u64) -> Option<f64> {
        let now = Instant::now();
        let started = *self.started.get_or_insert(now);
        let due = bytes >= self.size
            || self
                .last_sent
                .is_none_or(|t| now.duration_since(t) >= PROGRESS_INTERVAL);
        if !due {
            return None;
        }
        self.last_sent = Some(now);
        let secs = now.duration_since(started).as_secs_f64().max(0.001);
        Some(bytes as f64 / secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opendrop::transfer::{CHUNK_SIZE, sha256_hex};

    /// A node on loopback without mDNS, and the events it reports.
    async fn node(name: &str, dir: &Path) -> (Arc<Node>, mpsc::UnboundedReceiver<AppEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let sink: EventSink = Arc::new(move |e| {
            let _ = tx.send(e);
        });
        let node = Node::start(
            DeviceIdentity::new(name),
            Arc::new(PairedDevices::in_memory()),
            0,
            dir.to_owned(),
            false,
            sink,
        )
        .await
        .unwrap();
        (node, rx)
    }

    fn addr(node: &Node) -> Vec<SocketAddr> {
        vec![SocketAddr::from(([127, 0, 0, 1], node.port))]
    }

    /// Collect events until one matches `last`, failing after 10 seconds.
    async fn until(
        rx: &mut mpsc::UnboundedReceiver<AppEvent>,
        last: impl Fn(&AppEvent) -> bool,
    ) -> Vec<AppEvent> {
        let mut log = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), async {
            while let Some(event) = rx.recv().await {
                let done = last(&event);
                log.push(event);
                if done {
                    return;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out; got {log:?}"));
        log
    }

    #[tokio::test]
    async fn accepted_file_arrives_with_progress_and_matching_hash() {
        let src = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        let content: Vec<u8> = (0..CHUNK_SIZE * 40 + 123)
            .map(|i| (i % 251) as u8)
            .collect();
        let path = src.path().join("photo.jpg");
        std::fs::write(&path, &content).unwrap();
        let (sender, mut sent) = node("Sender", src.path()).await;
        let (receiver, mut received) = node("Receiver", dest.path()).await;

        let ids = sender
            .send_to_addrs(&addr(&receiver), &[path])
            .await
            .unwrap();
        let [send_id] = ids.as_slice() else {
            panic!("{ids:?}")
        };

        // The receiver is asked first and nothing is written until it says yes.
        let asked = until(&mut received, |e| {
            matches!(e, AppEvent::IncomingRequest { .. })
        })
        .await;
        let AppEvent::IncomingRequest {
            transfer_id,
            peer_name,
            name,
            size,
            ..
        } = &asked[0]
        else {
            panic!("{asked:?}")
        };
        assert_eq!(
            (peer_name.as_str(), name.as_str(), *size),
            ("Sender", "photo.jpg", content.len() as u64)
        );
        assert!(std::fs::read_dir(dest.path()).unwrap().next().is_none());
        assert!(receiver.respond(transfer_id, true));
        assert!(
            !receiver.respond(transfer_id, true),
            "answering twice must not work"
        );

        let rlog = until(&mut received, |e| {
            matches!(
                e,
                AppEvent::ReceiveDone { .. } | AppEvent::ReceiveFailed { .. }
            )
        })
        .await;
        let slog = until(&mut sent, |e| {
            matches!(e, AppEvent::SendDone { .. } | AppEvent::SendFailed { .. })
        })
        .await;

        let expected = sha256_hex(&content);
        assert_eq!(
            slog.last(),
            Some(&AppEvent::SendDone {
                transfer_id: send_id.clone(),
                sha256: expected.clone()
            })
        );
        let Some(AppEvent::ReceiveDone { path, sha256, .. }) = rlog.last() else {
            panic!("{rlog:?}")
        };
        assert_eq!(sha256, &expected);
        assert_eq!(std::fs::read(path).unwrap(), content);

        for log in [&slog, &rlog] {
            let progress: Vec<(u64, f64)> = log
                .iter()
                .filter_map(|e| match e {
                    AppEvent::SendProgress {
                        bytes,
                        bytes_per_sec,
                        ..
                    }
                    | AppEvent::ReceiveProgress {
                        bytes,
                        bytes_per_sec,
                        ..
                    } => Some((*bytes, *bytes_per_sec)),
                    _ => None,
                })
                .collect();
            assert!(!progress.is_empty(), "{log:?}");
            assert!(progress.windows(2).all(|w| w[0].0 < w[1].0), "{progress:?}");
            assert_eq!(progress.last().unwrap().0, content.len() as u64);
            assert!(progress.iter().all(|p| p.1 > 0.0), "{progress:?}");
        }
    }

    #[tokio::test]
    async fn declined_file_is_reported_and_not_saved() {
        let src = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        let path = src.path().join("secret.txt");
        std::fs::write(&path, b"no").unwrap();
        let (sender, mut sent) = node("Sender", src.path()).await;
        let (receiver, mut received) = node("Receiver", dest.path()).await;

        let ids = sender
            .send_to_addrs(&addr(&receiver), &[path])
            .await
            .unwrap();
        let asked = until(&mut received, |e| {
            matches!(e, AppEvent::IncomingRequest { .. })
        })
        .await;
        let AppEvent::IncomingRequest { transfer_id, .. } = &asked[0] else {
            panic!()
        };
        assert!(receiver.respond(transfer_id, false));

        let slog = until(&mut sent, |e| {
            matches!(e, AppEvent::SendDeclined { .. } | AppEvent::SendDone { .. })
        })
        .await;
        assert_eq!(
            slog.last(),
            Some(&AppEvent::SendDeclined {
                transfer_id: ids[0].clone()
            })
        );
        assert!(std::fs::read_dir(dest.path()).unwrap().next().is_none());
    }

    #[tokio::test]
    async fn sending_a_folder_or_to_nobody_fails_up_front() {
        let src = tempfile::tempdir().unwrap();
        let (sender, _) = node("Sender", src.path()).await;
        let folder = sender
            .send_to_addrs(&addr(&sender), &[src.path().to_owned()])
            .await;
        assert!(folder.unwrap_err().to_string().contains("folder"));

        let file = src.path().join("a.txt");
        std::fs::write(&file, b"a").unwrap();
        let closed = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let nobody = sender.send_to_addrs(&[closed], &[file]).await;
        assert!(nobody.unwrap_err().to_string().contains("could not reach"));
    }

    /// Wait for a `PairCode` and return `(pair_id, code, incoming)`.
    async fn pair_code(rx: &mut mpsc::UnboundedReceiver<AppEvent>) -> (String, String, bool) {
        let log = until(rx, |e| matches!(e, AppEvent::PairCode { .. })).await;
        let Some(AppEvent::PairCode {
            pair_id,
            code,
            incoming,
            ..
        }) = log.last()
        else {
            panic!("{log:?}")
        };
        (pair_id.clone(), code.clone(), *incoming)
    }

    async fn pair_done(rx: &mut mpsc::UnboundedReceiver<AppEvent>) -> (String, PairStatus) {
        let log = until(rx, |e| matches!(e, AppEvent::PairDone { .. })).await;
        let Some(AppEvent::PairDone {
            device_id, status, ..
        }) = log.last()
        else {
            panic!("{log:?}")
        };
        (device_id.clone(), *status)
    }

    #[tokio::test]
    async fn nodes_pair_when_both_users_confirm_the_same_code() {
        let dir = tempfile::tempdir().unwrap();
        let (mac, mut mac_events) = node("Mac", dir.path()).await;
        let (pc, mut pc_events) = node("PC", dir.path()).await;

        mac.pair_with_addrs(&addr(&pc)).await.unwrap();
        let (mac_pair, mac_code, mac_incoming) = pair_code(&mut mac_events).await;
        let (pc_pair, pc_code, pc_incoming) = pair_code(&mut pc_events).await;
        assert_eq!(mac_code, pc_code);
        assert!(!mac_incoming && pc_incoming);
        assert!(pc.respond_pair(&pc_pair, true));
        assert!(mac.respond_pair(&mac_pair, true));
        assert!(
            !mac.respond_pair(&mac_pair, true),
            "answering twice must not work"
        );

        assert_eq!(
            pair_done(&mut mac_events).await,
            (pc.identity.id.clone(), PairStatus::Paired)
        );
        assert_eq!(
            pair_done(&mut pc_events).await,
            (mac.identity.id.clone(), PairStatus::Paired)
        );
        assert!(mac.paired.get(&pc.identity.id).is_some());
        assert!(pc.paired.get(&mac.identity.id).is_some());

        // Pairing again is a no-op that reports the existing pairing.
        mac.pair_with_addrs(&addr(&pc)).await.unwrap();
        assert_eq!(pair_done(&mut mac_events).await.1, PairStatus::Paired);
    }

    #[tokio::test]
    async fn a_decline_withdraws_the_other_code_and_pairs_nobody() {
        let dir = tempfile::tempdir().unwrap();
        let (mac, mut mac_events) = node("Mac", dir.path()).await;
        let (pc, mut pc_events) = node("PC", dir.path()).await;

        mac.pair_with_addrs(&addr(&pc)).await.unwrap();
        let (mac_pair, _, _) = pair_code(&mut mac_events).await;
        let (pc_pair, _, _) = pair_code(&mut pc_events).await;
        assert!(pc.respond_pair(&pc_pair, false));
        // The Mac's code is withdrawn and the result reported, in either order.
        let mut log = Vec::new();
        let expired = AppEvent::PairExpired {
            pair_id: mac_pair.clone(),
        };
        while !(log.contains(&expired)
            && log.iter().any(|e| matches!(e, AppEvent::PairDone { .. })))
        {
            log.extend(until(&mut mac_events, |_| true).await);
        }
        assert!(log.iter().any(|e| matches!(
            e,
            AppEvent::PairDone {
                status: PairStatus::DeclinedByPeer,
                ..
            }
        )));
        assert!(!mac.respond_pair(&mac_pair, true));
        assert_eq!(pair_done(&mut pc_events).await.1, PairStatus::Declined);
        assert!(mac.paired.list().is_empty() && pc.paired.list().is_empty());
    }

    #[tokio::test]
    async fn unpair_is_mirrored_on_the_next_connection() {
        let dir = tempfile::tempdir().unwrap();
        let (mac, mut mac_events) = node("Mac", dir.path()).await;
        let (pc, mut pc_events) = node("PC", dir.path()).await;
        mac.pair_with_addrs(&addr(&pc)).await.unwrap();
        let (mac_pair, _, _) = pair_code(&mut mac_events).await;
        let (pc_pair, _, _) = pair_code(&mut pc_events).await;
        pc.respond_pair(&pc_pair, true);
        mac.respond_pair(&mac_pair, true);
        pair_done(&mut pc_events).await;
        pair_done(&mut mac_events).await;

        assert!(pc.unpair_device(&mac.identity.id).unwrap());
        assert!(!pc.unpair_device(&mac.identity.id).unwrap());
        // The device list is resent without the badge.
        let log = until(&mut pc_events, |e| matches!(e, AppEvent::Devices { .. })).await;
        assert!(matches!(log.last(), Some(AppEvent::Devices { .. })));

        // Any next connection (here, a file) makes the Mac forget the PC too.
        let file = dir.path().join("hi.txt");
        std::fs::write(&file, b"hi").unwrap();
        let started = Instant::now();
        mac.send_to_addrs(&addr(&pc), &[file]).await.unwrap();
        assert!(mac.paired.get(&pc.identity.id).is_none());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// Tauri calls `unpair_device` on its main thread, outside any Tokio
    /// runtime; the follow-up connection must still start (this used to
    /// panic with "there is no reactor running") and the other device must
    /// drop the pairing right away.
    #[test]
    fn unpair_notifies_the_peer_when_called_outside_the_runtime() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let ((mac, mut mac_events), (pc, mut pc_events)) = runtime
            .block_on(async { (node("Mac", dir.path()).await, node("PC", dir.path()).await) });
        runtime.block_on(async {
            mac.pair_with_addrs(&addr(&pc)).await.unwrap();
            let (mac_pair, _, _) = pair_code(&mut mac_events).await;
            let (pc_pair, _, _) = pair_code(&mut pc_events).await;
            pc.respond_pair(&pc_pair, true);
            mac.respond_pair(&mac_pair, true);
            pair_done(&mut pc_events).await;
            pair_done(&mut mac_events).await;
        });

        // Like the Tauri command: on this (non-runtime) thread.
        assert!(pc.paired.remove(&mac.identity.id).unwrap());
        let started = Instant::now();
        pc.notify_unpaired(addr(&mac));
        runtime.block_on(async {
            while mac.paired.get(&pc.identity.id).is_some() {
                assert!(
                    started.elapsed() < Duration::from_secs(5),
                    "Mac still paired"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
    }

    #[test]
    fn meter_throttles_but_always_reports_the_end() {
        let mut meter = Meter::new(100);
        assert!(meter.update(10).is_some());
        assert!(meter.update(20).is_none());
        assert!(meter.update(100).is_some());
    }
}

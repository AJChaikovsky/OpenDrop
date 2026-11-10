//! Listens for incoming connections and answers them.
//!
//! Connection lifecycle:
//!
//! ```text
//! client                     server
//!   | --- hello ------------> |   signed handshake, see `handshake`
//!   | <-------------- welcome |
//!   | --- hello_proof ------> |
//!   | <---------------- ready |
//!   | --- pair_request -----> |   (optional; see `pairing`)
//!   | --- text -------------> |   (repeatable)
//!   | <------------- text_ack |
//!   |                         |
//!   | --- file_offer -------> |   (repeatable; Task 3)
//!   | <---------- file_accept |   or file_decline, then the next offer
//!   | === raw bytes ========> |   exactly `size` bytes, unframed
//!   | --- file_done --------> |   SHA-256 of those bytes
//!   | <-------- file_received |   after the hash matched and the file was saved
//!   | --- [close] ----------> |
//! ```
//!
//! Every offered file needs the receiving user's approval (see [`Approval`])
//! before any bytes are written; accepted files land in the download folder.

use super::client::{Connection, FileResult};
use super::fetch::{Claim, PendingFetches};
use super::grants::{GrantOffer, Grants};
use super::limit::RateLimit;
use super::secure::{SecureStream, is_peer_cancel};
use super::{APPROVAL_TIMEOUT, BoxError, DeviceIdentity, IO_TIMEOUT, handshake};
use crate::audit::{AuditLog, Entry, Event};
use crate::daemon::{Direction, Status, Transfer, TransferTable};
use crate::pairing::store::PairedDevices;
use crate::pairing::{self, PairOutcome, PairPrompts, PairResult, PairResults};
use crate::protocol::FolderEntry;
use crate::protocol::{
    ErrorCode, FetchDeclineReason, Message, ProtocolError, read_message, share_list_within_frame,
    write_message,
};
use crate::share::{ShareError, Shares};
use crate::transfer::folder::{MAX_FOLDER_FILES, Staging, check_listing, folder_name, tree_hash};
use crate::transfer::{PartFile, copy_hashed, sanitize_file_name};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

/// A connection after the handshake: everything on it is encrypted.
type Secure<'a> = SecureStream<&'a mut TcpStream>;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

/// An offered file waiting for the user's decision. Send `true` on `respond`
/// to accept it, `false` (or drop it) to decline.
#[derive(Debug)]
pub struct FileRequest {
    /// Matches the [`ReceiveEvent`]s for this file if it's accepted.
    pub transfer_id: String,
    pub peer_name: String,
    pub peer_addr: SocketAddr,
    /// The peer is a paired device that proved it holds the key we paired
    /// with. Otherwise anyone could have picked this name: show it as
    /// unverified.
    pub verified: bool,
    /// Already sanitized: this is the name it will be saved under (or close
    /// to it, if a file with that name exists).
    pub name: String,
    pub size: u64,
    pub respond: oneshot::Sender<bool>,
    /// Set when the peer asks to fetch one of our shared files rather than
    /// offering us one: approving sends the file to them.
    pub fetch: Option<FetchInfo>,
    /// For an incoming file: firing it after a yes stops the download
    /// midway, tells the sender, and throws away what arrived.
    pub cancel: Option<oneshot::Sender<()>>,
    /// Set when the offer is a folder: how many files it holds (`name` is
    /// the folder's, `size` the total).
    pub files: Option<u64>,
}

/// What a fetch request adds to a [`FileRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchInfo {
    pub peer_id: String,
    /// The requester's stated reason, to show the user.
    pub reason: String,
    /// The requester says an AI assistant asked for the file.
    pub via_assistant: bool,
    /// A grant the user can give along with a yes: this device may fetch
    /// from this file's folder for 10 minutes without asking.
    pub grant: Option<GrantOffer>,
}

/// What happens to an accepted file, for a UI that shows incoming transfers.
#[derive(Debug, Clone, PartialEq)]
pub enum ReceiveEvent {
    /// Accepted; bytes are about to arrive.
    Started {
        transfer_id: String,
        peer_name: String,
        name: String,
        size: u64,
    },
    /// Bytes received so far, after every chunk.
    Progress { transfer_id: String, received: u64 },
    /// Verified and saved at `path`.
    Saved {
        transfer_id: String,
        path: PathBuf,
        sha256: String,
    },
    /// Dropped connection, checksum mismatch or storage error; nothing saved.
    Failed { transfer_id: String, error: String },
    /// Called off midway, by our side or (`by_peer`) the sender; nothing
    /// saved.
    Cancelled { transfer_id: String, by_peer: bool },
}

/// Why a receive stopped early on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReceiveCancelled {
    by_peer: bool,
}

impl std::fmt::Display for ReceiveCancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.by_peer {
            write!(f, "cancelled by the sender")
        } else {
            write!(f, "cancelled")
        }
    }
}

impl std::error::Error for ReceiveCancelled {}

/// Where [`run_with_events`] reports [`ReceiveEvent`]s.
pub type ReceiveEvents = mpsc::UnboundedSender<ReceiveEvent>;

/// How offered files get approved.
#[derive(Debug, Clone)]
pub enum Approval {
    /// Send each offer to whoever holds the receiver (a terminal prompt now,
    /// the desktop app's accept dialog later). Unanswered offers are declined
    /// after [`APPROVAL_TIMEOUT`].
    Ask(mpsc::Sender<FileRequest>),
    /// Take every file without asking. Only for tests and explicit opt-in.
    AcceptAll,
}

/// Everything a listening device needs.
#[derive(Debug, Clone)]
pub struct Options {
    pub identity: DeviceIdentity,
    /// Where accepted files are saved; created when the first file arrives.
    pub download_dir: PathBuf,
    pub approval: Approval,
    /// Where to report what happens to each accepted file, if anywhere.
    pub events: Option<ReceiveEvents>,
    /// Devices we paired with; every connecting peer is checked against it.
    pub paired: Arc<PairedDevices>,
    /// Where to show pairing codes when a peer asks to pair. Without it,
    /// pair requests are declined.
    pub pair_prompts: Option<PairPrompts>,
    /// Where to report how pairings that peers started ended, if anywhere.
    pub pair_results: Option<PairResults>,
    /// What paired devices may list and fetch. Without it nothing is shared.
    pub shares: Option<Arc<Shares>>,
    /// Let unpaired devices list and fetch too (local demos only).
    pub allow_unpaired_fetch: bool,
    /// Fetches we started, whose offers we take without asking.
    pub fetches: Arc<PendingFetches>,
    /// Where to record files we send in answer to fetches, if anywhere.
    pub outgoing: Option<Arc<TransferTable>>,
    /// How often each device may list our shares.
    pub list_limit: Arc<RateLimit>,
    /// Folders devices may fetch from for a while without asking.
    pub grants: Arc<Grants>,
    /// Where lists, requests and decisions are recorded.
    pub audit: Arc<AuditLog>,
}

impl Options {
    pub fn new(identity: DeviceIdentity, download_dir: PathBuf, approval: Approval) -> Self {
        Self {
            identity,
            download_dir,
            approval,
            events: None,
            paired: Arc::new(PairedDevices::in_memory()),
            pair_prompts: None,
            pair_results: None,
            shares: None,
            allow_unpaired_fetch: false,
            fetches: Arc::new(PendingFetches::new()),
            outgoing: None,
            list_limit: Arc::new(RateLimit::listings()),
            grants: Arc::new(Grants::new()),
            audit: Arc::new(AuditLog::in_memory()),
        }
    }
}

/// Accept connections forever, handling each on its own task. Received files
/// are saved in `download_dir`, which is created when the first file arrives.
pub async fn run(
    listener: TcpListener,
    identity: DeviceIdentity,
    download_dir: PathBuf,
    approval: Approval,
) -> std::io::Result<()> {
    serve(listener, Options::new(identity, download_dir, approval)).await
}

/// [`run`], also reporting what happens to each accepted file on `events`.
pub async fn run_with_events(
    listener: TcpListener,
    identity: DeviceIdentity,
    download_dir: PathBuf,
    approval: Approval,
    events: Option<ReceiveEvents>,
) -> std::io::Result<()> {
    let options = Options {
        events,
        ..Options::new(identity, download_dir, approval)
    };
    serve(listener, options).await
}

/// Accept connections forever with the given [`Options`].
pub async fn serve(listener: TcpListener, options: Options) -> std::io::Result<()> {
    let options = Arc::new(options);
    loop {
        let (mut stream, peer_addr) = listener.accept().await?;
        let options = Arc::clone(&options);
        tokio::spawn(async move {
            match handle_connection(&mut stream, peer_addr, &options).await {
                Ok(()) => {}
                // Already reported when it happened.
                Err(e) if e.downcast_ref::<ReceiveCancelled>().is_some() => {}
                Err(e) => {
                    eprintln!("[{peer_addr}] connection ended with error: {e}");
                    close_after_error(stream).await;
                }
            }
        });
    }
}

/// A peer's request for one of our shared files.
struct IncomingFetch {
    fetch_id: String,
    file_id: String,
    reason: String,
    via_assistant: bool,
    /// The requester's listener: its address on this connection, with the
    /// port it asked us to use.
    reply_to: SocketAddr,
}

/// Answer a fetch request: check pairing and the share list, ask our user,
/// and if they approve, send the file back over a new connection.
async fn serve_fetch(
    stream: &mut Secure<'_>,
    options: &Options,
    peer: &handshake::Handshake,
    peer_addr: SocketAddr,
    request: IncomingFetch,
) -> Result<(), BoxError> {
    let peer_name = &peer.peer.name;
    let fetch_id = request.fetch_id.clone();
    let decline = |reason| Message::FetchDeclined {
        fetch_id: fetch_id.clone(),
        reason,
    };
    let entry = |event| {
        Entry::new(event, Some(&peer.peer.id), peer_name).via_assistant(request.via_assistant)
    };
    let audit = &options.audit;
    audit.record(
        entry(Event::Request)
            .file(&request.file_id)
            .detail(&request.reason),
    );
    if !(peer.paired || options.allow_unpaired_fetch) {
        println!("[{peer_addr}] refused a fetch from unpaired \"{peer_name}\"");
        audit.record(
            entry(Event::Decline)
                .file(&request.file_id)
                .detail("not paired"),
        );
        write_message(stream, &decline(FetchDeclineReason::NotPaired)).await?;
        return Ok(());
    }
    let resolved = match &options.shares {
        Some(shares) => {
            let shares = Arc::clone(shares);
            let file_id = request.file_id.clone();
            tokio::task::spawn_blocking(move || shares.resolve(&file_id)).await?
        }
        None => Err(ShareError::NotShared),
    };
    let Ok(resolved) = resolved else {
        println!("[{peer_addr}] \"{peer_name}\" asked for a file that isn't shared");
        audit.record(
            entry(Event::Decline)
                .file(&request.file_id)
                .detail("not shared"),
        );
        write_message(stream, &decline(FetchDeclineReason::NotShared)).await?;
        return Ok(());
    };
    let file = resolved.file.clone();
    // Sending a file away always takes an explicit yes: auto-accept is
    // about files coming in, so it doesn't approve fetches.
    let granted = options.grants.covers(&peer.peer.id, &resolved.disk_path);
    let answer = match &options.approval {
        // A folder grant the user gave this device earlier answers for them.
        _ if granted => {
            println!(
                "[{peer_addr}] \"{peer_name}\" fetches \"{}\" under a folder grant",
                file.name
            );
            Ok(())
        }
        Approval::AcceptAll => Err(FetchDeclineReason::Declined),
        Approval::Ask(requests) => {
            let (respond, decision) = oneshot::channel();
            let ask = FileRequest {
                transfer_id: fetch_id.clone(),
                peer_name: peer_name.clone(),
                peer_addr,
                verified: peer.paired,
                name: file.name.clone(),
                size: file.size,
                respond,
                cancel: None,
                files: None,
                fetch: Some(FetchInfo {
                    peer_id: peer.peer.id.clone(),
                    reason: request.reason.clone(),
                    via_assistant: request.via_assistant,
                    grant: resolved.disk_path.parent().map(|folder| {
                        GrantOffer::new(
                            Arc::clone(&options.grants),
                            peer.peer.id.clone(),
                            folder.to_owned(),
                        )
                        .audited(Arc::clone(audit), peer_name)
                    }),
                }),
            };
            if requests.send(ask).await.is_err() {
                Err(FetchDeclineReason::Declined)
            } else {
                match timeout(APPROVAL_TIMEOUT, decision).await {
                    Ok(Ok(true)) => Ok(()),
                    Ok(_) => Err(FetchDeclineReason::Declined),
                    Err(_) => Err(FetchDeclineReason::Timeout),
                }
            }
        }
    };
    if let Err(reason) = answer {
        println!(
            "[{peer_addr}] fetch of \"{}\" by \"{peer_name}\": {reason:?}",
            file.name
        );
        audit.record(entry(Event::Decline).file(&file.name).detail(match reason {
            FetchDeclineReason::Timeout => "no answer in time",
            _ => "declined",
        }));
        write_message(stream, &decline(reason)).await?;
        return Ok(());
    }
    audit.record(entry(Event::Approve).file(&file.name).detail(if granted {
        "under a folder grant"
    } else {
        "approved"
    }));
    write_message(
        stream,
        &Message::FetchAccepted {
            fetch_id: fetch_id.clone(),
        },
    )
    .await?;
    let table = options.outgoing.clone();
    if let Some(table) = &table
        && table.get(&fetch_id).is_none()
    {
        table.begin_with_id(
            fetch_id.clone(),
            Transfer::new(
                Direction::Send,
                Some(peer.peer.id.clone()),
                peer_name.clone(),
                file.name.clone(),
                file.size,
            ),
        );
    }
    tokio::spawn(push_fetched(
        options.identity.clone(),
        Arc::clone(&options.paired),
        peer.peer.id.clone(),
        request.reply_to,
        resolved.disk_path,
        fetch_id,
        table,
        (
            Arc::clone(audit),
            Entry::new(Event::Send, Some(&peer.peer.id), peer_name)
                .file(&file.name)
                .via_assistant(request.via_assistant),
        ),
    ));
    Ok(())
}

/// Send an approved fetch back to the requester's listener, making sure it
/// is the same device that asked.
#[allow(clippy::too_many_arguments)]
async fn push_fetched(
    identity: DeviceIdentity,
    paired: Arc<PairedDevices>,
    requester_id: String,
    reply_to: SocketAddr,
    path: PathBuf,
    fetch_id: String,
    table: Option<Arc<TransferTable>>,
    audit: (Arc<AuditLog>, Entry),
) {
    let record = |change: &dyn Fn(&mut Transfer)| {
        if let Some(table) = &table {
            table.update(&fetch_id, change);
        }
    };
    let result = async {
        let mut connection =
            Connection::open_with(&reply_to.to_string(), &identity, &paired).await?;
        if connection.peer.id != requester_id {
            return Err(BoxError::from(format!(
                "{reply_to} is \"{}\", not the device that asked",
                connection.peer.name
            )));
        }
        connection
            .send_fetched(&path, &fetch_id, &mut |sent| {
                record(&|t| {
                    t.status = Status::Transferring;
                    t.bytes = sent;
                })
            })
            .await
    }
    .await;
    match &result {
        Ok(FileResult::Delivered(outcome)) => {
            println!("[{reply_to}] sent fetched \"{}\"", outcome.name);
            record(&|t| {
                t.bytes = outcome.size;
                t.sha256 = Some(outcome.sha256.clone());
                t.status = Status::Done;
            })
        }
        Ok(FileResult::Declined) => record(&|t| t.status = Status::Declined),
        Ok(FileResult::Cancelled | FileResult::CancelledByPeer) => {
            println!("[{reply_to}] fetched file cancelled by the device that asked");
            record(&|t| {
                t.status = Status::Cancelled;
                t.error = Some("cancelled by the device that asked".into());
            })
        }
        Err(e) => {
            eprintln!("[{reply_to}] could not send fetched file: {e}");
            record(&|t| {
                t.status = Status::Failed;
                t.error = Some(e.to_string());
            })
        }
    }
    let (log, entry) = audit;
    log.record(entry.detail(match &result {
        Ok(FileResult::Delivered(_)) => "fetched: done".to_owned(),
        Ok(FileResult::Declined) => "fetched: declined".to_owned(),
        Ok(FileResult::Cancelled | FileResult::CancelledByPeer) => "fetched: cancelled".to_owned(),
        Err(e) => format!("fetched: failed ({e})"),
    }));
}

/// Hang up without losing the error we just sent. Closing a socket that
/// still has unread bytes from the peer (say, an offer it sent without
/// waiting for our reply) makes the OS send a reset, and Windows then
/// throws away data the peer hasn't read yet, our error included. So
/// finish our side first and discard what the peer still sends, briefly.
async fn close_after_error(mut stream: TcpStream) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let _ = stream.shutdown().await;
    let mut sink = [0u8; 4096];
    let drain = async { while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {} };
    let _ = timeout(std::time::Duration::from_secs(1), drain).await;
}

async fn handle_connection(
    raw: &mut TcpStream,
    peer_addr: SocketAddr,
    options: &Options,
) -> Result<(), BoxError> {
    let download_dir = options.download_dir.as_path();
    let approval = &options.approval;
    let events = options.events.as_ref();
    let peer = handshake::accept(raw, &options.identity, &options.paired).await?;
    let mut secure = SecureStream::new(raw, &peer.keys);
    let stream = &mut secure;
    let peer_name = peer.peer.name.clone();
    println!(
        "[{peer_addr}] connected: \"{peer_name}\" ({}){}",
        peer.peer.id,
        if peer.paired { ", paired" } else { "" }
    );

    loop {
        match next_message(stream).await {
            Ok(Message::Text { body }) => {
                println!("[{peer_addr}] {peer_name}: {body}");
                write_message(
                    stream,
                    &Message::TextAck {
                        received_bytes: body.len(),
                    },
                )
                .await?;
            }
            Ok(Message::FileOffer {
                transfer_id,
                name,
                size,
            }) => {
                receive_file(
                    stream,
                    download_dir,
                    approval,
                    events,
                    &peer,
                    &options.audit,
                    peer_addr,
                    transfer_id,
                    &name,
                    size,
                    None,
                    None,
                )
                .await?;
            }
            Ok(Message::FolderOffer {
                transfer_id,
                name,
                files,
                size,
            }) => {
                let entries = match read_listing(stream, &transfer_id, files, size).await {
                    Ok(entries) => entries,
                    Err(why) => {
                        println!("[{peer_addr}] refused folder \"{name}\" from {peer_name}: {why}");
                        return reject(stream, ErrorCode::FileRejected, why).await;
                    }
                };
                receive_file(
                    stream,
                    download_dir,
                    approval,
                    events,
                    &peer,
                    &options.audit,
                    peer_addr,
                    transfer_id,
                    &name,
                    size,
                    None,
                    Some(entries),
                )
                .await?;
            }
            Ok(Message::FetchOffer {
                transfer_id,
                name,
                size,
                fetch_id,
            }) => {
                // Only an offer answering a fetch we started skips the prompt;
                // a wrong device or size falls back to the usual question.
                let (approval, stop) =
                    match options
                        .fetches
                        .claim(&fetch_id, &peer.peer.id, size, &transfer_id)
                    {
                        Claim::Ours(stop) => (&Approval::AcceptAll, Some(stop)),
                        Claim::NotOurs => (approval, None),
                        Claim::Cancelled => {
                            println!("[{peer_addr}] refused \"{name}\": that fetch was cancelled");
                            write_message(stream, &Message::FileDecline { transfer_id }).await?;
                            return Ok(());
                        }
                    };
                receive_file(
                    stream,
                    download_dir,
                    approval,
                    events,
                    &peer,
                    &options.audit,
                    peer_addr,
                    transfer_id,
                    &name,
                    size,
                    stop,
                    None,
                )
                .await?;
            }
            Ok(Message::ShareListRequest { query }) => {
                let entry = |event| Entry::new(event, Some(&peer.peer.id), &peer_name);
                if !(peer.paired || options.allow_unpaired_fetch) {
                    options
                        .audit
                        .record(entry(Event::Decline).detail("listing refused: not paired"));
                    return reject(
                        stream,
                        ErrorCode::NotPaired,
                        "only paired devices can see shared files".into(),
                    )
                    .await;
                }
                if !options.list_limit.allow(&peer.peer.id) {
                    options
                        .audit
                        .record(entry(Event::Decline).detail("listing refused: rate limited"));
                    println!("[{peer_addr}] {peer_name} is listing too often; refused");
                    return reject(
                        stream,
                        ErrorCode::RateLimited,
                        "too many share listings; try again in a minute".into(),
                    )
                    .await;
                }
                let matching = query
                    .as_deref()
                    .map(|q| format!(" matching \"{q}\""))
                    .unwrap_or_default();
                let files = match &options.shares {
                    Some(shares) => {
                        let shares = Arc::clone(shares);
                        tokio::task::spawn_blocking(move || shares.list(query.as_deref()))
                            .await?
                            .unwrap_or_else(|e| {
                                eprintln!("[{peer_addr}] cannot list shares: {e}");
                                Vec::new()
                            })
                    }
                    None => Vec::new(),
                };
                println!(
                    "[{peer_addr}] {peer_name} listed shared files ({} found)",
                    files.len()
                );
                options.audit.record(
                    entry(Event::List).detail(format!("{} file(s){matching}", files.len())),
                );
                write_message(stream, &share_list_within_frame(files)).await?;
            }
            Ok(Message::FetchRequest {
                fetch_id,
                file_id,
                reason,
                via_assistant,
                reply_port,
            }) => {
                let request = IncomingFetch {
                    fetch_id,
                    file_id,
                    reason,
                    via_assistant,
                    reply_to: SocketAddr::new(peer_addr.ip(), reply_port),
                };
                serve_fetch(stream, options, &peer, peer_addr, request).await?;
            }
            Ok(Message::PairRequest { commitment }) => {
                let result = pairing::respond(
                    stream,
                    &options.identity,
                    &peer.peer,
                    peer.nonces,
                    commitment,
                    options.pair_prompts.as_ref(),
                    &options.paired,
                )
                .await;
                if let Some(results) = &options.pair_results {
                    let _ = results.send(PairResult {
                        peer: peer.peer.clone(),
                        outcome: result.as_ref().map(Clone::clone).map_err(|e| e.to_string()),
                    });
                }
                let outcome = result?;
                println!("[{peer_addr}] pairing with {peer_name}: {outcome:?}");
                if outcome == PairOutcome::TimedOut {
                    // A late answer may still be in flight; start afresh.
                    return Ok(());
                }
            }
            Ok(other) => {
                return reject(
                    stream,
                    ErrorCode::UnexpectedMessage,
                    format!("unexpected {other:?}"),
                )
                .await;
            }
            Err(ProtocolError::ConnectionClosed) => {
                println!("[{peer_addr}] {peer_name} disconnected");
                return Ok(());
            }
            Err(ProtocolError::Json(e)) => {
                return reject(stream, ErrorCode::BadMessage, e.to_string()).await;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Take one offered file: ask the user, stream it into a temp file, check the
/// hash, then move it into `download_dir`.
#[allow(clippy::too_many_arguments)]
async fn receive_file(
    stream: &mut Secure<'_>,
    download_dir: &Path,
    approval: &Approval,
    events: Option<&ReceiveEvents>,
    peer: &handshake::Handshake,
    audit: &AuditLog,
    peer_addr: SocketAddr,
    transfer_id: String,
    offered_name: &str,
    size: u64,
    stop: Option<oneshot::Receiver<()>>,
    folder: Option<Vec<FolderEntry>>,
) -> Result<(), BoxError> {
    let peer_name = peer.peer.name.as_str();
    let verified = peer.paired;
    let usable = match folder {
        Some(_) => folder_name(offered_name),
        None => sanitize_file_name(offered_name),
    };
    let Some(name) = usable else {
        return reject(
            stream,
            ErrorCode::FileRejected,
            format!("unusable file name {offered_name:?}"),
        )
        .await;
    };
    // Whoever approves a pushed file also gets a way to stop it midway; a
    // fetch we started already has one.
    let (cancel, stop) = match stop {
        Some(stop) => (None, Some(stop)),
        None => {
            let (cancel, stop) = oneshot::channel();
            (Some(cancel), Some(stop))
        }
    };
    let accepted = match approval {
        Approval::AcceptAll => true,
        Approval::Ask(requests) => {
            let (respond, decision) = oneshot::channel();
            let request = FileRequest {
                transfer_id: transfer_id.clone(),
                peer_name: peer_name.to_owned(),
                peer_addr,
                verified,
                name: name.clone(),
                size,
                respond,
                fetch: None,
                cancel,
                files: folder.as_ref().map(|f| f.len() as u64),
            };
            let accepted = requests.send(request).await.is_ok()
                && matches!(timeout(APPROVAL_TIMEOUT, decision).await, Ok(Ok(true)));
            audit.record(
                Entry::new(
                    if accepted {
                        Event::Approve
                    } else {
                        Event::Decline
                    },
                    Some(&peer.peer.id),
                    peer_name,
                )
                .file(&name)
                .detail("incoming file"),
            );
            accepted
        }
    };
    if !accepted {
        println!("[{peer_addr}] declined \"{name}\" from {peer_name}");
        write_message(stream, &Message::FileDecline { transfer_id }).await?;
        return Ok(());
    }
    let emit = |event| {
        if let Some(events) = events {
            let _ = events.send(event);
        }
    };
    emit(ReceiveEvent::Started {
        transfer_id: transfer_id.clone(),
        peer_name: peer_name.to_owned(),
        name: name.clone(),
        size,
    });
    let result = match folder {
        None => {
            save_file(
                stream,
                download_dir,
                &emit,
                peer_addr,
                &transfer_id,
                &name,
                size,
                stop,
            )
            .await
        }
        Some(entries) => {
            save_folder(
                stream,
                download_dir,
                &emit,
                peer_addr,
                &transfer_id,
                &name,
                &entries,
                stop,
            )
            .await
        }
    };
    emit(match &result {
        Ok((path, sha256)) => ReceiveEvent::Saved {
            transfer_id,
            path: path.clone(),
            sha256: sha256.clone(),
        },
        Err(e) if e.downcast_ref::<ReceiveCancelled>().is_some() => ReceiveEvent::Cancelled {
            transfer_id,
            by_peer: e
                .downcast_ref::<ReceiveCancelled>()
                .is_some_and(|c| c.by_peer),
        },
        Err(e) => ReceiveEvent::Failed {
            transfer_id,
            error: e.to_string(),
        },
    });
    result.map(|_| ())
}

/// The accepted half of [`receive_file`]: tell the sender to go ahead, then
/// stream, verify and save. Returns where the file was saved and its SHA-256.
/// Resolves when `stop` fires; never, if there's no stop or its sender
/// went away without firing.
async fn stop_signal(stop: &mut Option<oneshot::Receiver<()>>) {
    if let Some(rx) = stop
        && rx.await.is_ok()
    {
        return;
    }
    std::future::pending().await
}

#[allow(clippy::too_many_arguments)]
async fn save_file(
    stream: &mut Secure<'_>,
    download_dir: &Path,
    emit: &(impl Fn(ReceiveEvent) + Sync),
    peer_addr: SocketAddr,
    transfer_id: &str,
    name: &str,
    size: u64,
    stop: Option<oneshot::Receiver<()>>,
) -> Result<(PathBuf, String), BoxError> {
    let mut part = match PartFile::create(download_dir).await {
        Ok(part) => part,
        Err(e) => {
            return reject(
                stream,
                ErrorCode::StorageError,
                format!("cannot save files: {e}"),
            )
            .await;
        }
    };
    write_message(
        stream,
        &Message::FileAccept {
            transfer_id: transfer_id.to_owned(),
        },
    )
    .await?;
    println!("[{peer_addr}] receiving \"{name}\" ({size} bytes)");

    // The temp file is deleted if anything below fails. Stopping (our
    // user cancelled the fetch) hangs up on the sender mid-file.
    let mut on_progress = |received| {
        emit(ReceiveEvent::Progress {
            transfer_id: transfer_id.to_owned(),
            received,
        })
    };
    let mut stop = stop;
    let copied = tokio::select! {
        actual = copy_hashed(stream, part.file(), size, &mut on_progress) => Some(actual),
        () = stop_signal(&mut stop) => None,
    };
    let Some(actual) = copied else {
        println!("[{peer_addr}] stopped receiving \"{name}\": cancelled");
        part.discard().await;
        // Tell the sender, so it stops too instead of finding out from a
        // dropped connection.
        let cancel = Message::Cancel {
            transfer_id: transfer_id.to_owned(),
        };
        let _ = timeout(
            std::time::Duration::from_secs(1),
            write_message(stream, &cancel),
        )
        .await;
        return Err(ReceiveCancelled { by_peer: false }.into());
    };
    let actual = match actual {
        Ok(actual) => actual,
        Err(e) if is_peer_cancel(&e) => {
            println!("[{peer_addr}] \"{name}\" cancelled by the sender");
            part.discard().await;
            return Err(ReceiveCancelled { by_peer: true }.into());
        }
        Err(e) => return Err(e.into()),
    };
    let expected = match next_message(stream).await {
        Ok(Message::FileDone {
            transfer_id: id,
            sha256,
        }) if id == transfer_id => sha256,
        Ok(other) => {
            return reject(
                stream,
                ErrorCode::UnexpectedMessage,
                format!("expected file_done, got {other:?}"),
            )
            .await;
        }
        Err(e) => return Err(e.into()),
    };
    // A cancel that came in as the last bytes did still wins: don't keep a
    // file the user no longer wants.
    if stop.as_mut().is_some_and(|s| s.try_recv().is_ok()) {
        println!("[{peer_addr}] stopped receiving \"{name}\": cancelled");
        part.discard().await;
        return Err(ReceiveCancelled { by_peer: false }.into());
    }
    if !actual.eq_ignore_ascii_case(&expected) {
        return reject(
            stream,
            ErrorCode::ChecksumMismatch,
            format!("\"{name}\" arrived corrupted (SHA-256 {actual}, expected {expected})"),
        )
        .await;
    }
    let saved = match part.persist(download_dir, name).await {
        Ok(path) => path,
        Err(e) => {
            return reject(
                stream,
                ErrorCode::StorageError,
                format!("could not save \"{name}\": {e}"),
            )
            .await;
        }
    };
    println!("[{peer_addr}] saved {} (SHA-256 verified)", saved.display());
    write_message(
        stream,
        &Message::FileReceived {
            transfer_id: transfer_id.to_owned(),
            received_bytes: size,
        },
    )
    .await?;
    Ok((saved, actual))
}

/// Read a folder's listing (`files` entries in `folder_entries` messages)
/// and check it. The error says why it's refused.
async fn read_listing(
    stream: &mut Secure<'_>,
    transfer_id: &str,
    files: u64,
    size: u64,
) -> Result<Vec<FolderEntry>, String> {
    if files == 0 || files > MAX_FOLDER_FILES as u64 {
        return Err(format!("a folder must have 1 to {MAX_FOLDER_FILES} files"));
    }
    let mut entries = Vec::with_capacity(files as usize);
    while (entries.len() as u64) < files {
        match next_message(stream).await {
            Ok(Message::FolderEntries {
                transfer_id: id,
                entries: more,
            }) if id == transfer_id && !more.is_empty() => entries.extend(more),
            Ok(other) => return Err(format!("expected folder_entries, got {other:?}")),
            Err(e) => return Err(e.to_string()),
        }
        if entries.len() as u64 > files {
            return Err("more files than offered".into());
        }
    }
    check_listing(&entries)?;
    if entries.iter().map(|e| e.size).sum::<u64>() != size {
        return Err("the file sizes don't add up to the offered size".into());
    }
    Ok(entries)
}

/// [`save_file`] for a folder: each file in listing order (raw bytes, then
/// `file_done`), written into a hidden staging folder that's moved into
/// place once every file checks out. Returns the folder's path and
/// [`tree_hash`].
#[allow(clippy::too_many_arguments)]
async fn save_folder(
    stream: &mut Secure<'_>,
    download_dir: &Path,
    emit: &(impl Fn(ReceiveEvent) + Sync),
    peer_addr: SocketAddr,
    transfer_id: &str,
    name: &str,
    entries: &[FolderEntry],
    stop: Option<oneshot::Receiver<()>>,
) -> Result<(PathBuf, String), BoxError> {
    let paths = match check_listing(entries) {
        Ok(paths) => paths,
        Err(why) => return reject(stream, ErrorCode::FileRejected, why).await,
    };
    let staging = match Staging::create(download_dir).await {
        Ok(staging) => staging,
        Err(e) => {
            return reject(
                stream,
                ErrorCode::StorageError,
                format!("cannot save files: {e}"),
            )
            .await;
        }
    };
    write_message(
        stream,
        &Message::FileAccept {
            transfer_id: transfer_id.to_owned(),
        },
    )
    .await?;
    let total: u64 = entries.iter().map(|e| e.size).sum();
    println!(
        "[{peer_addr}] receiving folder \"{name}\" ({} files, {total} bytes)",
        entries.len()
    );
    let mut stop = stop;
    let receive_all = async {
        let mut hashes = Vec::with_capacity(entries.len());
        let mut before = 0u64;
        for (entry, relative) in entries.iter().zip(&paths) {
            let mut file = staging
                .create_file(relative)
                .await
                .map_err(|e| format!("could not save {}: {e}", entry.path))?;
            let mut on_progress = |received| {
                emit(ReceiveEvent::Progress {
                    transfer_id: transfer_id.to_owned(),
                    received: before + received,
                })
            };
            let actual = copy_hashed(stream, &mut file, entry.size, &mut on_progress).await;
            let actual = match actual {
                Ok(actual) => actual,
                Err(e) if is_peer_cancel(&e) => {
                    return Err::<Vec<String>, BoxError>(ReceiveCancelled { by_peer: true }.into());
                }
                Err(e) => return Err(e.into()),
            };
            file.sync_all().await?;
            let expected = match next_message(stream).await {
                Ok(Message::FileDone {
                    transfer_id: id,
                    sha256,
                }) if id == transfer_id => sha256,
                Ok(other) => return Err(format!("expected file_done, got {other:?}").into()),
                Err(e) if is_peer_cancel(&e) => {
                    return Err(ReceiveCancelled { by_peer: true }.into());
                }
                Err(e) => return Err(e.into()),
            };
            if !actual.eq_ignore_ascii_case(&expected) {
                return Err(format!(
                    "{} arrived corrupted (SHA-256 {actual}, expected {expected})",
                    entry.path
                )
                .into());
            }
            before += entry.size;
            hashes.push(actual);
        }
        Ok(hashes)
    };
    let received = tokio::select! {
        received = receive_all => Some(received),
        () = stop_signal(&mut stop) => None,
    };
    let hashes = match received {
        Some(Ok(hashes)) => hashes,
        None => {
            println!("[{peer_addr}] stopped receiving folder \"{name}\": cancelled");
            drop(staging);
            let cancel = Message::Cancel {
                transfer_id: transfer_id.to_owned(),
            };
            let _ = timeout(
                std::time::Duration::from_secs(1),
                write_message(stream, &cancel),
            )
            .await;
            return Err(ReceiveCancelled { by_peer: false }.into());
        }
        Some(Err(e)) => {
            drop(staging);
            if let Some(cancelled) = e.downcast_ref::<ReceiveCancelled>() {
                println!("[{peer_addr}] folder \"{name}\" cancelled by the sender");
                return Err((*cancelled).into());
            }
            return reject(stream, ErrorCode::FileRejected, e.to_string()).await;
        }
    };
    if stop.as_mut().is_some_and(|s| s.try_recv().is_ok()) {
        return Err(ReceiveCancelled { by_peer: false }.into());
    }
    let saved = match staging.persist(download_dir, name).await {
        Ok(path) => path,
        Err(e) => {
            return reject(
                stream,
                ErrorCode::StorageError,
                format!("could not save folder \"{name}\": {e}"),
            )
            .await;
        }
    };
    let sha256 = tree_hash(
        entries
            .iter()
            .zip(&hashes)
            .map(|(e, h)| (e.path.as_str(), h.as_str())),
    );
    println!(
        "[{peer_addr}] saved folder {} ({} files, every SHA-256 verified)",
        saved.display(),
        entries.len()
    );
    write_message(
        stream,
        &Message::FileReceived {
            transfer_id: transfer_id.to_owned(),
            received_bytes: total,
        },
    )
    .await?;
    Ok((saved, sha256))
}

async fn next_message(stream: &mut Secure<'_>) -> Result<Message, ProtocolError> {
    timeout(IO_TIMEOUT, read_message(stream))
        .await
        .unwrap_or_else(|_| {
            Err(ProtocolError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "peer went quiet",
            )))
        })
}

/// Tell the peer why we're hanging up, then hang up.
async fn reject<T>(
    stream: &mut Secure<'_>,
    code: ErrorCode,
    message: String,
) -> Result<T, BoxError> {
    let _ = write_message(
        stream,
        &Message::Error {
            code,
            message: message.clone(),
        },
    )
    .await;
    Err(message.into())
}

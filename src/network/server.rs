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
use super::fetch::PendingFetches;
use super::{APPROVAL_TIMEOUT, BoxError, DeviceIdentity, IO_TIMEOUT, handshake};
use crate::daemon::{Direction, Status, Transfer, TransferTable};
use crate::pairing::store::PairedDevices;
use crate::pairing::{self, PairOutcome, PairPrompts, PairResult, PairResults};
use crate::protocol::{
    ErrorCode, FetchDeclineReason, Message, ProtocolError, read_message, share_list_within_frame,
    write_message,
};
use crate::share::{ShareError, Shares};
use crate::transfer::{PartFile, copy_hashed, sanitize_file_name};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
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
    /// Already sanitized: this is the name it will be saved under (or close
    /// to it, if a file with that name exists).
    pub name: String,
    pub size: u64,
    pub respond: oneshot::Sender<bool>,
    /// Set when the peer asks to fetch one of our shared files rather than
    /// offering us one: approving sends the file to them.
    pub fetch: Option<FetchInfo>,
}

/// What a fetch request adds to a [`FileRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchInfo {
    pub peer_id: String,
    /// The requester's stated reason, to show the user.
    pub reason: String,
    /// The requester says an AI assistant asked for the file.
    pub via_assistant: bool,
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
}

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
            if let Err(e) = handle_connection(&mut stream, peer_addr, &options).await {
                eprintln!("[{peer_addr}] connection ended with error: {e}");
                close_after_error(stream).await;
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
    stream: &mut TcpStream,
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
    if !(peer.paired || options.allow_unpaired_fetch) {
        println!("[{peer_addr}] refused a fetch from unpaired \"{peer_name}\"");
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
        write_message(stream, &decline(FetchDeclineReason::NotShared)).await?;
        return Ok(());
    };
    let file = resolved.file.clone();
    // Sending a file away always takes an explicit yes: auto-accept is
    // about files coming in, so it doesn't approve fetches.
    let answer = match &options.approval {
        Approval::AcceptAll => Err(FetchDeclineReason::Declined),
        Approval::Ask(requests) => {
            let (respond, decision) = oneshot::channel();
            let ask = FileRequest {
                transfer_id: fetch_id.clone(),
                peer_name: peer_name.clone(),
                peer_addr,
                name: file.name.clone(),
                size: file.size,
                respond,
                fetch: Some(FetchInfo {
                    peer_id: peer.peer.id.clone(),
                    reason: request.reason.clone(),
                    via_assistant: request.via_assistant,
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
        write_message(stream, &decline(reason)).await?;
        return Ok(());
    }
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
    ));
    Ok(())
}

/// Send an approved fetch back to the requester's listener, making sure it
/// is the same device that asked.
async fn push_fetched(
    identity: DeviceIdentity,
    paired: Arc<PairedDevices>,
    requester_id: String,
    reply_to: SocketAddr,
    path: PathBuf,
    fetch_id: String,
    table: Option<Arc<TransferTable>>,
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
    match result {
        Ok(FileResult::Delivered(outcome)) => {
            println!("[{reply_to}] sent fetched \"{}\"", outcome.name);
            record(&|t| {
                t.bytes = outcome.size;
                t.sha256 = Some(outcome.sha256.clone());
                t.status = Status::Done;
            })
        }
        Ok(FileResult::Declined) => record(&|t| t.status = Status::Declined),
        Err(e) => {
            eprintln!("[{reply_to}] could not send fetched file: {e}");
            record(&|t| {
                t.status = Status::Failed;
                t.error = Some(e.to_string());
            })
        }
    }
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
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    options: &Options,
) -> Result<(), BoxError> {
    let download_dir = options.download_dir.as_path();
    let approval = &options.approval;
    let events = options.events.as_ref();
    let peer = handshake::accept(stream, &options.identity, &options.paired).await?;
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
                    &peer_name,
                    peer_addr,
                    transfer_id,
                    &name,
                    size,
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
                let claimed = options
                    .fetches
                    .claim(&fetch_id, &peer.peer.id, size, &transfer_id);
                receive_file(
                    stream,
                    download_dir,
                    if claimed {
                        &Approval::AcceptAll
                    } else {
                        approval
                    },
                    events,
                    &peer_name,
                    peer_addr,
                    transfer_id,
                    &name,
                    size,
                )
                .await?;
            }
            Ok(Message::ShareListRequest { query }) => {
                if !(peer.paired || options.allow_unpaired_fetch) {
                    return reject(
                        stream,
                        ErrorCode::NotPaired,
                        "only paired devices can see shared files".into(),
                    )
                    .await;
                }
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
    stream: &mut TcpStream,
    download_dir: &Path,
    approval: &Approval,
    events: Option<&ReceiveEvents>,
    peer_name: &str,
    peer_addr: SocketAddr,
    transfer_id: String,
    offered_name: &str,
    size: u64,
) -> Result<(), BoxError> {
    let Some(name) = sanitize_file_name(offered_name) else {
        return reject(
            stream,
            ErrorCode::FileRejected,
            format!("unusable file name {offered_name:?}"),
        )
        .await;
    };
    let accepted = match approval {
        Approval::AcceptAll => true,
        Approval::Ask(requests) => {
            let (respond, decision) = oneshot::channel();
            let request = FileRequest {
                transfer_id: transfer_id.clone(),
                peer_name: peer_name.to_owned(),
                peer_addr,
                name: name.clone(),
                size,
                respond,
                fetch: None,
            };
            requests.send(request).await.is_ok()
                && matches!(timeout(APPROVAL_TIMEOUT, decision).await, Ok(Ok(true)))
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
    let result = save_file(
        stream,
        download_dir,
        &emit,
        peer_addr,
        &transfer_id,
        &name,
        size,
    )
    .await;
    emit(match &result {
        Ok((path, sha256)) => ReceiveEvent::Saved {
            transfer_id,
            path: path.clone(),
            sha256: sha256.clone(),
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
async fn save_file(
    stream: &mut TcpStream,
    download_dir: &Path,
    emit: &(impl Fn(ReceiveEvent) + Sync),
    peer_addr: SocketAddr,
    transfer_id: &str,
    name: &str,
    size: u64,
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

    // The temp file is deleted if anything below fails.
    let actual = copy_hashed(stream, part.file(), size, &mut |received| {
        emit(ReceiveEvent::Progress {
            transfer_id: transfer_id.to_owned(),
            received,
        })
    })
    .await?;
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

async fn next_message(stream: &mut TcpStream) -> Result<Message, ProtocolError> {
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
    stream: &mut TcpStream,
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

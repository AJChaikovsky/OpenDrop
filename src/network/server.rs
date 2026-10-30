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

use super::{APPROVAL_TIMEOUT, BoxError, DeviceIdentity, IO_TIMEOUT, handshake};
use crate::pairing::store::PairedDevices;
use crate::pairing::{self, PairOutcome, PairPrompts};
use crate::protocol::{ErrorCode, Message, ProtocolError, read_message, write_message};
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
        let (stream, peer_addr) = listener.accept().await?;
        let options = Arc::clone(&options);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer_addr, &options).await {
                eprintln!("[{peer_addr}] connection ended with error: {e}");
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    options: &Options,
) -> Result<(), BoxError> {
    let download_dir = options.download_dir.as_path();
    let approval = &options.approval;
    let events = options.events.as_ref();
    let peer = handshake::accept(&mut stream, &options.identity, &options.paired).await?;
    let peer_name = peer.peer.name.clone();
    println!(
        "[{peer_addr}] connected: \"{peer_name}\" ({}){}",
        peer.peer.id,
        if peer.paired { ", paired" } else { "" }
    );

    loop {
        match next_message(&mut stream).await {
            Ok(Message::Text { body }) => {
                println!("[{peer_addr}] {peer_name}: {body}");
                write_message(
                    &mut stream,
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
                    &mut stream,
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
            Ok(Message::PairRequest { commitment }) => {
                let outcome = pairing::respond(
                    &mut stream,
                    &options.identity,
                    &peer.peer,
                    peer.nonces,
                    commitment,
                    options.pair_prompts.as_ref(),
                    &options.paired,
                )
                .await?;
                println!("[{peer_addr}] pairing with {peer_name}: {outcome:?}");
                if outcome == PairOutcome::TimedOut {
                    // A late answer may still be in flight; start afresh.
                    return Ok(());
                }
            }
            Ok(other) => {
                return reject(
                    &mut stream,
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
                return reject(&mut stream, ErrorCode::BadMessage, e.to_string()).await;
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

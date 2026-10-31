//! Connects to another device and talks to it.

use super::{APPROVAL_TIMEOUT, BoxError, DeviceIdentity, IO_TIMEOUT, PeerIdentity, handshake};
use crate::pairing::store::PairedDevices;
use crate::pairing::{self, PairOutcome, PairPrompts};
use crate::protocol::{FetchDeclineReason, Message, SharedFile, read_message, write_message};
use crate::transfer::{copy_hashed, sanitize_file_name};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Result of a successful `send_text`.
#[derive(Debug)]
pub struct SendOutcome {
    pub peer: PeerIdentity,
    pub received_bytes: usize,
}

/// Result of a successful `Connection::send_file`.
#[derive(Debug)]
pub struct FileOutcome {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

/// What became of an offered file.
#[derive(Debug)]
pub enum FileResult {
    /// The receiver accepted it and confirmed it arrived intact.
    Delivered(FileOutcome),
    /// The receiver said no (or didn't answer in time). Nothing was sent, and
    /// the connection is still usable.
    Declined,
}

/// An open, introduced connection to a peer. Several texts and files can be
/// sent over one connection.
pub struct Connection {
    stream: TcpStream,
    pub peer: PeerIdentity,
    /// Whether we and the peer are paired (checked during the handshake).
    pub paired: bool,
    /// Handshake nonces, `(client, server)`, which pairing builds on.
    nonces: ([u8; 32], [u8; 32]),
}

impl Connection {
    /// Connect to `addr` (e.g. `"192.168.1.20:45454"`) and introduce
    /// ourselves, treating no device as paired.
    pub async fn open(addr: &str, identity: &DeviceIdentity) -> Result<Self, BoxError> {
        Self::open_with(addr, identity, &PairedDevices::in_memory()).await
    }

    /// Connect to `addr`, run the signed handshake, and check the peer
    /// against our paired devices.
    pub async fn open_with(
        addr: &str,
        identity: &DeviceIdentity,
        paired: &PairedDevices,
    ) -> Result<Self, BoxError> {
        let mut stream = timeout(IO_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| format!("timed out connecting to {addr}"))?
            .map_err(|e| format!("could not connect to {addr}: {e}"))?;
        let done = handshake::connect(&mut stream, identity, paired).await?;
        Ok(Self {
            stream,
            peer: done.peer,
            paired: done.paired,
            nonces: done.nonces,
        })
    }

    /// Ask the peer to pair: both users see the same 6-digit code (ours on
    /// `prompts`) and must both accept. On success the peer is stored in
    /// `paired`. A timed-out attempt leaves the connection unusable.
    pub async fn pair(
        &mut self,
        identity: &DeviceIdentity,
        prompts: &PairPrompts,
        paired: &PairedDevices,
    ) -> Result<PairOutcome, BoxError> {
        let outcome = pairing::initiate(
            &mut self.stream,
            identity,
            &self.peer,
            self.nonces,
            prompts,
            paired,
        )
        .await?;
        if outcome == PairOutcome::Paired {
            self.paired = true;
        }
        Ok(outcome)
    }

    /// Send a text message and wait for the acknowledgement.
    pub async fn send_text(&mut self, body: &str) -> Result<usize, BoxError> {
        write_message(
            &mut self.stream,
            &Message::Text {
                body: body.to_owned(),
            },
        )
        .await?;
        match recv(&mut self.stream).await? {
            Message::TextAck { received_bytes } => Ok(received_bytes),
            other => Err(unexpected(other)),
        }
    }

    /// Offer the file at `path`, stream it if the receiver accepts, and wait
    /// for it to confirm the file arrived intact. `progress` gets bytes sent
    /// so far.
    pub async fn send_file(
        &mut self,
        path: &Path,
        progress: &mut (dyn FnMut(u64) + Send),
    ) -> Result<FileResult, BoxError> {
        self.offer(path, None, progress).await
    }

    /// [`Connection::send_file`] in answer to the peer's fetch `fetch_id`
    /// (a `fetch_offer`, which the peer takes without asking its user).
    pub async fn send_fetched(
        &mut self,
        path: &Path,
        fetch_id: &str,
        progress: &mut (dyn FnMut(u64) + Send),
    ) -> Result<FileResult, BoxError> {
        self.offer(path, Some(fetch_id), progress).await
    }

    /// The files the peer shares with us (if we're paired), and whether the
    /// list was cut short.
    pub async fn list_shares(
        &mut self,
        query: Option<&str>,
    ) -> Result<(Vec<SharedFile>, bool), BoxError> {
        write_message(
            &mut self.stream,
            &Message::ShareListRequest {
                query: query.map(str::to_owned),
            },
        )
        .await?;
        match recv(&mut self.stream).await? {
            Message::ShareList { files, truncated } => Ok((files, truncated)),
            other => Err(unexpected(other)),
        }
    }

    /// Ask the peer for shared file `file_id`. Waits while its user decides;
    /// on `Ok(Ok(()))` the file is on its way to our listener on
    /// `reply_port` as a `fetch_offer` with this `fetch_id`.
    pub async fn request_fetch(
        &mut self,
        fetch_id: &str,
        file_id: &str,
        reason: &str,
        via_assistant: bool,
        reply_port: u16,
    ) -> Result<Result<(), FetchDeclineReason>, BoxError> {
        write_message(
            &mut self.stream,
            &Message::FetchRequest {
                fetch_id: fetch_id.to_owned(),
                file_id: file_id.to_owned(),
                reason: reason.to_owned(),
                via_assistant,
                reply_port,
            },
        )
        .await?;
        match recv_within(&mut self.stream, APPROVAL_TIMEOUT + IO_TIMEOUT).await? {
            Message::FetchAccepted { fetch_id: id } if id == fetch_id => Ok(Ok(())),
            Message::FetchDeclined {
                fetch_id: id,
                reason,
            } if id == fetch_id => Ok(Err(reason)),
            other => Err(unexpected(other)),
        }
    }

    async fn offer(
        &mut self,
        path: &Path,
        fetch_id: Option<&str>,
        progress: &mut (dyn FnMut(u64) + Send),
    ) -> Result<FileResult, BoxError> {
        let mut file = tokio::fs::File::open(path)
            .await
            .map_err(|e| format!("could not open {}: {e}", path.display()))?;
        let metadata = file.metadata().await?;
        if !metadata.is_file() {
            return Err(format!("{} is not a file", path.display()).into());
        }
        let size = metadata.len();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(sanitize_file_name)
            .ok_or_else(|| format!("{} has no usable file name", path.display()))?;
        let transfer_id = new_transfer_id();

        let offer = match fetch_id {
            None => Message::FileOffer {
                transfer_id: transfer_id.clone(),
                name: name.clone(),
                size,
            },
            Some(fetch_id) => Message::FetchOffer {
                transfer_id: transfer_id.clone(),
                name: name.clone(),
                size,
                fetch_id: fetch_id.to_owned(),
            },
        };
        write_message(&mut self.stream, &offer).await?;
        // The receiver may be asking its user, so allow for that on top of
        // the usual network delay.
        match recv_within(&mut self.stream, APPROVAL_TIMEOUT + IO_TIMEOUT).await? {
            Message::FileAccept { transfer_id: id } if id == transfer_id => {}
            Message::FileDecline { transfer_id: id } if id == transfer_id => {
                return Ok(FileResult::Declined);
            }
            other => return Err(unexpected(other)),
        }

        let sha256 = match copy_hashed(&mut file, &mut self.stream, size, progress).await {
            Ok(hash) => hash,
            // If the peer hung up mid-transfer it probably said why first.
            Err(e) => {
                return Err(match recv(&mut self.stream).await {
                    Ok(reply) => unexpected(reply),
                    Err(_) => format!("transfer interrupted: {e}").into(),
                });
            }
        };
        write_message(
            &mut self.stream,
            &Message::FileDone {
                transfer_id: transfer_id.clone(),
                sha256: sha256.clone(),
            },
        )
        .await?;
        match recv(&mut self.stream).await? {
            Message::FileReceived {
                transfer_id: id,
                received_bytes,
            } if id == transfer_id && received_bytes == size => {
                Ok(FileResult::Delivered(FileOutcome { name, size, sha256 }))
            }
            other => Err(unexpected(other)),
        }
    }
}

/// Connect to `addr`, introduce ourselves, send `body`, and wait for the
/// acknowledgement.
pub async fn send_text(
    addr: &str,
    identity: &DeviceIdentity,
    body: &str,
) -> Result<SendOutcome, BoxError> {
    let mut connection = Connection::open(addr, identity).await?;
    let received_bytes = connection.send_text(body).await?;
    Ok(SendOutcome {
        peer: connection.peer,
        received_bytes,
    })
}

async fn recv(stream: &mut TcpStream) -> Result<Message, BoxError> {
    recv_within(stream, IO_TIMEOUT).await
}

async fn recv_within(stream: &mut TcpStream, limit: Duration) -> Result<Message, BoxError> {
    Ok(timeout(limit, read_message(stream))
        .await
        .map_err(|_| "timed out waiting for peer")??)
}

fn unexpected(message: Message) -> BoxError {
    match message {
        Message::Error { code, message } => format!("peer refused ({code:?}): {message}").into(),
        other => format!("unexpected reply from peer: {other:?}").into(),
    }
}

fn new_transfer_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("transfer-{:012x}", nanos & 0xffff_ffff_ffff)
}

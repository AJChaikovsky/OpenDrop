//! Listens for incoming connections and answers them.
//!
//! Connection lifecycle (Task 1):
//!
//! ```text
//! client                     server
//!   | --- hello ------------> |
//!   | <-------------- welcome |
//!   | --- text -------------> |   (repeatable)
//!   | <------------- text_ack |
//!   |                         |
//!   | --- file_offer -------> |   (repeatable; Task 3)
//!   | <---------- file_accept |
//!   | === raw bytes ========> |   exactly `size` bytes, unframed
//!   | --- file_done --------> |   SHA-256 of those bytes
//!   | <-------- file_received |   after the hash matched and the file was saved
//!   | --- [close] ----------> |
//! ```
//!
//! Files are accepted automatically for now and saved to the download folder;
//! asking the user first comes with the desktop app.

use super::{BoxError, DeviceIdentity, IO_TIMEOUT};
use crate::protocol::{ErrorCode, Message, ProtocolError, read_message, write_message};
use crate::transfer::{PartFile, copy_hashed, sanitize_file_name};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// Accept connections forever, handling each on its own task. Received files
/// are saved in `download_dir`, which is created when the first file arrives.
pub async fn run(
    listener: TcpListener,
    identity: DeviceIdentity,
    download_dir: PathBuf,
) -> std::io::Result<()> {
    let download_dir = Arc::new(download_dir);
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let identity = identity.clone();
        let download_dir = Arc::clone(&download_dir);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer_addr, &identity, &download_dir).await {
                eprintln!("[{peer_addr}] connection ended with error: {e}");
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    identity: &DeviceIdentity,
    download_dir: &Path,
) -> Result<(), BoxError> {
    // Handshake: the first message must be `hello`.
    let peer_name = match next_message(&mut stream).await {
        Ok(Message::Hello {
            device_id,
            device_name,
        }) => {
            println!("[{peer_addr}] connected: \"{device_name}\" ({device_id})");
            write_message(
                &mut stream,
                &Message::Welcome {
                    device_id: identity.id.clone(),
                    device_name: identity.name.clone(),
                },
            )
            .await?;
            device_name
        }
        Ok(other) => {
            return reject(
                &mut stream,
                ErrorCode::UnexpectedMessage,
                format!("expected hello, got {other:?}"),
            )
            .await;
        }
        Err(ProtocolError::UnsupportedVersion(v)) => {
            return reject(
                &mut stream,
                ErrorCode::UnsupportedVersion,
                format!("version {v} not supported"),
            )
            .await;
        }
        Err(e) => return Err(e.into()),
    };

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
                    &peer_name,
                    peer_addr,
                    transfer_id,
                    &name,
                    size,
                )
                .await?;
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

/// Take one offered file: accept it, stream it into a temp file, check the
/// hash, then move it into `download_dir`.
async fn receive_file(
    stream: &mut TcpStream,
    download_dir: &Path,
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
            transfer_id: transfer_id.clone(),
        },
    )
    .await?;
    println!("[{peer_addr}] receiving \"{name}\" ({size} bytes) from {peer_name}");

    // The temp file is deleted if anything below fails.
    let actual = copy_hashed(stream, part.file(), size, &mut |_| {}).await?;
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
    let saved = match part.persist(download_dir, &name).await {
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
            transfer_id,
            received_bytes: size,
        },
    )
    .await?;
    Ok(())
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
async fn reject(stream: &mut TcpStream, code: ErrorCode, message: String) -> Result<(), BoxError> {
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

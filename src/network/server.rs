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
//!   | --- [close] ----------> |
//! ```

use super::{BoxError, DeviceIdentity, IO_TIMEOUT};
use crate::protocol::{ErrorCode, Message, ProtocolError, read_message, write_message};
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// Accept connections forever, handling each on its own task.
pub async fn run(listener: TcpListener, identity: DeviceIdentity) -> std::io::Result<()> {
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let identity = identity.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer_addr, &identity).await {
                eprintln!("[{peer_addr}] connection ended with error: {e}");
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    identity: &DeviceIdentity,
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

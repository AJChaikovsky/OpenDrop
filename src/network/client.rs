//! Connects to another device and talks to it.

use super::{BoxError, DeviceIdentity, IO_TIMEOUT};
use crate::protocol::{Message, read_message, write_message};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Result of a successful `send_text`.
#[derive(Debug)]
pub struct SendOutcome {
    pub peer: DeviceIdentity,
    pub received_bytes: usize,
}

/// Connect to `addr` (e.g. `"192.168.1.20:45454"`), introduce ourselves,
/// send `body`, and wait for the acknowledgement.
pub async fn send_text(
    addr: &str,
    identity: &DeviceIdentity,
    body: &str,
) -> Result<SendOutcome, BoxError> {
    let mut stream = timeout(IO_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| format!("timed out connecting to {addr}"))?
        .map_err(|e| format!("could not connect to {addr}: {e}"))?;

    write_message(
        &mut stream,
        &Message::Hello {
            device_id: identity.id.clone(),
            device_name: identity.name.clone(),
        },
    )
    .await?;
    let peer = match recv(&mut stream).await? {
        Message::Welcome {
            device_id,
            device_name,
        } => DeviceIdentity {
            id: device_id,
            name: device_name,
        },
        other => return Err(unexpected(other)),
    };

    write_message(
        &mut stream,
        &Message::Text {
            body: body.to_owned(),
        },
    )
    .await?;
    let received_bytes = match recv(&mut stream).await? {
        Message::TextAck { received_bytes } => received_bytes,
        other => return Err(unexpected(other)),
    };

    Ok(SendOutcome {
        peer,
        received_bytes,
    })
}

async fn recv(stream: &mut TcpStream) -> Result<Message, BoxError> {
    Ok(timeout(IO_TIMEOUT, read_message(stream))
        .await
        .map_err(|_| "timed out waiting for peer")??)
}

fn unexpected(message: Message) -> BoxError {
    match message {
        Message::Error { code, message } => format!("peer refused ({code:?}): {message}").into(),
        other => format!("unexpected reply from peer: {other:?}").into(),
    }
}

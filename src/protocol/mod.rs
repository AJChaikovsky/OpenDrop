//! The OpenDrop wire protocol.
//!
//! Every control message is a JSON object sent as one *frame*:
//!
//! ```text
//! +----------------------+---------------------------+
//! | length: u32 (big-end)| payload: `length` bytes   |
//! +----------------------+---------------------------+
//! ```
//!
//! The payload is UTF-8 JSON carrying a `version` and a `type` field, e.g.
//! `{"version":1,"type":"text","body":"hi"}`. Framing means we never assume one
//! TCP read equals one message, and it lets raw file bytes travel between
//! control frames: after a `file_accept`, the sender writes exactly the offered
//! number of bytes, unframed, then resumes with a `file_done` frame.

use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Protocol version this build speaks.
pub const PROTOCOL_VERSION: u32 = 1;

/// Largest control frame we accept. Control messages are small; anything
/// bigger is a bug or a hostile peer, so we refuse it before allocating.
pub const MAX_FRAME_LEN: u32 = 64 * 1024;

/// A control message. Serialized with a `type` tag in snake_case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    /// First message a client sends after connecting.
    Hello {
        device_id: String,
        device_name: String,
    },
    /// Server's reply to `Hello`, identifying itself.
    Welcome {
        device_id: String,
        device_name: String,
    },
    /// A plain text message (Task 1 milestone; later reused for clipboard sharing).
    Text { body: String },
    /// Acknowledges a `Text` message.
    TextAck { received_bytes: usize },
    /// Client proposes sending a file. `name` is a bare file name, never a path.
    FileOffer {
        transfer_id: String,
        name: String,
        size: u64,
    },
    /// Receiver agrees; the client then sends exactly `size` raw bytes.
    FileAccept { transfer_id: String },
    /// Sent right after the raw bytes, with their SHA-256 in lowercase hex.
    FileDone { transfer_id: String, sha256: String },
    /// Receiver checked the hash and saved the file.
    FileReceived {
        transfer_id: String,
        received_bytes: u64,
    },
    /// Something went wrong; the sender closes the connection afterwards.
    Error { code: ErrorCode, message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    UnsupportedVersion,
    UnexpectedMessage,
    BadMessage,
    /// The receiver won't take this file (e.g. its name is unusable).
    FileRejected,
    /// The received bytes don't match the sender's SHA-256.
    ChecksumMismatch,
    /// The receiver couldn't write the file to disk.
    StorageError,
}

/// What actually goes on the wire: the message plus the protocol version.
#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    version: u32,
    #[serde(flatten)]
    message: Message,
}

#[derive(Debug)]
pub enum ProtocolError {
    Io(io::Error),
    /// Peer closed the connection cleanly between frames.
    ConnectionClosed,
    FrameTooLarge(u32),
    Json(serde_json::Error),
    UnsupportedVersion(u32),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::ConnectionClosed => write!(f, "connection closed by peer"),
            Self::FrameTooLarge(n) => {
                write!(f, "frame of {n} bytes exceeds limit of {MAX_FRAME_LEN}")
            }
            Self::Json(e) => write!(f, "malformed message: {e}"),
            Self::UnsupportedVersion(v) => write!(
                f,
                "peer speaks protocol version {v}, we speak {PROTOCOL_VERSION}"
            ),
        }
    }
}

impl std::error::Error for ProtocolError {}

impl From<io::Error> for ProtocolError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Encode `message` into a single frame (length prefix + JSON).
pub fn encode(message: &Message) -> Result<Vec<u8>, ProtocolError> {
    let envelope = Envelope {
        version: PROTOCOL_VERSION,
        message: message.clone(),
    };
    let payload = serde_json::to_vec(&envelope).map_err(ProtocolError::Json)?;
    let len = u32::try_from(payload.len())
        .ok()
        .filter(|&n| n <= MAX_FRAME_LEN)
        .ok_or(ProtocolError::FrameTooLarge(payload.len() as u32))?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Write one framed message.
pub async fn write_message<W>(writer: &mut W, message: &Message) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&encode(message)?).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one framed message. Returns `ConnectionClosed` if the peer hung up
/// before sending any bytes of a new frame.
pub async fn read_message<R>(reader: &mut R) -> Result<Message, ProtocolError>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(ProtocolError::ConnectionClosed);
        }
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(ProtocolError::FrameTooLarge(len));
    }
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;

    // Check the version before interpreting the rest, so a future v2 peer
    // gets a clear "unsupported version" instead of a confusing parse error.
    #[derive(Deserialize)]
    struct VersionOnly {
        version: u32,
    }
    let VersionOnly { version } = serde_json::from_slice(&payload).map_err(ProtocolError::Json)?;
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(version));
    }
    let envelope: Envelope = serde_json::from_slice(&payload).map_err(ProtocolError::Json)?;
    Ok(envelope.message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trips_messages() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let msgs = [
            Message::Hello {
                device_id: "a1".into(),
                device_name: "Mac".into(),
            },
            Message::Text {
                body: "héllo 👋".into(),
            },
            Message::TextAck { received_bytes: 11 },
            Message::FileOffer {
                transfer_id: "t1".into(),
                name: "photo.jpg".into(),
                size: 5_000_000_000,
            },
            Message::FileDone {
                transfer_id: "t1".into(),
                sha256: "ab".repeat(32),
            },
        ];
        for m in &msgs {
            write_message(&mut a, m).await.unwrap();
        }
        for m in &msgs {
            assert_eq!(&read_message(&mut b).await.unwrap(), m);
        }
    }

    #[test]
    fn wire_format_is_versioned_snake_case_json() {
        let frame = encode(&Message::Text { body: "hi".into() }).unwrap();
        let len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(len, frame.len() - 4);
        let json: serde_json::Value = serde_json::from_slice(&frame[4..]).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"version": 1, "type": "text", "body": "hi"})
        );
    }

    #[tokio::test]
    async fn handles_frames_split_across_reads() {
        let frame = encode(&Message::Text {
            body: "split".into(),
        })
        .unwrap();
        let (mut a, mut b) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            for byte in frame {
                a.write_all(&[byte]).await.unwrap();
                a.flush().await.unwrap();
            }
        });
        assert_eq!(
            read_message(&mut b).await.unwrap(),
            Message::Text {
                body: "split".into()
            }
        );
    }

    #[tokio::test]
    async fn rejects_oversized_frame_without_allocating() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&(MAX_FRAME_LEN + 1).to_be_bytes())
            .await
            .unwrap();
        assert!(matches!(
            read_message(&mut b).await,
            Err(ProtocolError::FrameTooLarge(_))
        ));
    }

    #[tokio::test]
    async fn rejects_other_protocol_versions() {
        let payload = br#"{"version":2,"type":"text","body":"from the future"}"#;
        let (mut a, mut b) = tokio::io::duplex(1024);
        a.write_all(&(payload.len() as u32).to_be_bytes())
            .await
            .unwrap();
        a.write_all(payload).await.unwrap();
        assert!(matches!(
            read_message(&mut b).await,
            Err(ProtocolError::UnsupportedVersion(2))
        ));
    }

    #[tokio::test]
    async fn clean_close_is_reported() {
        let (a, mut b) = tokio::io::duplex(64);
        drop(a);
        assert!(matches!(
            read_message(&mut b).await,
            Err(ProtocolError::ConnectionClosed)
        ));
    }
}

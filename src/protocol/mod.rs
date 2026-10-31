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
//! `{"version":2,"type":"text","body":"hi"}`. Framing means we never assume one
//! TCP read equals one message, and it lets raw file bytes travel between
//! control frames: after a `file_accept`, the sender writes exactly the offered
//! number of bytes, unframed, then resumes with a `file_done` frame.

use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Protocol version this build speaks. Version 2 added key-backed identity
/// (signed handshake) and pairing.
pub const PROTOCOL_VERSION: u32 = 2;

/// Largest control frame we accept. Control messages are small; anything
/// bigger is a bug or a hostile peer, so we refuse it before allocating.
pub const MAX_FRAME_LEN: u32 = 64 * 1024;

/// A control message. Serialized with a `type` tag in snake_case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    /// First message a client sends after connecting. `nonce` is fresh for
    /// this connection; the server proves its key by signing it.
    Hello {
        device_id: String,
        device_name: String,
        #[serde(with = "hex_array")]
        public_key: [u8; 32],
        #[serde(with = "hex_array")]
        nonce: [u8; 32],
    },
    /// Server's reply to `Hello`, identifying itself. `signature` covers
    /// both nonces and both keys (see `network::handshake`); `paired` says
    /// whether the server has the client's key as a paired device.
    Welcome {
        device_id: String,
        device_name: String,
        #[serde(with = "hex_array")]
        public_key: [u8; 32],
        #[serde(with = "hex_array")]
        nonce: [u8; 32],
        paired: bool,
        #[serde(with = "hex_array")]
        signature: [u8; 64],
    },
    /// The client's half of the proof: its signature over the same
    /// transcript, including the server's fresh nonce.
    HelloProof {
        paired: bool,
        #[serde(with = "hex_array")]
        signature: [u8; 64],
    },
    /// The server checked the client's proof; the connection is ready.
    Ready,
    /// Client asks to pair. `commitment` is the SHA-256 of the client's
    /// pairing nonce, which it reveals only after seeing the server's, so
    /// neither side can pick its nonce to steer the verification code.
    PairRequest {
        #[serde(with = "hex_array")]
        commitment: [u8; 32],
    },
    /// Server's pairing nonce, sent after the commitment.
    PairNonce {
        #[serde(with = "hex_array")]
        nonce: [u8; 32],
    },
    /// Client reveals the nonce it committed to. Both sides now show the
    /// 6-digit code and ask their user to compare it.
    PairReveal {
        #[serde(with = "hex_array")]
        nonce: [u8; 32],
    },
    /// This side's user confirmed the code. Either side sends it.
    PairAccept,
    /// This side's user rejected the code or cancelled; with `timed_out`,
    /// nobody answered in time.
    PairDecline {
        #[serde(default)]
        timed_out: bool,
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
    /// Receiver (or its user) said no. The connection stays open, so the
    /// client can go on to its next file.
    FileDecline { transfer_id: String },
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
    /// The peer's key doesn't match the device id it claims, its proof of
    /// owning that key is wrong or stale, or it uses a different key than
    /// the one we paired with.
    IdentityMismatch,
    /// The pairing commitment didn't match the revealed nonce.
    PairingFailed,
}

/// Serde for fixed-size byte arrays as lowercase hex strings.
pub(crate) mod hex_array {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer, const N: usize>(
        bytes: &[u8; N],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&crate::transfer::hex(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<[u8; N], D::Error> {
        let text = <&str>::deserialize(deserializer)?;
        let mut out = [0u8; N];
        if text.len() != N * 2 || !text.is_ascii() {
            return Err(D::Error::custom(format!("expected {} hex digits", N * 2)));
        }
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
                .map_err(|_| D::Error::custom("invalid hex digit"))?;
        }
        Ok(out)
    }
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

/// Write one frame holding `payload` as is. The control API uses this for
/// its own message set.
pub async fn write_frame<W>(writer: &mut W, payload: &[u8]) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    let len = u32::try_from(payload.len())
        .ok()
        .filter(|&n| n <= MAX_FRAME_LEN)
        .ok_or(ProtocolError::FrameTooLarge(payload.len() as u32))?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one frame's payload. Returns `ConnectionClosed` if the peer hung up
/// before sending any bytes of a new frame.
pub async fn read_frame<R>(reader: &mut R) -> Result<Vec<u8>, ProtocolError>
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
    Ok(payload)
}

/// Read one framed message. Returns `ConnectionClosed` if the peer hung up
/// before sending any bytes of a new frame.
pub async fn read_message<R>(reader: &mut R) -> Result<Message, ProtocolError>
where
    R: AsyncRead + Unpin,
{
    let payload = read_frame(reader).await?;

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
                public_key: [7; 32],
                nonce: [0xab; 32],
            },
            Message::HelloProof {
                paired: true,
                signature: [0xfe; 64],
            },
            Message::PairAccept,
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
            serde_json::json!({"version": 2, "type": "text", "body": "hi"})
        );
        let frame = encode(&Message::PairNonce { nonce: [0x0f; 32] }).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&frame[4..]).unwrap();
        assert_eq!(json["nonce"], "0f".repeat(32));
    }

    #[test]
    fn rejects_malformed_hex() {
        for bad in ["0f", &"zz".repeat(32), &"é".repeat(32)] {
            let json = format!(r#"{{"version":2,"type":"pair_nonce","nonce":"{bad}"}}"#);
            assert!(serde_json::from_str::<Envelope>(&json).is_err(), "{bad}");
        }
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
        let payload = br#"{"version":3,"type":"text","body":"from the future"}"#;
        let (mut a, mut b) = tokio::io::duplex(1024);
        a.write_all(&(payload.len() as u32).to_be_bytes())
            .await
            .unwrap();
        a.write_all(payload).await.unwrap();
        assert!(matches!(
            read_message(&mut b).await,
            Err(ProtocolError::UnsupportedVersion(3))
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

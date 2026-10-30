//! The signed handshake that opens every connection.
//!
//! ```text
//! client                                         server
//!   | --- hello {id, name, key, nonce_c} ---------> |
//!   | <-- welcome {id, name, key, nonce_s, paired,  |
//!   |              sig_s} ------------------------- |
//!   | --- hello_proof {paired, sig_c} ------------> |
//!   | <-------------------------------------- ready |
//! ```
//!
//! Each side signs a transcript of both keys and both nonces (plus its own
//! `paired` flag) with its device key. Since each side's signature covers a
//! nonce the *other* side just made up, an old signature can't be replayed,
//! and a peer that copies another device's id or key, but doesn't hold its
//! private key, can't produce one. The device id must also be the
//! fingerprint of the presented key, and a device we paired with must
//! present the key we stored for it. Any of these failing ends the
//! connection with `identity_mismatch` before any other message is read.
//!
//! The `paired` flags let pairing state converge: if we have the peer as
//! paired but it no longer has us (it unpaired), we forget it too.

use super::{DeviceIdentity, IO_TIMEOUT, PeerIdentity};
use crate::identity::{device_id_for, random_bytes, verify};
use crate::pairing::store::{PairedDevices, Trust};
use crate::protocol::{ErrorCode, Message, ProtocolError, read_message, write_message};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;

/// A completed handshake.
#[derive(Debug, Clone)]
pub struct Handshake {
    pub peer: PeerIdentity,
    /// Whether the two devices are paired: each has the other's key. If only
    /// one side had the other, that side has now forgotten it.
    pub paired: bool,
    /// Both nonces, `(client, server)`; pairing binds its code to them.
    pub nonces: ([u8; 32], [u8; 32]),
}

/// A handshake that failed, and what to tell the peer about it.
#[derive(Debug)]
pub struct HandshakeError {
    /// Sent to the peer before hanging up, if set.
    pub code: Option<ErrorCode>,
    pub message: String,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.code {
            Some(code) => write!(f, "{} ({code:?})", self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for HandshakeError {}

fn refuse(code: ErrorCode, message: impl Into<String>) -> HandshakeError {
    HandshakeError {
        code: Some(code),
        message: message.into(),
    }
}

fn failed(message: impl Into<String>) -> HandshakeError {
    HandshakeError {
        code: None,
        message: message.into(),
    }
}

/// The bytes each side signs. `role` keeps a server's signature from being
/// passed off as a client's and vice versa.
fn transcript(
    role: &str,
    client: (&[u8; 32], &[u8; 32]),
    server: (&[u8; 32], &[u8; 32]),
    paired: bool,
) -> Vec<u8> {
    let mut t = Vec::with_capacity(160);
    t.extend_from_slice(b"OpenDrop handshake v2\0");
    t.extend_from_slice(role.as_bytes());
    t.push(0);
    t.extend_from_slice(client.0);
    t.extend_from_slice(client.1);
    t.extend_from_slice(server.0);
    t.extend_from_slice(server.1);
    t.push(paired as u8);
    t
}

/// Check a peer's claimed id against its key and our paired devices.
/// Returns whether we have it as paired.
fn check_identity(
    paired: &PairedDevices,
    id: &str,
    public_key: &[u8; 32],
) -> Result<bool, HandshakeError> {
    if id != device_id_for(public_key) {
        return Err(refuse(
            ErrorCode::IdentityMismatch,
            format!("device id {id} does not belong to the key it presented"),
        ));
    }
    match paired.check(id, public_key) {
        Trust::Paired => Ok(true),
        Trust::Unknown => Ok(false),
        Trust::Mismatch => Err(refuse(
            ErrorCode::IdentityMismatch,
            format!("{id} presented a different key than the one we paired with"),
        )),
    }
}

/// If we had the peer as paired but it doesn't have us, forget it too.
fn reconcile(paired: &PairedDevices, id: &str, we_have: bool, they_have: bool) -> bool {
    if we_have && !they_have {
        let _ = paired.remove(id);
    }
    we_have && they_have
}

/// Run the server side of the handshake on a fresh connection. On failure,
/// the peer has been told why.
pub async fn accept<S>(
    stream: &mut S,
    identity: &DeviceIdentity,
    paired: &PairedDevices,
) -> Result<Handshake, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let result = accept_inner(stream, identity, paired).await;
    if let Err(HandshakeError {
        code: Some(code),
        message,
    }) = &result
    {
        let _ = write_message(
            stream,
            &Message::Error {
                code: *code,
                message: message.clone(),
            },
        )
        .await;
    }
    result
}

async fn accept_inner<S>(
    stream: &mut S,
    identity: &DeviceIdentity,
    paired: &PairedDevices,
) -> Result<Handshake, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (id, name, client_key, client_nonce) = match next(stream).await? {
        Message::Hello {
            device_id,
            device_name,
            public_key,
            nonce,
        } => (device_id, device_name, public_key, nonce),
        other => {
            return Err(refuse(
                ErrorCode::UnexpectedMessage,
                format!("expected hello, got {other:?}"),
            ));
        }
    };
    let we_have = check_identity(paired, &id, &client_key)?;

    let my_key = identity.public_key();
    let server_nonce = random_bytes();
    let signed = |role, flag| {
        transcript(
            role,
            (&client_key, &client_nonce),
            (&my_key, &server_nonce),
            flag,
        )
    };
    send(
        stream,
        &Message::Welcome {
            device_id: identity.id.clone(),
            device_name: identity.name.clone(),
            public_key: my_key,
            nonce: server_nonce,
            paired: we_have,
            signature: identity.sign(&signed("server", we_have)),
        },
    )
    .await?;

    let (they_have, signature) = match next(stream).await? {
        Message::HelloProof { paired, signature } => (paired, signature),
        other => {
            return Err(refuse(
                ErrorCode::UnexpectedMessage,
                format!("expected hello_proof, got {other:?}"),
            ));
        }
    };
    if !verify(&client_key, &signed("client", they_have), &signature) {
        return Err(refuse(
            ErrorCode::IdentityMismatch,
            format!("{id} could not prove it holds its key"),
        ));
    }
    send(stream, &Message::Ready).await?;
    Ok(Handshake {
        paired: reconcile(paired, &id, we_have, they_have),
        peer: PeerIdentity {
            id,
            name,
            public_key: client_key,
        },
        nonces: (client_nonce, server_nonce),
    })
}

/// Run the client side of the handshake on a fresh connection.
pub async fn connect<S>(
    stream: &mut S,
    identity: &DeviceIdentity,
    paired: &PairedDevices,
) -> Result<Handshake, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let my_key = identity.public_key();
    let client_nonce = random_bytes();
    send(
        stream,
        &Message::Hello {
            device_id: identity.id.clone(),
            device_name: identity.name.clone(),
            public_key: my_key,
            nonce: client_nonce,
        },
    )
    .await?;
    let (id, name, server_key, server_nonce, they_have, signature) = match next(stream).await? {
        Message::Welcome {
            device_id,
            device_name,
            public_key,
            nonce,
            paired,
            signature,
        } => (device_id, device_name, public_key, nonce, paired, signature),
        Message::Error { code, message } => {
            return Err(failed(format!("peer refused ({code:?}): {message}")));
        }
        other => return Err(failed(format!("expected welcome, got {other:?}"))),
    };
    let signed = |role, flag| {
        transcript(
            role,
            (&my_key, &client_nonce),
            (&server_key, &server_nonce),
            flag,
        )
    };
    let checked = check_identity(paired, &id, &server_key).and_then(|we_have| {
        if verify(&server_key, &signed("server", they_have), &signature) {
            Ok(we_have)
        } else {
            Err(refuse(
                ErrorCode::IdentityMismatch,
                format!("{id} could not prove it holds its key"),
            ))
        }
    });
    let we_have = match checked {
        Ok(we_have) => we_have,
        Err(e) => {
            if let Some(code) = e.code {
                let _ = write_message(
                    stream,
                    &Message::Error {
                        code,
                        message: e.message.clone(),
                    },
                )
                .await;
            }
            return Err(e);
        }
    };
    send(
        stream,
        &Message::HelloProof {
            paired: we_have,
            signature: identity.sign(&signed("client", we_have)),
        },
    )
    .await?;
    match next(stream).await? {
        Message::Ready => {}
        Message::Error { code, message } => {
            return Err(failed(format!("peer refused ({code:?}): {message}")));
        }
        other => return Err(failed(format!("expected ready, got {other:?}"))),
    }
    Ok(Handshake {
        paired: reconcile(paired, &id, we_have, they_have),
        peer: PeerIdentity {
            id,
            name,
            public_key: server_key,
        },
        nonces: (client_nonce, server_nonce),
    })
}

async fn next<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Message, HandshakeError> {
    match timeout(IO_TIMEOUT, read_message(stream)).await {
        Ok(Ok(message)) => Ok(message),
        Ok(Err(ProtocolError::UnsupportedVersion(v))) => Err(refuse(
            ErrorCode::UnsupportedVersion,
            format!("version {v} not supported"),
        )),
        Ok(Err(ProtocolError::Json(e))) => Err(refuse(ErrorCode::BadMessage, e.to_string())),
        Ok(Err(e)) => Err(failed(e.to_string())),
        Err(_) => Err(failed("peer went quiet during the handshake")),
    }
}

async fn send<S: AsyncWrite + Unpin>(
    stream: &mut S,
    message: &Message,
) -> Result<(), HandshakeError> {
    write_message(stream, message)
        .await
        .map_err(|e| failed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairing::store::PairedDevice;
    use std::time::{Duration, Instant};
    use tokio::io::DuplexStream;

    fn pair_of_streams() -> (DuplexStream, DuplexStream) {
        tokio::io::duplex(64 * 1024)
    }

    /// Run a real server handshake against a hand-driven client.
    fn serve(
        identity: DeviceIdentity,
        paired: PairedDevices,
    ) -> (
        DuplexStream,
        tokio::task::JoinHandle<Result<Handshake, HandshakeError>>,
    ) {
        let (client, mut server) = pair_of_streams();
        let task = tokio::spawn(async move { accept(&mut server, &identity, &paired).await });
        (client, task)
    }

    async fn expect_error(stream: &mut DuplexStream, code: ErrorCode) {
        match read_message(stream).await.unwrap() {
            Message::Error { code: got, .. } => assert_eq!(got, code),
            other => panic!("expected {code:?}, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn honest_handshake_completes_quickly() {
        let mac = DeviceIdentity::new("Mac");
        let pc = DeviceIdentity::new("PC");
        let (none_a, none_b) = (PairedDevices::in_memory(), PairedDevices::in_memory());
        let (mut a, mut b) = pair_of_streams();
        let started = Instant::now();
        let (client, server) =
            tokio::join!(connect(&mut a, &mac, &none_a), accept(&mut b, &pc, &none_b),);
        let elapsed = started.elapsed();
        let (client, server) = (client.unwrap(), server.unwrap());
        assert_eq!(client.peer.id, pc.id);
        assert_eq!(client.peer.public_key, pc.public_key());
        assert_eq!(server.peer.id, mac.id);
        assert_eq!(server.peer.name, "Mac");
        assert_eq!(client.nonces, server.nonces);
        assert!(!client.paired && !server.paired);
        assert!(elapsed < Duration::from_millis(50), "took {elapsed:?}");
    }

    #[tokio::test]
    async fn borrowed_id_with_another_key_is_refused() {
        let mac = DeviceIdentity::new("Mac");
        let attacker = DeviceIdentity::new("Mac");
        let paired = PairedDevices::in_memory();
        paired
            .insert(PairedDevice::new(
                mac.id.clone(),
                "Mac".into(),
                mac.public_key(),
            ))
            .unwrap();
        let (mut stream, server) = serve(DeviceIdentity::new("PC"), paired);
        write_message(
            &mut stream,
            &Message::Hello {
                device_id: mac.id.clone(),
                device_name: "Mac".into(),
                public_key: attacker.public_key(),
                nonce: random_bytes(),
            },
        )
        .await
        .unwrap();
        expect_error(&mut stream, ErrorCode::IdentityMismatch).await;
        assert_eq!(
            server.await.unwrap().unwrap_err().code,
            Some(ErrorCode::IdentityMismatch)
        );
    }

    #[tokio::test]
    async fn borrowed_id_and_key_without_the_private_key_is_refused() {
        let mac = DeviceIdentity::new("Mac");
        let attacker = DeviceIdentity::new("Mac");
        let (mut stream, server) = serve(DeviceIdentity::new("PC"), PairedDevices::in_memory());
        write_message(
            &mut stream,
            &Message::Hello {
                device_id: mac.id.clone(),
                device_name: "Mac".into(),
                public_key: mac.public_key(),
                nonce: random_bytes(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_message(&mut stream).await.unwrap(),
            Message::Welcome { .. }
        ));
        // It can only sign with its own key.
        write_message(
            &mut stream,
            &Message::HelloProof {
                paired: false,
                signature: attacker.sign(b"anything"),
            },
        )
        .await
        .unwrap();
        expect_error(&mut stream, ErrorCode::IdentityMismatch).await;
        assert!(server.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn replayed_proof_is_refused() {
        let mac = DeviceIdentity::new("Mac");
        let pc = DeviceIdentity::new("PC");
        let paired = PairedDevices::in_memory();
        let hello = Message::Hello {
            device_id: mac.id.clone(),
            device_name: "Mac".into(),
            public_key: mac.public_key(),
            nonce: [9; 32],
        };

        // An honest connection, recorded by an eavesdropper.
        let (mut stream, server) = serve(pc.clone(), PairedDevices::in_memory());
        write_message(&mut stream, &hello).await.unwrap();
        let Message::Welcome { nonce, .. } = read_message(&mut stream).await.unwrap() else {
            panic!("no welcome")
        };
        let proof = Message::HelloProof {
            paired: false,
            signature: mac.sign(&transcript(
                "client",
                (&mac.public_key(), &[9; 32]),
                (&pc.public_key(), &nonce),
                false,
            )),
        };
        write_message(&mut stream, &proof).await.unwrap();
        assert_eq!(read_message(&mut stream).await.unwrap(), Message::Ready);
        assert!(server.await.unwrap().is_ok());

        // The eavesdropper replays the same hello and proof.
        let (mut stream, server) = serve(pc, paired);
        write_message(&mut stream, &hello).await.unwrap();
        let Message::Welcome { nonce: fresh, .. } = read_message(&mut stream).await.unwrap() else {
            panic!("no welcome")
        };
        assert_ne!(fresh, nonce);
        write_message(&mut stream, &proof).await.unwrap();
        expect_error(&mut stream, ErrorCode::IdentityMismatch).await;
        assert!(server.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn client_refuses_a_server_that_fakes_its_signature() {
        let mac = DeviceIdentity::new("Mac");
        let pc = DeviceIdentity::new("PC");
        let (mut a, mut b) = pair_of_streams();
        let fake_server = tokio::spawn(async move {
            let Message::Hello { .. } = read_message(&mut b).await.unwrap() else {
                panic!()
            };
            write_message(
                &mut b,
                &Message::Welcome {
                    device_id: pc.id.clone(),
                    device_name: "PC".into(),
                    public_key: pc.public_key(),
                    nonce: [1; 32],
                    paired: false,
                    signature: [0; 64],
                },
            )
            .await
            .unwrap();
            read_message(&mut b).await.unwrap()
        });
        let err = connect(&mut a, &mac, &PairedDevices::in_memory())
            .await
            .unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::IdentityMismatch));
        assert!(matches!(
            fake_server.await.unwrap(),
            Message::Error {
                code: ErrorCode::IdentityMismatch,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn paired_state_converges_when_one_side_unpaired() {
        let mac = DeviceIdentity::new("Mac");
        let pc = DeviceIdentity::new("PC");
        let mac_store = PairedDevices::in_memory();
        let pc_store = PairedDevices::in_memory();
        mac_store
            .insert(PairedDevice::new(
                pc.id.clone(),
                "PC".into(),
                pc.public_key(),
            ))
            .unwrap();
        pc_store
            .insert(PairedDevice::new(
                mac.id.clone(),
                "Mac".into(),
                mac.public_key(),
            ))
            .unwrap();

        let (mut a, mut b) = pair_of_streams();
        let (c, s) = tokio::join!(
            connect(&mut a, &mac, &mac_store),
            accept(&mut b, &pc, &pc_store)
        );
        assert!(c.unwrap().paired && s.unwrap().paired);

        pc_store.remove(&mac.id).unwrap();
        let (mut a, mut b) = pair_of_streams();
        let (c, s) = tokio::join!(
            connect(&mut a, &mac, &mac_store),
            accept(&mut b, &pc, &pc_store)
        );
        assert!(!c.unwrap().paired && !s.unwrap().paired);
        assert!(mac_store.get(&pc.id).is_none(), "Mac should forget PC too");
    }
}

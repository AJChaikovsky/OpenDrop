//! Pairing: two devices confirm a 6-digit code once, then remember each
//! other's keys.
//!
//! Pairing runs over an already authenticated connection (see
//! `network::handshake`), so both sides know each other's public key. What
//! the handshake can't tell is whether that key belongs to the device the
//! user means, rather than to someone in the middle. So both screens show a
//! code derived from both keys and both sides' nonces, and the users check
//! that the codes match.
//!
//! ```text
//! client (initiator)                        server
//!   | --- pair_request {H(nonce_c)} ------> |   commit first...
//!   | <---------------- pair_nonce {nonce_s} |
//!   | --- pair_reveal {nonce_c} ----------> |   ...reveal after
//!   |        both show the code and ask their user        |
//!   | --- pair_accept | pair_decline -----> |   each side sends exactly
//!   | <----- pair_accept | pair_decline --- |   one answer, in any order
//! ```
//!
//! The commitment stops a man in the middle from choosing its nonce after
//! seeing the other side's, which would let it search for nonces that make
//! the two codes match. Each side stores the other only when both users
//! accepted. A decline on either side, or no answer within
//! [`PAIRING_TIMEOUT`], leaves both unpaired.

pub mod store;

use crate::identity::random_bytes;
use crate::network::{BoxError, DeviceIdentity, PeerIdentity};
use crate::protocol::{ErrorCode, Message, read_message, write_message};
use sha2::{Digest, Sha256};
use std::time::Duration;
use store::{PairedDevice, PairedDevices};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

/// How long both users have to compare the codes and answer.
pub const PAIRING_TIMEOUT: Duration = Duration::from_secs(60);

/// A code for the local user to compare with the other screen. Send `true`
/// on `respond` if it matches, `false` (or drop it) if not. `respond`
/// closes if the other side declines or time runs out first.
#[derive(Debug)]
pub struct PairPrompt {
    pub peer: PeerIdentity,
    /// Six digits, e.g. `"042917"`.
    pub code: String,
    /// True if the other device asked to pair; false if we did.
    pub incoming: bool,
    pub respond: oneshot::Sender<bool>,
}

/// Where pairing codes are shown to the local user.
pub type PairPrompts = mpsc::Sender<PairPrompt>;

/// How a pairing attempt ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairOutcome {
    /// Both users confirmed; each side has stored the other's key.
    Paired,
    /// A user said no. `by_peer` is true if it was the other device's user.
    Declined { by_peer: bool },
    /// Someone didn't answer within [`PAIRING_TIMEOUT`].
    TimedOut,
}

/// What the two sides of one pairing agreed on, enough to compute the code.
struct Session<'a> {
    identity: &'a DeviceIdentity,
    peer: &'a PeerIdentity,
    /// Handshake nonces, `(client, server)`.
    nonces: ([u8; 32], [u8; 32]),
    /// Whether we are the server (the side that was asked).
    incoming: bool,
}

impl Session<'_> {
    /// Public keys as `(client, server)`.
    fn keys(&self) -> ([u8; 32], [u8; 32]) {
        let (mine, theirs) = (self.identity.public_key(), self.peer.public_key);
        if self.incoming {
            (theirs, mine)
        } else {
            (mine, theirs)
        }
    }

    fn code(&self, client_nonce: &[u8; 32], server_nonce: &[u8; 32]) -> String {
        let (client_key, server_key) = self.keys();
        verification_code(
            &client_key,
            &server_key,
            self.nonces,
            client_nonce,
            server_nonce,
        )
    }
}

/// The 6-digit code both screens show: a hash of both keys, both handshake
/// nonces and both pairing nonces, reduced to a number below one million.
pub fn verification_code(
    client_key: &[u8; 32],
    server_key: &[u8; 32],
    handshake_nonces: ([u8; 32], [u8; 32]),
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
) -> String {
    let digest = Sha256::new()
        .chain_update(b"OpenDrop pairing code v2\0")
        .chain_update(client_key)
        .chain_update(server_key)
        .chain_update(handshake_nonces.0)
        .chain_update(handshake_nonces.1)
        .chain_update(client_nonce)
        .chain_update(server_nonce)
        .finalize();
    let n = u64::from_be_bytes(digest[..8].try_into().unwrap());
    format!("{:06}", n % 1_000_000)
}

fn commitment(client_key: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"OpenDrop pairing commitment v2\0")
        .chain_update(client_key)
        .chain_update(nonce)
        .finalize()
        .into()
}

/// Ask the device on the other end of `stream` to pair. `nonces` are the
/// handshake's `(client, server)` nonces. Shows the code on `prompts` and,
/// if both users accept, stores the peer in `paired`.
pub async fn initiate<S>(
    stream: &mut S,
    identity: &DeviceIdentity,
    peer: &PeerIdentity,
    nonces: ([u8; 32], [u8; 32]),
    prompts: &PairPrompts,
    paired: &PairedDevices,
) -> Result<PairOutcome, BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let session = Session {
        identity,
        peer,
        nonces,
        incoming: false,
    };
    let client_nonce = random_bytes();
    write_message(
        stream,
        &Message::PairRequest {
            commitment: commitment(&identity.public_key(), &client_nonce),
        },
    )
    .await?;
    let server_nonce = match recv(stream).await? {
        Message::PairNonce { nonce } => nonce,
        // The other side can't pair right now (e.g. nobody to ask).
        Message::PairDecline { .. } => return Ok(PairOutcome::Declined { by_peer: true }),
        other => return Err(unexpected(other)),
    };
    write_message(
        stream,
        &Message::PairReveal {
            nonce: client_nonce,
        },
    )
    .await?;
    let code = session.code(&client_nonce, &server_nonce);
    confirm(stream, &session, code, prompts, paired).await
}

/// Answer a `pair_request` that arrived on `stream` with `commitment`.
pub async fn respond<S>(
    stream: &mut S,
    identity: &DeviceIdentity,
    peer: &PeerIdentity,
    nonces: ([u8; 32], [u8; 32]),
    commitment_received: [u8; 32],
    prompts: Option<&PairPrompts>,
    paired: &PairedDevices,
) -> Result<PairOutcome, BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(prompts) = prompts else {
        write_message(stream, &Message::PairDecline { timed_out: false }).await?;
        return Ok(PairOutcome::Declined { by_peer: false });
    };
    let session = Session {
        identity,
        peer,
        nonces,
        incoming: true,
    };
    let server_nonce = random_bytes();
    write_message(
        stream,
        &Message::PairNonce {
            nonce: server_nonce,
        },
    )
    .await?;
    let client_nonce = match recv(stream).await? {
        Message::PairReveal { nonce } => nonce,
        other => return Err(unexpected(other)),
    };
    if commitment(&peer.public_key, &client_nonce) != commitment_received {
        let message = "pairing nonce does not match its commitment".to_owned();
        let _ = write_message(
            stream,
            &Message::Error {
                code: ErrorCode::PairingFailed,
                message: message.clone(),
            },
        )
        .await;
        return Err(message.into());
    }
    let code = session.code(&client_nonce, &server_nonce);
    confirm(stream, &session, code, prompts, paired).await
}

/// Show `code` to our user and trade answers with the peer. Each side sends
/// exactly one `pair_accept` or `pair_decline`; a decline from the peer
/// withdraws our prompt and is answered with our own decline.
async fn confirm<S>(
    stream: &mut S,
    session: &Session<'_>,
    code: String,
    prompts: &PairPrompts,
    paired: &PairedDevices,
) -> Result<PairOutcome, BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (respond, decision) = oneshot::channel();
    // If nobody is listening for prompts, `respond` is dropped and the
    // decision below resolves to "no" at once.
    let _ = prompts
        .send(PairPrompt {
            peer: session.peer.clone(),
            code,
            incoming: session.incoming,
            respond,
        })
        .await;

    let (mut reader, mut writer) = tokio::io::split(stream);
    let deadline = tokio::time::sleep(PAIRING_TIMEOUT);
    let remote = read_message(&mut reader);
    tokio::pin!(deadline, remote);
    let mut decision = Some(decision);
    let mut mine: Option<bool> = None;
    let mut theirs: Option<bool> = None;
    // Whether our "no" only echoed theirs, and whether theirs was a timeout.
    let mut followed = false;
    let mut peer_timed_out = false;

    while mine.is_none() || theirs.is_none() {
        tokio::select! {
            answer = async { decision.as_mut().unwrap().await }, if decision.is_some() => {
                decision = None;
                let accept = answer.unwrap_or(false);
                mine = Some(accept);
                let reply = if accept {
                    Message::PairAccept
                } else {
                    Message::PairDecline { timed_out: false }
                };
                write_message(&mut writer, &reply).await?;
            }
            message = &mut remote, if theirs.is_none() => {
                theirs = Some(match message? {
                    Message::PairAccept => true,
                    Message::PairDecline { timed_out } => {
                        peer_timed_out = timed_out;
                        false
                    }
                    other => return Err(unexpected(other)),
                });
                if theirs == Some(false) && mine.is_none() {
                    // Withdraw our prompt and answer in kind.
                    decision = None;
                    mine = Some(false);
                    followed = true;
                    let reply = Message::PairDecline { timed_out: peer_timed_out };
                    write_message(&mut writer, &reply).await?;
                }
            }
            _ = &mut deadline => {
                if mine.is_none() {
                    let reply = Message::PairDecline { timed_out: true };
                    let _ = write_message(&mut writer, &reply).await;
                }
                return Ok(PairOutcome::TimedOut);
            }
        }
    }
    Ok(match (mine, theirs) {
        (Some(true), Some(true)) => {
            paired.insert(PairedDevice::new(
                session.peer.id.clone(),
                session.peer.name.clone(),
                session.peer.public_key,
            ))?;
            PairOutcome::Paired
        }
        _ if peer_timed_out => PairOutcome::TimedOut,
        _ => PairOutcome::Declined {
            by_peer: followed || mine == Some(true),
        },
    })
}

async fn recv<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Message, BoxError> {
    Ok(timeout(crate::network::IO_TIMEOUT, read_message(stream))
        .await
        .map_err(|_| "timed out waiting for peer")??)
}

fn unexpected(message: Message) -> BoxError {
    match message {
        Message::Error { code, message } => format!("peer refused ({code:?}): {message}").into(),
        other => format!("unexpected message while pairing: {other:?}").into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::handshake;
    use tokio::io::DuplexStream;

    /// What one side's simulated user does with the code it's shown.
    #[derive(Clone, Copy)]
    enum User {
        Accept,
        Decline,
        Ignore,
    }

    /// A prompt channel driven by `user`; reports the code it was shown.
    fn user(behaviour: User) -> (PairPrompts, oneshot::Receiver<String>) {
        let (prompts, mut rx) = mpsc::channel::<PairPrompt>(1);
        let (code_tx, code_rx) = oneshot::channel();
        tokio::spawn(async move {
            let mut prompt = rx.recv().await.unwrap();
            let _ = code_tx.send(prompt.code.clone());
            match behaviour {
                User::Accept => drop(prompt.respond.send(true)),
                User::Decline => drop(prompt.respond.send(false)),
                // Hold the prompt open until it is withdrawn.
                User::Ignore => prompt.respond.closed().await,
            }
        });
        (prompts, code_rx)
    }

    struct Side {
        identity: DeviceIdentity,
        store: PairedDevices,
    }

    impl Side {
        fn new(name: &str) -> Self {
            Self {
                identity: DeviceIdentity::new(name),
                store: PairedDevices::in_memory(),
            }
        }
    }

    /// Handshake, then pair, with `client` initiating. Returns each side's
    /// outcome and the code each user saw.
    async fn pair(
        client: &Side,
        client_user: User,
        server: &Side,
        server_user: User,
    ) -> ((PairOutcome, String), (PairOutcome, String)) {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        let (c, s) = tokio::join!(
            handshake::connect(&mut a, &client.identity, &client.store),
            handshake::accept(&mut b, &server.identity, &server.store),
        );
        let (c, s) = (c.unwrap(), s.unwrap());
        let (client_prompts, client_code) = user(client_user);
        let (server_prompts, server_code) = user(server_user);
        let serve = async {
            let Message::PairRequest { commitment } = read_message(&mut b).await.unwrap() else {
                panic!("expected pair_request")
            };
            respond(
                &mut b,
                &server.identity,
                &s.peer,
                s.nonces,
                commitment,
                Some(&server_prompts),
                &server.store,
            )
            .await
            .unwrap()
        };
        let (client_outcome, server_outcome) = tokio::join!(
            async {
                initiate(
                    &mut a,
                    &client.identity,
                    &c.peer,
                    c.nonces,
                    &client_prompts,
                    &client.store,
                )
                .await
                .unwrap()
            },
            serve
        );
        (
            (client_outcome, client_code.await.unwrap()),
            (server_outcome, server_code.await.unwrap()),
        )
    }

    #[tokio::test]
    async fn both_accept_same_code_and_store_each_other() {
        let (mac, pc) = (Side::new("Mac"), Side::new("PC"));
        let ((c, c_code), (s, s_code)) = pair(&mac, User::Accept, &pc, User::Accept).await;
        assert_eq!((c, s), (PairOutcome::Paired, PairOutcome::Paired));
        assert_eq!(c_code, s_code);
        assert_eq!(c_code.len(), 6);
        assert!(c_code.chars().all(|ch| ch.is_ascii_digit()));
        let stored = mac.store.get(&pc.identity.id).unwrap();
        assert_eq!(stored.public_key, pc.identity.public_key());
        assert_eq!(stored.name, "PC");
        assert_eq!(
            pc.store.get(&mac.identity.id).unwrap().public_key,
            mac.identity.public_key()
        );
    }

    #[tokio::test]
    async fn codes_differ_between_sessions() {
        let (mac, pc) = (Side::new("Mac"), Side::new("PC"));
        let ((_, first), _) = pair(&mac, User::Decline, &pc, User::Decline).await;
        let ((_, second), _) = pair(&mac, User::Decline, &pc, User::Decline).await;
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn decline_on_either_side_leaves_both_unpaired() {
        for (client_user, server_user) in [
            (User::Decline, User::Accept),
            (User::Accept, User::Decline),
            (User::Decline, User::Ignore),
            (User::Ignore, User::Decline),
        ] {
            let (mac, pc) = (Side::new("Mac"), Side::new("PC"));
            let ((c, _), (s, _)) = pair(&mac, client_user, &pc, server_user).await;
            assert!(matches!(c, PairOutcome::Declined { .. }), "{c:?}");
            assert!(matches!(s, PairOutcome::Declined { .. }), "{s:?}");
            assert!(mac.store.list().is_empty() && pc.store.list().is_empty());
        }
    }

    #[tokio::test]
    async fn decline_reports_which_side_said_no() {
        let (mac, pc) = (Side::new("Mac"), Side::new("PC"));
        let ((c, _), (s, _)) = pair(&mac, User::Ignore, &pc, User::Decline).await;
        assert_eq!(c, PairOutcome::Declined { by_peer: true });
        assert_eq!(s, PairOutcome::Declined { by_peer: false });
    }

    /// Nobody answers: after 60 seconds (on a paused clock) both give up.
    #[tokio::test(start_paused = true)]
    async fn unanswered_pairing_times_out_after_60_seconds() {
        let (mac, pc) = (Side::new("Mac"), Side::new("PC"));
        let started = tokio::time::Instant::now();
        let ((c, _), (s, _)) = pair(&mac, User::Ignore, &pc, User::Ignore).await;
        assert_eq!((c, s), (PairOutcome::TimedOut, PairOutcome::TimedOut));
        let waited = started.elapsed();
        assert!(
            waited >= PAIRING_TIMEOUT && waited < PAIRING_TIMEOUT + Duration::from_secs(1),
            "{waited:?}"
        );
        assert!(mac.store.list().is_empty() && pc.store.list().is_empty());
    }

    /// Mallory sits between the Mac and the PC: she answers the Mac as a
    /// server and calls the PC as a client, each with her own key, and
    /// relays nothing else. The codes on the two real screens differ, so
    /// the PC's user rejects; even though the Mac's user (fooled) accepts,
    /// neither real device ends up with the other's key.
    #[tokio::test]
    async fn man_in_the_middle_gets_different_codes() {
        for _ in 0..20 {
            let (mac, pc, mallory) = (Side::new("Mac"), Side::new("PC"), Side::new("PC"));
            let ((mac_outcome, mac_code), (_, _mallory_code_to_mac)) =
                pair(&mac, User::Accept, &mallory, User::Accept).await;
            let ((_, _mallory_code_to_pc), (pc_outcome, pc_code)) =
                pair(&mallory, User::Accept, &pc, User::Decline).await;
            assert_ne!(mac_code, pc_code);
            assert_eq!(pc_outcome, PairOutcome::Declined { by_peer: false });
            assert!(pc.store.list().is_empty());
            assert!(mac.store.get(&pc.identity.id).is_none());
            // What the Mac did pair with is Mallory's key, which is not the
            // PC's: its id gives that away in the device list.
            assert_eq!(mac_outcome, PairOutcome::Paired);
            assert!(
                mac.store
                    .list()
                    .iter()
                    .all(|d| d.public_key != pc.identity.public_key())
            );
        }
    }

    #[tokio::test]
    async fn a_reveal_that_breaks_the_commitment_is_refused() {
        let (mac, pc) = (Side::new("Mac"), Side::new("PC"));
        let (mut a, mut b): (DuplexStream, DuplexStream) = tokio::io::duplex(64 * 1024);
        let (c, s) = tokio::join!(
            handshake::connect(&mut a, &mac.identity, &mac.store),
            handshake::accept(&mut b, &pc.identity, &pc.store),
        );
        let (_c, s) = (c.unwrap(), s.unwrap());
        let (prompts, _code) = user(User::Accept);
        let server = tokio::spawn(async move {
            let Message::PairRequest { commitment } = read_message(&mut b).await.unwrap() else {
                panic!()
            };
            respond(
                &mut b,
                &pc.identity,
                &s.peer,
                s.nonces,
                commitment,
                Some(&prompts),
                &pc.store,
            )
            .await
        });
        write_message(
            &mut a,
            &Message::PairRequest {
                commitment: commitment(&mac.identity.public_key(), &[1; 32]),
            },
        )
        .await
        .unwrap();
        let Message::PairNonce { .. } = read_message(&mut a).await.unwrap() else {
            panic!()
        };
        write_message(&mut a, &Message::PairReveal { nonce: [2; 32] })
            .await
            .unwrap();
        assert!(matches!(
            read_message(&mut a).await.unwrap(),
            Message::Error {
                code: ErrorCode::PairingFailed,
                ..
            }
        ));
        assert!(server.await.unwrap().is_err());
    }

    #[test]
    fn code_is_always_six_digits() {
        let code =
            |n: u8| verification_code(&[n; 32], &[1; 32], ([2; 32], [3; 32]), &[4; 32], &[5; 32]);
        for n in 0..=255 {
            let c = code(n);
            assert_eq!(c.len(), 6, "{c}");
            assert!(c.bytes().all(|b| b.is_ascii_digit()));
        }
        assert_eq!(code(9), code(9));
    }
}

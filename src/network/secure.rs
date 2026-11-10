//! The encrypted channel every connection switches to after the handshake.
//!
//! Each side puts a fresh X25519 key in its handshake message, and both
//! keys are covered by the device signatures (see `handshake`), so a
//! device in the middle can't swap in its own. The Diffie-Hellman result,
//! salted with a hash of the whole handshake, goes through HKDF-SHA256 to
//! give one ChaCha20-Poly1305 key per direction. The ephemeral keys are
//! thrown away after the handshake, so a device key stolen later can't
//! decrypt a recorded connection.
//!
//! After that the stream is a series of records:
//!
//! ```text
//! u32 big-endian length of the ciphertext | ciphertext + 16-byte tag
//! ```
//!
//! The nonce is a per-direction record counter, and the length is
//! authenticated as associated data, so records can't be dropped,
//! reordered, replayed, cut or altered without the next read failing. A
//! connection that ends exactly between records looks like a normal close;
//! the protocol above notices a short transfer by its declared size and
//! SHA-256.

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};
use sha2::{Digest, Sha256};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Largest plaintext in one record.
pub const MAX_RECORD: usize = 64 * 1024;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 4;

/// One side's fresh X25519 key pair for a single handshake.
pub struct Ephemeral {
    secret: x25519_dalek::StaticSecret,
    pub public: [u8; 32],
}

impl Ephemeral {
    pub fn new() -> Self {
        let secret = x25519_dalek::StaticSecret::from(crate::identity::random_bytes());
        let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
        Self { secret, public }
    }

    /// Agree on the connection's keys with the peer's ephemeral key.
    /// `transcript` is every handshake value both sides saw, in order; it
    /// salts the derivation so both sides only agree if they saw the same
    /// handshake.
    pub fn agree(
        self,
        their_public: &[u8; 32],
        transcript: &[u8],
        we_are_client: bool,
    ) -> Option<SessionKeys> {
        let shared = self
            .secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(*their_public));
        // An all-zero result means the peer sent a low-order point.
        if !shared.was_contributory() {
            return None;
        }
        let salt = Sha256::digest(transcript);
        let hkdf = hkdf::Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
        let mut client_to_server = [0u8; 32];
        let mut server_to_client = [0u8; 32];
        hkdf.expand(b"OpenDrop v3 client to server", &mut client_to_server)
            .ok()?;
        hkdf.expand(b"OpenDrop v3 server to client", &mut server_to_client)
            .ok()?;
        Some(if we_are_client {
            SessionKeys {
                send: client_to_server,
                recv: server_to_client,
            }
        } else {
            SessionKeys {
                send: server_to_client,
                recv: client_to_server,
            }
        })
    }
}

impl Default for Ephemeral {
    fn default() -> Self {
        Self::new()
    }
}

/// The two keys of one connection, from our point of view.
#[derive(Clone)]
pub struct SessionKeys {
    send: [u8; 32],
    recv: [u8; 32],
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKeys(..)")
    }
}

/// One direction's cipher and record counter.
struct Direction {
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl Direction {
    fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(key.into()),
            counter: 0,
        }
    }

    fn next_nonce(&mut self) -> io::Result<Nonce> {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.counter.to_be_bytes());
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| io::Error::other("record counter exhausted"))?;
        Ok(Nonce::from(nonce))
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

/// A stream wrapped in the encrypted channel. Reads and writes plaintext;
/// the inner stream only ever carries records.
pub struct SecureStream<S> {
    inner: S,
    send: Direction,
    recv: Direction,
    /// A sealed record not yet fully written, and how much of it is.
    out: Vec<u8>,
    out_pos: usize,
    /// Plaintext bytes taken by the last `poll_write` whose record is still
    /// in `out`; reported once the record is written.
    unacked: Option<usize>,
    /// Raw bytes read but not yet opened.
    rx: Vec<u8>,
    rx_start: usize,
    rx_end: usize,
    /// The last opened record's plaintext, and how much was handed out.
    plain: Vec<u8>,
    plain_pos: usize,
}

impl<S> SecureStream<S> {
    pub fn new(inner: S, keys: &SessionKeys) -> Self {
        Self {
            inner,
            send: Direction::new(&keys.send),
            recv: Direction::new(&keys.recv),
            out: Vec::with_capacity(HEADER_LEN + MAX_RECORD + TAG_LEN),
            out_pos: 0,
            unacked: None,
            rx: vec![0; HEADER_LEN + MAX_RECORD + TAG_LEN],
            rx_start: 0,
            rx_end: 0,
            plain: Vec::with_capacity(MAX_RECORD + TAG_LEN),
            plain_pos: 0,
        }
    }

    /// The stream underneath, e.g. to read its addresses.
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    fn seal(&mut self, plaintext: &[u8]) -> io::Result<()> {
        let nonce = self.send.next_nonce()?;
        let header = ((plaintext.len() + TAG_LEN) as u32).to_be_bytes();
        self.out.clear();
        self.out.extend_from_slice(&header);
        self.out.extend_from_slice(plaintext);
        let tag = self
            .send
            .cipher
            .encrypt_inout_detached(&nonce, &header, (&mut self.out[HEADER_LEN..]).into())
            .map_err(|_| io::Error::other("encryption failed"))?;
        self.out.extend_from_slice(&tag);
        self.out_pos = 0;
        Ok(())
    }

    /// Open the next whole record in `rx`, if there is one.
    fn open(&mut self) -> io::Result<bool> {
        let available = &self.rx[self.rx_start..self.rx_end];
        if available.len() < HEADER_LEN {
            return Ok(false);
        }
        let header: [u8; 4] = available[..HEADER_LEN].try_into().unwrap();
        let len = u32::from_be_bytes(header) as usize;
        if !(TAG_LEN..=MAX_RECORD + TAG_LEN).contains(&len) {
            return Err(invalid("bad encrypted record length"));
        }
        if available.len() < HEADER_LEN + len {
            return Ok(false);
        }
        let body = &available[HEADER_LEN..HEADER_LEN + len];
        let (ciphertext, tag) = body.split_at(len - TAG_LEN);
        let tag = Tag::try_from(tag).map_err(|_| invalid("bad tag"))?;
        self.plain.clear();
        self.plain.extend_from_slice(ciphertext);
        self.plain_pos = 0;
        let nonce = self.recv.next_nonce()?;
        self.recv
            .cipher
            .decrypt_inout_detached(&nonce, &header, self.plain.as_mut_slice().into(), &tag)
            .map_err(|_| invalid("encrypted record failed authentication"))?;
        self.rx_start += HEADER_LEN + len;
        // An empty record is the peer calling the transfer off (see
        // `SecureStream::cancel`); nothing else sends one.
        if self.plain.is_empty() {
            return Err(cancelled());
        }
        Ok(true)
    }
}

/// The peer stopped the transfer on purpose: what reading returns after the
/// other side calls [`SecureStream::cancel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCancelled;

impl std::fmt::Display for PeerCancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the other device cancelled the transfer")
    }
}

impl std::error::Error for PeerCancelled {}

fn cancelled() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, PeerCancelled)
}

/// Whether `error` (or anything it wraps) is [`PeerCancelled`].
pub fn is_peer_cancel(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut next = Some(error);
    while let Some(e) = next {
        if e.is::<PeerCancelled>() {
            return true;
        }
        if let Some(io) = e.downcast_ref::<io::Error>()
            && io
                .get_ref()
                .is_some_and(|inner| inner.is::<PeerCancelled>())
        {
            return true;
        }
        next = e.source();
    }
    false
}

impl<S: AsyncWrite + Unpin> SecureStream<S> {
    /// Tell the peer we're calling the transfer off: finish any record
    /// already on its way, then send an empty one, which the peer's next
    /// read reports as [`PeerCancelled`]. The stream is done after this.
    pub async fn cancel(&mut self) -> io::Result<()> {
        std::future::poll_fn(|cx| self.poll_drain(cx)).await?;
        self.unacked = None;
        self.seal(&[])?;
        std::future::poll_fn(|cx| self.poll_drain(cx)).await?;
        std::future::poll_fn(|cx| Pin::new(&mut self.inner).poll_flush(cx)).await
    }
}

impl<S: AsyncWrite + Unpin> SecureStream<S> {
    /// Write out whatever is left of the sealed record.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.out_pos += n;
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SecureStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.plain_pos < this.plain.len() {
                let n = buf.remaining().min(this.plain.len() - this.plain_pos);
                buf.put_slice(&this.plain[this.plain_pos..this.plain_pos + n]);
                this.plain_pos += n;
                return Poll::Ready(Ok(()));
            }
            if this.open()? {
                continue;
            }
            if this.rx_start > 0 {
                this.rx.copy_within(this.rx_start..this.rx_end, 0);
                this.rx_end -= this.rx_start;
                this.rx_start = 0;
            }
            let mut read = ReadBuf::new(&mut this.rx[this.rx_end..]);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
            let n = read.filled().len();
            if n == 0 {
                return Poll::Ready(if this.rx_end == this.rx_start {
                    Ok(())
                } else {
                    Err(io::ErrorKind::UnexpectedEof.into())
                });
            }
            this.rx_end += n;
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SecureStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.unacked.is_none() {
            // Finish any record a flush started before taking more.
            ready!(this.poll_drain(cx))?;
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let n = buf.len().min(MAX_RECORD);
            this.seal(&buf[..n])?;
            this.unacked = Some(n);
        }
        // Report the bytes only once their record is on the wire, so data
        // never sits here unsent while the caller waits for a reply.
        ready!(this.poll_drain(cx))?;
        let n = this.unacked.take().unwrap_or(0);
        Poll::Ready(Ok(n.min(buf.len())))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn pair() -> (SessionKeys, SessionKeys) {
        let (a, b) = (Ephemeral::new(), Ephemeral::new());
        let (a_pub, b_pub) = (a.public, b.public);
        let client = a.agree(&b_pub, b"transcript", true).unwrap();
        let server = b.agree(&a_pub, b"transcript", false).unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn a_cancel_reaches_the_reader_after_the_data_before_it() {
        let (client, server) = pair();
        let (a, b) = duplex(1 << 20);
        let mut writer = SecureStream::new(a, &client);
        let mut reader = SecureStream::new(b, &server);
        writer.write_all(b"first part").await.unwrap();
        writer.cancel().await.unwrap();
        let mut buf = [0u8; 10];
        reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"first part");
        let err = reader.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert!(is_peer_cancel(&err));
        let boxed: Box<dyn std::error::Error + Send + Sync> = Box::new(err);
        assert!(is_peer_cancel(boxed.as_ref()));
        assert!(!is_peer_cancel(&io::Error::from(
            io::ErrorKind::UnexpectedEof
        )));
    }

    #[tokio::test]
    async fn both_sides_derive_matching_keys() {
        let (client, server) = pair();
        assert_eq!(client.send, server.recv);
        assert_eq!(client.recv, server.send);
        assert_ne!(client.send, client.recv);
    }

    #[tokio::test]
    async fn a_different_transcript_gives_different_keys() {
        let (a, b) = (Ephemeral::new(), Ephemeral::new());
        let (a_pub, b_pub) = (a.public, b.public);
        let client = a.agree(&b_pub, b"one", true).unwrap();
        let server = b.agree(&a_pub, b"two", false).unwrap();
        assert_ne!(client.send, server.recv);
    }

    #[tokio::test]
    async fn a_low_order_key_is_refused() {
        assert!(Ephemeral::new().agree(&[0; 32], b"t", true).is_none());
    }

    #[tokio::test]
    async fn round_trips_large_data_and_hides_it_on_the_wire() {
        let (client_keys, server_keys) = pair();
        let (a, b) = duplex(16 * 1024);
        let marker = b"OPENDROP-MARKER-1234";
        let mut data = Vec::new();
        while data.len() < 3 * MAX_RECORD + 77 {
            data.extend_from_slice(marker);
        }
        // Record what crosses the "wire" with a tap between the two ends.
        let (mut tap_in, tap_out) = duplex(16 * 1024);
        let mut a = a;
        let wire = tokio::spawn(async move {
            let mut seen = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = a.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                seen.extend_from_slice(&chunk[..n]);
                tap_in.write_all(&chunk[..n]).await.unwrap();
            }
            tap_in.shutdown().await.unwrap();
            seen
        });
        let expected = data.clone();
        let sender = tokio::spawn(async move {
            let mut client = SecureStream::new(b, &client_keys);
            client.write_all(&data).await.unwrap();
            client.shutdown().await.unwrap();
        });
        let mut server = SecureStream::new(tap_out, &server_keys);
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        sender.await.unwrap();
        drop(server);
        let seen = wire.await.unwrap();
        assert_eq!(got, expected);
        assert!(seen.len() > expected.len());
        assert!(
            !seen.windows(marker.len()).any(|w| w == marker),
            "plaintext leaked onto the wire"
        );
    }

    #[tokio::test]
    async fn a_tampered_record_fails_to_read() {
        let (client_keys, server_keys) = pair();
        let mut sealed = SecureStream::new(Vec::new(), &client_keys);
        sealed.write_all(b"hello there").await.unwrap();
        let mut wire = sealed.inner.clone();
        wire[HEADER_LEN + 2] ^= 1;
        let mut reader = SecureStream::new(&wire[..], &server_keys);
        let mut buf = Vec::new();
        let err = reader.read_to_end(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn a_replayed_record_fails_to_read() {
        let (client_keys, server_keys) = pair();
        let mut sealed = SecureStream::new(Vec::new(), &client_keys);
        sealed.write_all(b"pay 5").await.unwrap();
        let mut wire = sealed.inner.clone();
        wire.extend_from_slice(&sealed.inner.clone());
        let mut reader = SecureStream::new(&wire[..], &server_keys);
        let mut first = [0u8; 5];
        reader.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"pay 5");
        let mut rest = Vec::new();
        let err = reader.read_to_end(&mut rest).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn a_cut_record_is_an_error_not_a_clean_end() {
        let (client_keys, server_keys) = pair();
        let mut sealed = SecureStream::new(Vec::new(), &client_keys);
        sealed.write_all(b"incomplete").await.unwrap();
        let wire = &sealed.inner[..sealed.inner.len() - 3];
        let mut reader = SecureStream::new(wire, &server_keys);
        let mut buf = Vec::new();
        let err = reader.read_to_end(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}

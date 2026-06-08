use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use noise_protocol::patterns::noise_ik_psk2;
use noise_protocol::{CipherState, DH, HandshakeState, HandshakeStateBuilder, U8Array};
use noise_rust_crypto::{Blake2s, ChaCha20Poly1305, X25519};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::keys::{PublicKey, SecretKey, KEY_LEN};
use crate::psk::Psk;
use crate::{Error, Result, PROTOCOL_VERSION};

type Cipher = ChaCha20Poly1305;
type Hash = Blake2s;

const TAG_LEN: usize = 16;
const LEN_PREFIX: usize = 2;
pub const MAX_PLAINTEXT: usize = 16384;
const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + TAG_LEN;
const MAX_HANDSHAKE_MSG: usize = 4096;

fn prologue() -> [u8; 14] {
    let mut p = *b"hyperion-vpn\x00\x00";
    p[12..].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    p
}

fn to_noise_secret(bytes: &[u8; KEY_LEN]) -> <X25519 as DH>::Key {
    <X25519 as DH>::Key::from_slice(bytes)
}

pub struct ClientHandshake<'a> {
    pub static_secret: &'a SecretKey,
    pub server_pubkey: &'a PublicKey,
    pub psk: &'a Psk,
}

pub struct ServerHandshake<'a> {
    pub static_secret: &'a SecretKey,
    pub psk: &'a Psk,
    pub allowed_admins: &'a [PublicKey],
}

pub async fn connect<S>(mut stream: S, hs: &ClientHandshake<'_>) -> Result<NoiseStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let prologue = prologue();
    let mut builder: HandshakeStateBuilder<'_, X25519> = HandshakeStateBuilder::new();
    builder
        .set_pattern(noise_ik_psk2())
        .set_is_initiator(true)
        .set_prologue(&prologue)
        .set_s(to_noise_secret(hs.static_secret.as_bytes()))
        .set_rs(hs.server_pubkey.to_bytes());
    let mut state: HandshakeState<X25519, Cipher, Hash> = builder.build_handshake_state();
    state.push_psk(hs.psk.as_bytes());

    let msg1 = state.write_message_vec(&[]).map_err(|_| Error::Handshake)?;
    write_handshake_msg(&mut stream, &msg1).await?;

    let msg2 = read_handshake_msg(&mut stream).await?;
    state.read_message_vec(&msg2).map_err(|_| Error::Handshake)?;

    if !state.completed() {
        return Err(Error::Handshake);
    }
    let (initiator_to_responder, responder_to_initiator) = state.get_ciphers();
    Ok(NoiseStream::new(
        stream,
        initiator_to_responder,
        responder_to_initiator,
    ))
}

pub async fn accept<S>(
    mut stream: S,
    hs: &ServerHandshake<'_>,
) -> Result<(NoiseStream<S>, PublicKey)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let prologue = prologue();
    let mut builder: HandshakeStateBuilder<'_, X25519> = HandshakeStateBuilder::new();
    builder
        .set_pattern(noise_ik_psk2())
        .set_is_initiator(false)
        .set_prologue(&prologue)
        .set_s(to_noise_secret(hs.static_secret.as_bytes()));
    let mut state: HandshakeState<X25519, Cipher, Hash> = builder.build_handshake_state();
    state.push_psk(hs.psk.as_bytes());

    let msg1 = read_handshake_msg(&mut stream).await?;
    state.read_message_vec(&msg1).map_err(|_| Error::Handshake)?;

    let admin = PublicKey::from_bytes(state.get_rs().ok_or(Error::Handshake)?);
    if !hs.allowed_admins.contains(&admin) {
        return Err(Error::Unauthorized);
    }

    let msg2 = state.write_message_vec(&[]).map_err(|_| Error::Handshake)?;
    write_handshake_msg(&mut stream, &msg2).await?;

    if !state.completed() {
        return Err(Error::Handshake);
    }
    let (initiator_to_responder, responder_to_initiator) = state.get_ciphers();
    Ok((
        NoiseStream::new(stream, responder_to_initiator, initiator_to_responder),
        admin,
    ))
}

async fn write_handshake_msg<S: AsyncWrite + Unpin>(stream: &mut S, msg: &[u8]) -> Result<()> {
    if msg.len() > MAX_HANDSHAKE_MSG {
        return Err(Error::Protocol("handshake message too large".into()));
    }
    stream.write_all(&(msg.len() as u16).to_be_bytes()).await?;
    stream.write_all(msg).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_handshake_msg<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut len = [0u8; LEN_PREFIX];
    stream.read_exact(&mut len).await?;
    let len = u16::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_HANDSHAKE_MSG {
        return Err(Error::Protocol("invalid handshake length".into()));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

pub struct NoiseStream<S> {
    inner: S,
    send: CipherState<Cipher>,
    recv: CipherState<Cipher>,
    write_pending: Vec<u8>,
    write_off: usize,
    read_raw: Vec<u8>,
    read_plain: Vec<u8>,
    read_off: usize,
    read_target: usize,
    have_len: bool,
}

impl<S> NoiseStream<S> {
    pub(crate) fn new(inner: S, send: CipherState<Cipher>, recv: CipherState<Cipher>) -> Self {
        Self {
            inner,
            send,
            recv,
            write_pending: Vec::new(),
            write_off: 0,
            read_raw: Vec::new(),
            read_plain: Vec::new(),
            read_off: 0,
            read_target: 0,
            have_len: false,
        }
    }
}

impl<S: AsyncWrite + Unpin> NoiseStream<S> {
    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_off < self.write_pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.write_pending[self.write_off..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)))
                }
                Poll::Ready(Ok(n)) => self.write_off += n,
            }
        }
        self.write_pending.clear();
        self.write_off = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> NoiseStream<S> {
    fn poll_fill(&mut self, cx: &mut Context<'_>, n: usize) -> Poll<io::Result<bool>> {
        while self.read_raw.len() < n {
            let mut tmp = [0u8; 8192];
            let mut buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let filled = buf.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Ok(false));
                    }
                    self.read_raw.extend_from_slice(filled);
                }
            }
        }
        Poll::Ready(Ok(true))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for NoiseStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(this.poll_flush_pending(cx))?;

        let n = buf.len().min(MAX_PLAINTEXT);
        let ciphertext = this.send.encrypt_vec(&buf[..n]);
        let mut frame = Vec::with_capacity(LEN_PREFIX + ciphertext.len());
        frame.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
        frame.extend_from_slice(&ciphertext);
        this.write_pending = frame;
        this.write_off = 0;

        let _ = this.poll_flush_pending(cx)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_pending(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_pending(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for NoiseStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.read_off < this.read_plain.len() {
                let n = (this.read_plain.len() - this.read_off).min(buf.remaining());
                buf.put_slice(&this.read_plain[this.read_off..this.read_off + n]);
                this.read_off += n;
                return Poll::Ready(Ok(()));
            }

            if !this.have_len {
                match ready!(this.poll_fill(cx, LEN_PREFIX)) {
                    Ok(true) => {}
                    Ok(false) => return Poll::Ready(Ok(())),
                    Err(e) => return Poll::Ready(Err(e)),
                }
                let len = u16::from_be_bytes([this.read_raw[0], this.read_raw[1]]) as usize;
                if !(TAG_LEN..=MAX_CIPHERTEXT).contains(&len) {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid frame length",
                    )));
                }
                this.read_target = LEN_PREFIX + len;
                this.have_len = true;
            }

            match ready!(this.poll_fill(cx, this.read_target)) {
                Ok(true) => {}
                Ok(false) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)))
                }
                Err(e) => return Poll::Ready(Err(e)),
            }

            let plain = this
                .recv
                .decrypt_vec(&this.read_raw[LEN_PREFIX..this.read_target])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decryption failed"))?;
            this.read_raw.drain(..this.read_target);
            this.read_plain = plain;
            this.read_off = 0;
            this.have_len = false;
            this.read_target = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Keypair;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn cipher_pair() -> (CipherState<Cipher>, CipherState<Cipher>) {
        let key = [7u8; 32];
        (CipherState::new(&key, 0), CipherState::new(&key, 0))
    }

    #[tokio::test]
    async fn transport_roundtrip_small_and_multiframe() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (a_send, a_recv) = cipher_pair();
        let (b_send, b_recv) = cipher_pair();
        let mut alice = NoiseStream::new(a, a_send, b_recv);
        let mut bob = NoiseStream::new(b, b_send, a_recv);

        let big = vec![0xABu8; MAX_PLAINTEXT * 3 + 123];
        let expected = big.clone();
        let writer = tokio::spawn(async move {
            alice.write_all(b"hi").await.unwrap();
            alice.write_all(&big).await.unwrap();
            alice.flush().await.unwrap();
            alice
        });

        let mut head = [0u8; 2];
        bob.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"hi");
        let mut rest = vec![0u8; expected.len()];
        bob.read_exact(&mut rest).await.unwrap();
        assert_eq!(rest, expected);
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn transport_rejects_tampered_frame() {
        let (mut raw_tx, rx) = tokio::io::duplex(64 * 1024);
        let key = [9u8; 32];
        let mut enc = CipherState::<Cipher>::new(&key, 0);
        let mut stream = NoiseStream::new(rx, CipherState::new(&key, 0), CipherState::new(&key, 0));

        let ct = enc.encrypt_vec(b"secret");
        let mut frame = (ct.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(&ct);
        frame[LEN_PREFIX + 3] ^= 0xff;
        raw_tx.write_all(&frame).await.unwrap();

        let mut out = [0u8; 6];
        let err = stream.read_exact(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    async fn run_handshake(
        server: ServerHandshake<'_>,
        client: ClientHandshake<'_>,
    ) -> (Result<()>, Result<()>) {
        let (cs, ss) = tokio::io::duplex(64 * 1024);
        let server_fut = async {
            match accept(ss, &server).await {
                Ok((mut s, _admin)) => {
                    let mut buf = [0u8; 4];
                    s.read_exact(&mut buf).await?;
                    s.write_all(&buf).await?;
                    s.flush().await?;
                    Ok(())
                }
                Err(e) => Err(e),
            }
        };
        let client_fut = async {
            match connect(cs, &client).await {
                Ok(mut c) => {
                    c.write_all(b"ping").await?;
                    c.flush().await?;
                    let mut buf = [0u8; 4];
                    c.read_exact(&mut buf).await?;
                    assert_eq!(&buf, b"ping");
                    Ok(())
                }
                Err(e) => Err(e),
            }
        };
        tokio::join!(server_fut, client_fut)
    }

    #[tokio::test]
    async fn handshake_success_and_echo() {
        let admin = Keypair::generate();
        let server = Keypair::generate();
        let psk = Psk::from_bytes([3u8; 32]);
        let allowed = [admin.public];

        let (s, c) = run_handshake(
            ServerHandshake {
                static_secret: &server.secret,
                psk: &psk,
                allowed_admins: &allowed,
            },
            ClientHandshake {
                static_secret: &admin.secret,
                server_pubkey: &server.public,
                psk: &psk,
            },
        )
        .await;
        assert!(s.is_ok(), "server: {s:?}");
        assert!(c.is_ok(), "client: {c:?}");
    }

    #[tokio::test]
    async fn handshake_wrong_psk_fails() {
        let admin = Keypair::generate();
        let server = Keypair::generate();
        let allowed = [admin.public];

        let (s, c) = run_handshake(
            ServerHandshake {
                static_secret: &server.secret,
                psk: &Psk::from_bytes([1u8; 32]),
                allowed_admins: &allowed,
            },
            ClientHandshake {
                static_secret: &admin.secret,
                server_pubkey: &server.public,
                psk: &Psk::from_bytes([2u8; 32]),
            },
        )
        .await;
        assert!(s.is_err() || c.is_err());
    }

    #[tokio::test]
    async fn handshake_unauthorized_admin_fails() {
        let admin = Keypair::generate();
        let other = Keypair::generate();
        let server = Keypair::generate();
        let psk = Psk::from_bytes([5u8; 32]);
        let allowed = [other.public];

        let (s, c) = run_handshake(
            ServerHandshake {
                static_secret: &server.secret,
                psk: &psk,
                allowed_admins: &allowed,
            },
            ClientHandshake {
                static_secret: &admin.secret,
                server_pubkey: &server.public,
                psk: &psk,
            },
        )
        .await;
        assert!(matches!(s, Err(Error::Unauthorized)));
        assert!(c.is_err());
    }
}

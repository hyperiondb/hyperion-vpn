use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use noise_protocol::{Hash, U8Array};
use noise_rust_crypto::Blake2s;
use zeroize::Zeroizing;

use crate::keys::PublicKey;
use crate::psk::Psk;
use crate::{Error, Result, PROTOCOL_VERSION};

const MAGIC: [u8; 4] = *b"HVPK";
const KDF_LABEL: &[u8] = b"hyperion-vpn knock key v1";
const NONCE_LEN: usize = 12;
const PAYLOAD_LEN: usize = 12;
const TAG_LEN: usize = 16;
const AAD_LEN: usize = MAGIC.len() + 32;
pub const PACKET_LEN: usize = MAGIC.len() + NONCE_LEN + PAYLOAD_LEN + TAG_LEN;

pub const DEFAULT_WINDOW_SECS: u64 = 30;
const REPLAY_CAP: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Knock {
    pub tunnel_port: u16,
}

fn knock_cipher(psk: &Psk) -> ChaCha20Poly1305 {
    let (k1, _k2) = Blake2s::hkdf(KDF_LABEL, psk.as_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&k1.as_slice()[..32]);
    ChaCha20Poly1305::new_from_slice(key.as_slice()).expect("key length")
}

fn knock_aad(server_pub: &PublicKey) -> [u8; AAD_LEN] {
    let mut aad = [0u8; AAD_LEN];
    aad[..MAGIC.len()].copy_from_slice(&MAGIC);
    aad[MAGIC.len()..].copy_from_slice(server_pub.as_bytes());
    aad
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn seal(psk: &Psk, server_pub: &PublicKey, tunnel_port: u16) -> Vec<u8> {
    seal_at(psk, server_pub, tunnel_port, now_unix())
}

pub fn seal_at(psk: &Psk, server_pub: &PublicKey, tunnel_port: u16, timestamp: u64) -> Vec<u8> {
    let cipher = knock_cipher(psk);
    let aad = knock_aad(server_pub);
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).expect("system RNG");

    let mut payload = [0u8; PAYLOAD_LEN];
    payload[0..2].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    payload[2..10].copy_from_slice(&timestamp.to_be_bytes());
    payload[10..12].copy_from_slice(&tunnel_port.to_be_bytes());

    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &payload,
                aad: &aad,
            },
        )
        .expect("encrypt");

    let mut packet = Vec::with_capacity(PACKET_LEN);
    packet.extend_from_slice(&MAGIC);
    packet.extend_from_slice(&nonce);
    packet.extend_from_slice(&ciphertext);
    packet
}

pub struct ReplayGuard {
    seen: HashMap<[u8; NONCE_LEN], u64>,
    window: u64,
}

impl ReplayGuard {
    pub fn new(window_secs: u64) -> Self {
        Self {
            seen: HashMap::new(),
            window: window_secs,
        }
    }

    pub fn window(&self) -> u64 {
        self.window
    }

    fn check_and_record(&mut self, nonce: [u8; NONCE_LEN], now: u64) -> bool {
        self.seen
            .retain(|_, &mut t| now.saturating_sub(t) <= self.window);
        if self.seen.contains_key(&nonce) {
            return false;
        }
        if self.seen.len() >= REPLAY_CAP {
            return false;
        }
        self.seen.insert(nonce, now);
        true
    }
}

pub struct KnockVerifier {
    cipher: ChaCha20Poly1305,
    aad: [u8; AAD_LEN],
    replay: ReplayGuard,
}

impl KnockVerifier {
    pub fn new(psk: &Psk, server_pub: &PublicKey, window_secs: u64) -> Self {
        Self {
            cipher: knock_cipher(psk),
            aad: knock_aad(server_pub),
            replay: ReplayGuard::new(window_secs),
        }
    }

    pub fn window(&self) -> u64 {
        self.replay.window()
    }

    pub fn open(&mut self, packet: &[u8], now: u64) -> Result<Knock> {
        if packet.len() != PACKET_LEN {
            return Err(Error::Protocol("knock: bad length".into()));
        }
        if packet[0..4] != MAGIC {
            return Err(Error::Protocol("knock: bad magic".into()));
        }
        let nonce: [u8; NONCE_LEN] = packet[4..16].try_into().unwrap();
        let ciphertext = &packet[16..];

        let plaintext = self
            .cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: &self.aad,
                },
            )
            .map_err(|_| Error::Unauthorized)?;

        let version = u16::from_be_bytes([plaintext[0], plaintext[1]]);
        if version != PROTOCOL_VERSION {
            return Err(Error::Protocol("knock: version mismatch".into()));
        }
        let timestamp = u64::from_be_bytes(plaintext[2..10].try_into().unwrap());
        let tunnel_port = u16::from_be_bytes([plaintext[10], plaintext[11]]);

        if now.abs_diff(timestamp) > self.replay.window {
            return Err(Error::Protocol("knock: stale timestamp".into()));
        }
        if !self.replay.check_and_record(nonce, now) {
            return Err(Error::Protocol("knock: replay".into()));
        }

        Ok(Knock { tunnel_port })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Keypair;

    fn server_pub() -> PublicKey {
        Keypair::generate().public
    }

    #[test]
    fn roundtrip_opens() {
        let psk = Psk::from_bytes([5u8; 32]);
        let server = server_pub();
        let mut v = KnockVerifier::new(&psk, &server, DEFAULT_WINDOW_SECS);
        let pkt = seal_at(&psk, &server, 8443, 1000);
        let k = v.open(&pkt, 1005).unwrap();
        assert_eq!(k.tunnel_port, 8443);
        assert_eq!(pkt.len(), PACKET_LEN);
    }

    #[test]
    fn wrong_psk_rejected() {
        let server = server_pub();
        let mut v = KnockVerifier::new(&Psk::from_bytes([2u8; 32]), &server, DEFAULT_WINDOW_SECS);
        let pkt = seal_at(&Psk::from_bytes([1u8; 32]), &server, 8443, 1000);
        let err = v.open(&pkt, 1000).unwrap_err();
        assert!(matches!(err, Error::Unauthorized));
    }

    #[test]
    fn knock_for_other_server_rejected() {
        let psk = Psk::from_bytes([5u8; 32]);
        let server_a = server_pub();
        let server_b = server_pub();
        let mut v = KnockVerifier::new(&psk, &server_b, DEFAULT_WINDOW_SECS);
        let pkt = seal_at(&psk, &server_a, 8443, 1000);
        let err = v.open(&pkt, 1000).unwrap_err();
        assert!(matches!(err, Error::Unauthorized));
    }

    #[test]
    fn stale_timestamp_rejected() {
        let psk = Psk::from_bytes([5u8; 32]);
        let server = server_pub();
        let mut v = KnockVerifier::new(&psk, &server, 30);
        let pkt = seal_at(&psk, &server, 8443, 1000);
        assert!(v.open(&pkt, 1031).is_err());
    }

    #[test]
    fn replay_rejected() {
        let psk = Psk::from_bytes([5u8; 32]);
        let server = server_pub();
        let mut v = KnockVerifier::new(&psk, &server, DEFAULT_WINDOW_SECS);
        let pkt = seal_at(&psk, &server, 8443, 1000);
        assert!(v.open(&pkt, 1000).is_ok());
        assert!(v.open(&pkt, 1000).is_err());
    }

    #[test]
    fn full_replay_cache_fails_closed() {
        let mut guard = ReplayGuard::new(DEFAULT_WINDOW_SECS);
        for i in 0..REPLAY_CAP {
            let mut nonce = [0u8; NONCE_LEN];
            nonce[..8].copy_from_slice(&(i as u64).to_be_bytes());
            assert!(guard.check_and_record(nonce, 1000));
        }
        assert!(!guard.check_and_record([0xffu8; NONCE_LEN], 1000));
        assert!(guard.check_and_record([0xffu8; NONCE_LEN], 1000 + DEFAULT_WINDOW_SECS + 1));
    }

    #[test]
    fn garbage_rejected() {
        let psk = Psk::from_bytes([5u8; 32]);
        let server = server_pub();
        let mut v = KnockVerifier::new(&psk, &server, DEFAULT_WINDOW_SECS);
        assert!(v.open(&[0u8; PACKET_LEN], 1000).is_err());
        assert!(v.open(b"short", 1000).is_err());
    }

    #[test]
    fn open_never_panics_on_arbitrary_input() {
        let psk = Psk::from_bytes([5u8; 32]);
        let server = server_pub();
        let mut v = KnockVerifier::new(&psk, &server, DEFAULT_WINDOW_SECS);
        let mut buf = [0u8; 80];
        for _ in 0..5000 {
            getrandom::fill(&mut buf).unwrap();
            let len = buf[0] as usize % buf.len();
            let _ = v.open(&buf[..len], 1000);
        }
    }
}

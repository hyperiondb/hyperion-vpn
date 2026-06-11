use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use noise_protocol::{Hash, U8Array};
use noise_rust_crypto::Blake2s;

use crate::psk::Psk;
use crate::{Error, Result, PROTOCOL_VERSION};

const MAGIC: [u8; 4] = *b"HVPK";
const KDF_LABEL: &[u8] = b"hyperion-vpn knock key v1";
const NONCE_LEN: usize = 12;
const PAYLOAD_LEN: usize = 12;
const TAG_LEN: usize = 16;
pub const PACKET_LEN: usize = MAGIC.len() + NONCE_LEN + PAYLOAD_LEN + TAG_LEN;

pub const DEFAULT_WINDOW_SECS: u64 = 30;
const REPLAY_CAP: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Knock {
    pub tunnel_port: u16,
}

fn knock_key(psk: &Psk) -> [u8; 32] {
    let (k1, _k2) = Blake2s::hkdf(KDF_LABEL, psk.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&k1.as_slice()[..32]);
    out
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn seal(psk: &Psk, tunnel_port: u16) -> Vec<u8> {
    seal_at(psk, tunnel_port, now_unix())
}

pub fn seal_at(psk: &Psk, tunnel_port: u16, timestamp: u64) -> Vec<u8> {
    let key = knock_key(psk);
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).expect("system RNG");

    let mut payload = [0u8; PAYLOAD_LEN];
    payload[0..2].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    payload[2..10].copy_from_slice(&timestamp.to_be_bytes());
    payload[10..12].copy_from_slice(&tunnel_port.to_be_bytes());

    let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("key length");
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &payload,
                aad: &MAGIC,
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
        if self.seen.len() < REPLAY_CAP {
            self.seen.insert(nonce, now);
        }
        true
    }
}

pub fn open(psk: &Psk, packet: &[u8], now: u64, replay: &mut ReplayGuard) -> Result<Knock> {
    if packet.len() != PACKET_LEN {
        return Err(Error::Protocol("knock: bad length".into()));
    }
    if packet[0..4] != MAGIC {
        return Err(Error::Protocol("knock: bad magic".into()));
    }
    let nonce: [u8; NONCE_LEN] = packet[4..16].try_into().unwrap();
    let ciphertext = &packet[16..];

    let key = knock_key(psk);
    let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("key length");
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &MAGIC,
            },
        )
        .map_err(|_| Error::Unauthorized)?;

    let version = u16::from_be_bytes([plaintext[0], plaintext[1]]);
    if version != PROTOCOL_VERSION {
        return Err(Error::Protocol("knock: version mismatch".into()));
    }
    let timestamp = u64::from_be_bytes(plaintext[2..10].try_into().unwrap());
    let tunnel_port = u16::from_be_bytes([plaintext[10], plaintext[11]]);

    if now.abs_diff(timestamp) > replay.window {
        return Err(Error::Protocol("knock: stale timestamp".into()));
    }
    if !replay.check_and_record(nonce, now) {
        return Err(Error::Protocol("knock: replay".into()));
    }

    Ok(Knock { tunnel_port })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_opens() {
        let psk = Psk::from_bytes([5u8; 32]);
        let mut guard = ReplayGuard::new(DEFAULT_WINDOW_SECS);
        let pkt = seal_at(&psk, 8443, 1000);
        let k = open(&psk, &pkt, 1005, &mut guard).unwrap();
        assert_eq!(k.tunnel_port, 8443);
        assert_eq!(pkt.len(), PACKET_LEN);
    }

    #[test]
    fn wrong_psk_rejected() {
        let mut guard = ReplayGuard::new(DEFAULT_WINDOW_SECS);
        let pkt = seal_at(&Psk::from_bytes([1u8; 32]), 8443, 1000);
        let err = open(&Psk::from_bytes([2u8; 32]), &pkt, 1000, &mut guard).unwrap_err();
        assert!(matches!(err, Error::Unauthorized));
    }

    #[test]
    fn stale_timestamp_rejected() {
        let psk = Psk::from_bytes([5u8; 32]);
        let mut guard = ReplayGuard::new(30);
        let pkt = seal_at(&psk, 8443, 1000);
        assert!(open(&psk, &pkt, 1031, &mut guard).is_err());
    }

    #[test]
    fn replay_rejected() {
        let psk = Psk::from_bytes([5u8; 32]);
        let mut guard = ReplayGuard::new(DEFAULT_WINDOW_SECS);
        let pkt = seal_at(&psk, 8443, 1000);
        assert!(open(&psk, &pkt, 1000, &mut guard).is_ok());
        assert!(open(&psk, &pkt, 1000, &mut guard).is_err());
    }

    #[test]
    fn garbage_rejected() {
        let psk = Psk::from_bytes([5u8; 32]);
        let mut guard = ReplayGuard::new(DEFAULT_WINDOW_SECS);
        assert!(open(&psk, &[0u8; PACKET_LEN], 1000, &mut guard).is_err());
        assert!(open(&psk, b"short", 1000, &mut guard).is_err());
    }

    #[test]
    fn open_never_panics_on_arbitrary_input() {
        let psk = Psk::from_bytes([5u8; 32]);
        let mut guard = ReplayGuard::new(DEFAULT_WINDOW_SECS);
        let mut buf = [0u8; 80];
        for _ in 0..5000 {
            getrandom::fill(&mut buf).unwrap();
            let len = buf[0] as usize % buf.len();
            let _ = open(&psk, &buf[..len], 1000, &mut guard);
        }
    }
}

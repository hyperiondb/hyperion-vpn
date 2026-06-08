use crate::{Error, Result};
use base64::Engine;
use noise_protocol::{DH, U8Array};
use noise_rust_crypto::X25519;
use zeroize::Zeroize;

pub const KEY_LEN: usize = 32;

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[derive(Clone)]
pub struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    pub fn from_bytes(b: [u8; KEY_LEN]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub fn to_base64(&self) -> String {
        B64.encode(self.0)
    }

    pub fn from_base64(s: &str) -> Result<Self> {
        decode_key(s).map(Self)
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PublicKey([u8; KEY_LEN]);

impl PublicKey {
    pub fn from_bytes(b: [u8; KEY_LEN]) -> Self {
        Self(b)
    }

    pub fn to_bytes(&self) -> [u8; KEY_LEN] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub fn to_base64(&self) -> String {
        B64.encode(self.0)
    }

    pub fn from_base64(s: &str) -> Result<Self> {
        decode_key(s).map(Self)
    }
}

pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl Keypair {
    pub fn generate() -> Self {
        let k = X25519::genkey();
        let mut secret = [0u8; KEY_LEN];
        secret.copy_from_slice(k.as_slice());
        let public = X25519::pubkey(&k);
        Self {
            secret: SecretKey(secret),
            public: PublicKey(public),
        }
    }
}

fn decode_key(s: &str) -> Result<[u8; KEY_LEN]> {
    let raw = B64
        .decode(s.trim())
        .map_err(|_| Error::Protocol("invalid base64 key".into()))?;
    if raw.len() != KEY_LEN {
        return Err(Error::Protocol("key must be 32 bytes".into()));
    }
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&raw);
    Ok(out)
}

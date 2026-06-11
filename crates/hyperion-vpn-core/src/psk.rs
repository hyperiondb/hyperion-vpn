use crate::{Error, Result};
use argon2::Argon2;
use base64::Engine;
use zeroize::{Zeroize, Zeroizing};

pub const PSK_LEN: usize = 32;
pub const MIN_SALT_LEN: usize = 8;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

#[derive(Clone)]
pub struct Psk([u8; PSK_LEN]);

impl Psk {
    pub fn from_bytes(b: [u8; PSK_LEN]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; PSK_LEN] {
        &self.0
    }

    pub fn from_base64(s: &str) -> Result<Self> {
        let raw = Zeroizing::new(
            B64.decode(s.trim())
                .map_err(|_| Error::Protocol("invalid base64 psk".into()))?,
        );
        if raw.len() != PSK_LEN {
            return Err(Error::Protocol("psk must be 32 bytes".into()));
        }
        let mut out = [0u8; PSK_LEN];
        out.copy_from_slice(&raw);
        Ok(Self(out))
    }

    pub fn from_passphrase(passphrase: &[u8], salt: &[u8]) -> Result<Self> {
        if salt.len() < MIN_SALT_LEN {
            return Err(Error::Protocol("salt must be at least 8 bytes".into()));
        }
        let mut out = [0u8; PSK_LEN];
        Argon2::default()
            .hash_password_into(passphrase, salt, &mut out)
            .map_err(|_| Error::Protocol("argon2 derivation failed".into()))?;
        Ok(Self(out))
    }
}

impl Drop for Psk {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_is_deterministic_and_salt_sensitive() {
        let a = Psk::from_passphrase(b"correct horse battery", b"saltsalt").unwrap();
        let b = Psk::from_passphrase(b"correct horse battery", b"saltsalt").unwrap();
        let c = Psk::from_passphrase(b"correct horse battery", b"different-salt").unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), c.as_bytes());
    }

    #[test]
    fn passphrase_rejects_short_salt() {
        assert!(Psk::from_passphrase(b"pw", b"short").is_err());
    }
}

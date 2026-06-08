use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use hyperion_vpn_core::keys::{PublicKey, SecretKey};
use hyperion_vpn_core::psk::Psk;
use hyperion_vpn_core::server::{Egress, ServerConfig};
use serde::Deserialize;

#[derive(Deserialize)]
struct FileConfig {
    listen: String,
    key: KeySource,
    identity: Identity,
    #[serde(default)]
    egress: EgressSection,
    #[serde(default)]
    limits: Limits,
}

#[derive(Deserialize)]
struct KeySource {
    source: String,
    #[serde(default)]
    env_var: Option<String>,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

#[derive(Deserialize)]
struct Identity {
    static_key_file: String,
    #[serde(default)]
    admin_pubkeys: Vec<String>,
}

#[derive(Deserialize, Default)]
struct EgressSection {
    #[serde(default)]
    allow: Vec<String>,
}

#[derive(Deserialize)]
struct Limits {
    #[serde(default = "default_handshake_ms")]
    handshake_timeout_ms: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            handshake_timeout_ms: default_handshake_ms(),
        }
    }
}

fn default_handshake_ms() -> u64 {
    3000
}

pub struct LoadedConfig {
    pub listen: SocketAddr,
    pub server: Arc<ServerConfig>,
}

pub fn load(path: &str) -> anyhow::Result<LoadedConfig> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading config {path}"))?;
    let file: FileConfig = toml::from_str(&text).context("parsing config TOML")?;

    let listen: SocketAddr = file
        .listen
        .parse()
        .with_context(|| format!("invalid listen address: {}", file.listen))?;

    let psk = load_psk(&file.key)?;

    let secret_b64 = std::fs::read_to_string(&file.identity.static_key_file)
        .with_context(|| format!("reading static key {}", file.identity.static_key_file))?;
    let static_secret = SecretKey::from_base64(secret_b64.trim()).context("invalid static key")?;

    let mut allowed_admins = Vec::with_capacity(file.identity.admin_pubkeys.len());
    for pk in &file.identity.admin_pubkeys {
        allowed_admins.push(PublicKey::from_base64(pk).context("invalid admin pubkey")?);
    }
    if allowed_admins.is_empty() {
        bail!("identity.admin_pubkeys is empty — no admin could authenticate");
    }

    let egress = Egress::parse(&file.egress.allow).context("invalid egress allowlist")?;

    Ok(LoadedConfig {
        listen,
        server: Arc::new(ServerConfig {
            static_secret,
            psk,
            allowed_admins,
            egress,
            handshake_timeout: Duration::from_millis(file.limits.handshake_timeout_ms),
        }),
    })
}

fn load_psk(key: &KeySource) -> anyhow::Result<Psk> {
    let b64 = match key.source.as_str() {
        "env" => {
            let var = key
                .env_var
                .as_deref()
                .context("key.source = env requires key.env_var")?;
            std::env::var(var).with_context(|| format!("env var {var} not set"))?
        }
        "file" => {
            let path = key
                .file
                .as_deref()
                .context("key.source = file requires key.file")?;
            std::fs::read_to_string(path).with_context(|| format!("reading psk file {path}"))?
        }
        "value" => key
            .value
            .clone()
            .context("key.source = value requires key.value")?,
        other => bail!("unknown key.source: {other}"),
    };
    Psk::from_base64(b64.trim()).context("invalid PSK")
}

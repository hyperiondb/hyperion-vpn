use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use hyperion_vpn_cli_common as common;
use hyperion_vpn_cli_common::Zeroizing;
use hyperion_vpn_core::keys::{Keypair, PublicKey, SecretKey};
use hyperion_vpn_core::psk::Psk;
use hyperion_vpn_core::server::{Egress, ServerConfig};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    listen: String,
    key: KeySource,
    identity: Identity,
    #[serde(default)]
    egress: EgressSection,
    #[serde(default)]
    limits: Limits,
    #[serde(default)]
    knock: KnockSection,
    #[serde(default)]
    firewall: FirewallSection,
}

#[derive(Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
struct KnockSection {
    #[serde(default)]
    enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    knock_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    window_secs: Option<u64>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FirewallSection {
    #[serde(default = "default_table")]
    table: String,
    #[serde(default = "default_set")]
    set: String,
    #[serde(default = "default_ttl")]
    ttl_secs: u64,
}

impl Default for FirewallSection {
    fn default() -> Self {
        Self {
            table: default_table(),
            set: default_set(),
            ttl_secs: default_ttl(),
        }
    }
}

fn default_table() -> String {
    "hyperion".into()
}

fn default_set() -> String {
    "knock_allow".into()
}

fn default_ttl() -> u64 {
    60
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct KeySource {
    source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    env_var: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    passphrase_env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    salt: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    static_key_file: String,
    #[serde(default)]
    admin_pubkeys: Vec<String>,
}

#[derive(Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
struct EgressSection {
    #[serde(default)]
    allow: Vec<u16>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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
    pub knock: Option<KnockRuntime>,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct KnockRuntime {
    pub knock_port: u16,
    pub tunnel_port: u16,
    pub psk: Psk,
    pub server_pub: PublicKey,
    pub window_secs: u64,
    pub table: String,
    pub set: String,
    pub ttl_secs: u64,
}

pub struct Summary {
    pub listen: String,
    pub knock_enabled: bool,
    pub egress: Vec<u16>,
    pub admin_count: usize,
    pub key_is_passphrase: bool,
    pub passphrase_env: Option<String>,
}

pub fn default_config_path() -> String {
    crate::paths::config_file().to_string_lossy().into_owned()
}

fn read_file(path: &str) -> anyhow::Result<FileConfig> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading config {path}"))?;
    toml::from_str(&text).context("parsing config TOML")
}

pub fn summarize(path: &str) -> anyhow::Result<Summary> {
    let file = read_file(path)?;
    let (key_is_passphrase, passphrase_env) = if file.key.source == "passphrase" {
        (true, file.key.passphrase_env.clone())
    } else {
        (false, None)
    };
    Ok(Summary {
        listen: file.listen,
        knock_enabled: file.knock.enabled,
        egress: file.egress.allow,
        admin_count: file.identity.admin_pubkeys.len(),
        key_is_passphrase,
        passphrase_env,
    })
}

pub fn init_config(
    salt: &str,
    admin_key: &str,
    allow: &[u16],
    listen: &str,
    force: bool,
) -> anyhow::Result<(String, String)> {
    crate::paths::ensure_config_dir().context("creating config dir")?;
    let cfg_path = crate::paths::config_file();
    let key_path = crate::paths::server_key_file();
    if cfg_path.exists() && !force {
        bail!(
            "config already exists at {} (use --force to overwrite)",
            cfg_path.display()
        );
    }
    let _: SocketAddr = listen
        .parse()
        .with_context(|| format!("invalid listen address {listen}"))?;
    PublicKey::from_base64(admin_key).context("invalid admin pubkey")?;

    let keypair = Keypair::generate();
    common::write_secret(&key_path, &keypair.secret.to_base64())?;

    let file = FileConfig {
        listen: listen.to_string(),
        key: KeySource {
            source: "passphrase".into(),
            env_var: None,
            file: None,
            value: None,
            passphrase_env: Some("HYPERION_PASSPHRASE".into()),
            salt: Some(salt.to_string()),
        },
        identity: Identity {
            static_key_file: key_path.to_string_lossy().into_owned(),
            admin_pubkeys: vec![admin_key.to_string()],
        },
        egress: EgressSection {
            allow: allow.to_vec(),
        },
        limits: Limits::default(),
        knock: KnockSection {
            enabled: true,
            knock_port: None,
            window_secs: None,
        },
        firewall: FirewallSection::default(),
    };
    let path = cfg_path.to_string_lossy().into_owned();
    let text = toml::to_string_pretty(&file).context("serializing config")?;
    std::fs::write(&path, text).with_context(|| format!("writing config {path}"))?;

    Ok((path, keypair.public.to_base64()))
}

pub fn load(path: &str) -> anyhow::Result<LoadedConfig> {
    let file = read_file(path)?;

    let listen: SocketAddr = file
        .listen
        .parse()
        .with_context(|| format!("invalid listen address: {}", file.listen))?;

    let psk = load_psk(&file.key)?;

    let key_path = common::expand_home(&file.identity.static_key_file);
    let secret_b64 = Zeroizing::new(
        std::fs::read_to_string(&key_path)
            .with_context(|| format!("reading static key {}", key_path.display()))?,
    );
    let static_secret = SecretKey::from_base64(secret_b64.trim()).context("invalid static key")?;
    let server_pub = static_secret.public_key();

    let mut allowed_admins = Vec::with_capacity(file.identity.admin_pubkeys.len());
    for pk in &file.identity.admin_pubkeys {
        allowed_admins.push(PublicKey::from_base64(pk).context("invalid admin pubkey")?);
    }
    if allowed_admins.is_empty() {
        bail!("identity.admin_pubkeys is empty — no admin could authenticate");
    }

    let egress = Egress::new(file.egress.allow);

    let knock = if file.knock.enabled {
        Some(KnockRuntime {
            knock_port: file.knock.knock_port.unwrap_or(listen.port()),
            tunnel_port: listen.port(),
            psk: psk.clone(),
            server_pub,
            window_secs: file.knock.window_secs.unwrap_or(30),
            table: file.firewall.table,
            set: file.firewall.set,
            ttl_secs: file.firewall.ttl_secs,
        })
    } else {
        None
    };

    Ok(LoadedConfig {
        listen,
        server: Arc::new(ServerConfig {
            static_secret,
            psk,
            allowed_admins,
            egress,
            handshake_timeout: Duration::from_millis(file.limits.handshake_timeout_ms),
        }),
        knock,
    })
}

fn load_psk(key: &KeySource) -> anyhow::Result<Psk> {
    if key.source == "passphrase" {
        let salt = key
            .salt
            .as_deref()
            .context("key.source = passphrase requires key.salt")?;
        let passphrase = common::read_passphrase(
            "hyperion server passphrase: ",
            key.passphrase_env.as_deref(),
        )?;
        return Psk::from_passphrase(passphrase.as_bytes(), salt.as_bytes())
            .context("deriving PSK from passphrase");
    }
    let b64 = Zeroizing::new(match key.source.as_str() {
        "env" => {
            let var = key
                .env_var
                .as_deref()
                .context("key.source = env requires key.env_var")?;
            std::env::var(var).with_context(|| format!("env var {var} not set"))?
        }
        "file" => {
            let path = common::expand_home(
                key.file
                    .as_deref()
                    .context("key.source = file requires key.file")?,
            );
            std::fs::read_to_string(&path)
                .with_context(|| format!("reading psk file {}", path.display()))?
        }
        "value" => key
            .value
            .clone()
            .context("key.source = value requires key.value")?,
        other => bail!("unknown key.source: {other}"),
    });
    Psk::from_base64(b64.trim()).context("invalid PSK")
}

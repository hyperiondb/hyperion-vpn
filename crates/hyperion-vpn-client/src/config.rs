use std::collections::HashMap;
use std::net::SocketAddr;

use anyhow::{bail, Context};
use hyperion_vpn_core::client::TunnelParams;
use hyperion_vpn_core::keys::{PublicKey, SecretKey};
use hyperion_vpn_core::psk::Psk;
use serde::Deserialize;

const DEFAULT_POOL_SIZE: usize = 2;

#[derive(Deserialize)]
struct FileConfig {
    admin_static_key_file: String,
    #[serde(default)]
    pool_size: Option<usize>,
    #[serde(default)]
    server: Vec<ServerSection>,
    #[serde(default)]
    forward: Vec<ForwardSection>,
}

#[derive(Deserialize)]
struct ServerSection {
    name: String,
    addr: String,
    server_pubkey: String,
    #[serde(default)]
    key_env: Option<String>,
    #[serde(default)]
    key_value: Option<String>,
    #[serde(default)]
    pool_size: Option<usize>,
}

#[derive(Deserialize)]
struct ForwardSection {
    local: String,
    server: String,
    remote_host: String,
    remote_port: u16,
}

pub struct ServerEntry {
    pub addr: SocketAddr,
    pub params: TunnelParams,
    pub pool_size: usize,
}

pub struct ForwardEntry {
    pub local: SocketAddr,
    pub server: String,
    pub remote_host: String,
    pub remote_port: u16,
}

pub struct LoadedClient {
    pub servers: HashMap<String, ServerEntry>,
    pub forwards: Vec<ForwardEntry>,
}

pub fn load(path: &str) -> anyhow::Result<LoadedClient> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading config {path}"))?;
    let file: FileConfig = toml::from_str(&text).context("parsing config TOML")?;

    let admin_b64 = std::fs::read_to_string(&file.admin_static_key_file)
        .with_context(|| format!("reading admin key {}", file.admin_static_key_file))?;
    let admin_secret = SecretKey::from_base64(admin_b64.trim()).context("invalid admin key")?;

    let mut servers = HashMap::new();
    for s in file.server {
        let addr: SocketAddr = s
            .addr
            .parse()
            .with_context(|| format!("server {}: invalid addr {}", s.name, s.addr))?;
        let server_pubkey = PublicKey::from_base64(&s.server_pubkey)
            .with_context(|| format!("server {}: invalid server_pubkey", s.name))?;
        let psk = resolve_psk(&s).with_context(|| format!("server {}: psk", s.name))?;
        let pool_size = s.pool_size.or(file.pool_size).unwrap_or(DEFAULT_POOL_SIZE);
        if servers
            .insert(
                s.name.clone(),
                ServerEntry {
                    addr,
                    params: TunnelParams {
                        static_secret: admin_secret.clone(),
                        server_pubkey,
                        psk,
                    },
                    pool_size,
                },
            )
            .is_some()
        {
            bail!("duplicate server name: {}", s.name);
        }
    }

    let mut forwards = Vec::with_capacity(file.forward.len());
    for f in file.forward {
        let local: SocketAddr = f
            .local
            .parse()
            .with_context(|| format!("forward: invalid local addr {}", f.local))?;
        if !servers.contains_key(&f.server) {
            bail!("forward references unknown server: {}", f.server);
        }
        forwards.push(ForwardEntry {
            local,
            server: f.server,
            remote_host: f.remote_host,
            remote_port: f.remote_port,
        });
    }

    Ok(LoadedClient { servers, forwards })
}

fn resolve_psk(s: &ServerSection) -> anyhow::Result<Psk> {
    let b64 = if let Some(var) = &s.key_env {
        std::env::var(var).with_context(|| format!("env var {var} not set"))?
    } else if let Some(value) = &s.key_value {
        value.clone()
    } else {
        bail!("server requires key_env or key_value");
    };
    Psk::from_base64(b64.trim()).context("invalid PSK")
}

pub fn parse_forward_spec(spec: &str) -> anyhow::Result<ForwardEntry> {
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() != 4 {
        bail!("-L expects local_port:server:remote_host:remote_port");
    }
    let local_port: u16 = parts[0].parse().context("bad local port in -L")?;
    let remote_port: u16 = parts[3].parse().context("bad remote port in -L")?;
    Ok(ForwardEntry {
        local: SocketAddr::from(([127, 0, 0, 1], local_port)),
        server: parts[1].to_string(),
        remote_host: parts[2].to_string(),
        remote_port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_config_parses_and_ignores_knock_section() {
        let toml = r#"
admin_static_key_file = "admin.key"

[knock]
transport = "udp"

[[server]]
name = "srvA"
addr = "203.0.113.10:8443"
server_pubkey = "AAA"
key_env = "HYPERION_PSK_SRVA"
pool_size = 3

[[forward]]
local = "127.0.0.1:2201"
server = "srvA"
remote_host = "127.0.0.1"
remote_port = 22
"#;
        let file: FileConfig = toml::from_str(toml).unwrap();
        assert_eq!(file.server.len(), 1);
        assert_eq!(file.server[0].name, "srvA");
        assert_eq!(file.server[0].pool_size, Some(3));
        assert_eq!(file.forward[0].remote_port, 22);
    }

    #[test]
    fn forward_spec_round_trips() {
        let f = parse_forward_spec("2201:srvA:127.0.0.1:22").unwrap();
        assert_eq!(f.local.port(), 2201);
        assert_eq!(f.server, "srvA");
        assert_eq!(f.remote_host, "127.0.0.1");
        assert_eq!(f.remote_port, 22);
    }

    #[test]
    fn forward_spec_rejects_malformed() {
        assert!(parse_forward_spec("nope").is_err());
        assert!(parse_forward_spec("2201:srvA:127.0.0.1").is_err());
    }
}

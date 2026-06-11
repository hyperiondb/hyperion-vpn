use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::{bail, Context};
use hyperion_vpn_cli_common as common;
use hyperion_vpn_cli_common::Zeroizing;
use hyperion_vpn_core::client::{KnockSettings, TunnelParams};
use hyperion_vpn_core::keys::{Keypair, PublicKey, SecretKey};
use hyperion_vpn_core::psk::Psk;
use hyperion_vpn_core::DEFAULT_LISTEN_PORT;
use serde::{Deserialize, Serialize};

const DEFAULT_POOL_SIZE: usize = 2;
const VIRTUAL_HOST_START: u32 = 10;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    admin_static_key_file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pool_size: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key: Option<KeySection>,
    #[serde(default)]
    knock: KnockSection,
    #[serde(default)]
    tun: TunSection,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    server: Vec<ServerSection>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    forward: Vec<ForwardSection>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct KeySection {
    source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    env_var: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    passphrase_env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    salt: Option<String>,
}

#[derive(Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
struct KnockSection {
    #[serde(default)]
    enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TunSection {
    #[serde(default = "default_tun_addr")]
    addr: String,
    #[serde(default = "default_tun_prefix")]
    prefix: u8,
    #[serde(default = "default_tun_mtu")]
    mtu: u16,
}

impl Default for TunSection {
    fn default() -> Self {
        Self {
            addr: default_tun_addr(),
            prefix: default_tun_prefix(),
            mtu: default_tun_mtu(),
        }
    }
}

fn default_tun_addr() -> String {
    "10.99.0.1".into()
}

fn default_tun_prefix() -> u8 {
    24
}

fn default_tun_mtu() -> u16 {
    1420
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ServerSection {
    name: String,
    addr: String,
    server_pubkey: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    virtual_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pool_size: Option<usize>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ForwardSection {
    local: String,
    server: String,
    remote_port: u16,
}

pub struct TunConfig {
    pub addr: Ipv4Addr,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    pub prefix: u8,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    pub mtu: u16,
}

pub struct ServerEntry {
    pub addr: SocketAddr,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    pub virtual_ip: Ipv4Addr,
    pub params: TunnelParams,
    pub pool_size: usize,
}

pub struct ForwardEntry {
    pub local: SocketAddr,
    pub server: String,
    pub remote_port: u16,
}

pub struct LoadedClient {
    pub servers: HashMap<String, ServerEntry>,
    pub forwards: Vec<ForwardEntry>,
    #[cfg_attr(not(feature = "tun"), allow(dead_code))]
    pub tun: TunConfig,
}

pub struct ServerSummary {
    pub name: String,
    pub addr: String,
    pub virtual_ip: Ipv4Addr,
}

pub struct Summary {
    pub servers: Vec<ServerSummary>,
    pub key_is_passphrase: bool,
    pub passphrase_env: Option<String>,
    pub tun_addr: Ipv4Addr,
}

pub fn default_config_path() -> String {
    crate::paths::config_file().to_string_lossy().into_owned()
}

fn read_file(path: &str) -> anyhow::Result<FileConfig> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading config {path}"))?;
    toml::from_str(&text).context("parsing config TOML")
}

fn write_file(path: &str, file: &FileConfig) -> anyhow::Result<()> {
    let text = toml::to_string_pretty(file).context("serializing config TOML")?;
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(path, text).with_context(|| format!("writing config {path}"))
}

fn parse_tun(t: &TunSection) -> anyhow::Result<TunConfig> {
    let addr: Ipv4Addr = t
        .addr
        .parse()
        .with_context(|| format!("[tun] invalid addr {}", t.addr))?;
    if t.prefix == 0 || t.prefix > 30 {
        bail!("[tun] prefix must be between 1 and 30");
    }
    Ok(TunConfig {
        addr,
        prefix: t.prefix,
        mtu: t.mtu,
    })
}

fn assign_virtual_ip(tun: &TunConfig, used: &HashSet<Ipv4Addr>) -> Option<Ipv4Addr> {
    let mask: u32 = u32::MAX << (32 - tun.prefix);
    let base = u32::from(tun.addr) & mask;
    let host_count: u32 = 1u32 << (32 - tun.prefix);
    for h in VIRTUAL_HOST_START..host_count.saturating_sub(1) {
        let cand = Ipv4Addr::from(base + h);
        if cand != tun.addr && !used.contains(&cand) {
            return Some(cand);
        }
    }
    None
}

fn resolve_virtual_ips(
    tun: &TunConfig,
    servers: &[ServerSection],
) -> anyhow::Result<Vec<Ipv4Addr>> {
    let mut used: HashSet<Ipv4Addr> = HashSet::new();
    for s in servers {
        if let Some(vip) = &s.virtual_ip {
            let ip: Ipv4Addr = vip
                .parse()
                .with_context(|| format!("server {}: invalid virtual_ip {vip}", s.name))?;
            if !used.insert(ip) {
                bail!("duplicate virtual_ip {ip}");
            }
        }
    }
    let mut out = Vec::with_capacity(servers.len());
    for s in servers {
        let ip = match &s.virtual_ip {
            Some(vip) => vip.parse().unwrap(),
            None => {
                let ip = assign_virtual_ip(tun, &used)
                    .context("no free virtual IP left in the tun subnet")?;
                used.insert(ip);
                ip
            }
        };
        out.push(ip);
    }
    Ok(out)
}

pub fn load(path: &str) -> anyhow::Result<LoadedClient> {
    let file = read_file(path)?;

    let key_path = common::expand_home(&file.admin_static_key_file);
    let admin_b64 = Zeroizing::new(
        std::fs::read_to_string(&key_path)
            .with_context(|| format!("reading admin key {}", key_path.display()))?,
    );
    let admin_secret = SecretKey::from_base64(admin_b64.trim()).context("invalid admin key")?;

    let default_psk = match &file.key {
        Some(k) => Some(resolve_default_psk(k)?),
        None => None,
    };

    let tun = parse_tun(&file.tun)?;
    let vips = resolve_virtual_ips(&tun, &file.server)?;

    let mut servers = HashMap::new();
    for (s, virtual_ip) in file.server.into_iter().zip(vips) {
        let addr: SocketAddr = s
            .addr
            .parse()
            .with_context(|| format!("server {}: invalid addr {}", s.name, s.addr))?;
        let server_pubkey = PublicKey::from_base64(&s.server_pubkey)
            .with_context(|| format!("server {}: invalid server_pubkey", s.name))?;
        let psk =
            resolve_psk(&s, &default_psk).with_context(|| format!("server {}: psk", s.name))?;
        let pool_size = s.pool_size.or(file.pool_size).unwrap_or(DEFAULT_POOL_SIZE);
        let knock = if file.knock.enabled {
            Some(KnockSettings {
                port: file.knock.port.unwrap_or(addr.port()),
            })
        } else {
            None
        };
        if servers
            .insert(
                s.name.clone(),
                ServerEntry {
                    addr,
                    virtual_ip,
                    params: TunnelParams {
                        static_secret: admin_secret.clone(),
                        server_pubkey,
                        psk,
                        knock,
                        fwmark: None,
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
            remote_port: f.remote_port,
        });
    }

    Ok(LoadedClient {
        servers,
        forwards,
        tun,
    })
}

pub fn summarize(path: &str) -> anyhow::Result<Summary> {
    let file = read_file(path)?;
    let tun = parse_tun(&file.tun)?;
    let vips = resolve_virtual_ips(&tun, &file.server)?;
    let servers = file
        .server
        .iter()
        .zip(vips)
        .map(|(s, virtual_ip)| ServerSummary {
            name: s.name.clone(),
            addr: s.addr.clone(),
            virtual_ip,
        })
        .collect();
    let (key_is_passphrase, passphrase_env) = match &file.key {
        Some(k) if k.source == "passphrase" => (true, k.passphrase_env.clone()),
        _ => (false, None),
    };
    Ok(Summary {
        servers,
        key_is_passphrase,
        passphrase_env,
        tun_addr: tun.addr,
    })
}

pub fn init_config(force: bool) -> anyhow::Result<(String, String, String)> {
    crate::paths::ensure_config_dir().context("creating config dir")?;
    let cfg_path = crate::paths::config_file();
    let key_path = crate::paths::admin_key_file();
    if cfg_path.exists() && !force {
        bail!(
            "config already exists at {} (use --force to overwrite)",
            cfg_path.display()
        );
    }

    let keypair = Keypair::generate();
    common::write_secret(&key_path, &keypair.secret.to_base64())?;

    let salt = Keypair::generate().public.to_base64();
    let salt: String = salt
        .chars()
        .filter(|c| c.is_alphanumeric())
        .take(22)
        .collect();

    let file = FileConfig {
        admin_static_key_file: key_path.to_string_lossy().into_owned(),
        pool_size: None,
        key: Some(KeySection {
            source: "passphrase".into(),
            env_var: None,
            value: None,
            passphrase_env: Some("HYPERION_PASSPHRASE".into()),
            salt: Some(salt.clone()),
        }),
        knock: KnockSection {
            enabled: true,
            port: None,
        },
        tun: TunSection::default(),
        server: Vec::new(),
        forward: Vec::new(),
    };
    let path = cfg_path.to_string_lossy().into_owned();
    write_file(&path, &file)?;

    Ok((path, keypair.public.to_base64(), salt))
}

pub fn add_server(
    path: &str,
    name: &str,
    addr: &str,
    server_pubkey: &str,
) -> anyhow::Result<Ipv4Addr> {
    let parsed_addr: SocketAddr = normalize_addr(addr)
        .parse()
        .with_context(|| format!("invalid server addr {addr}"))?;
    PublicKey::from_base64(server_pubkey).context("invalid server_pubkey")?;

    let mut file = read_file(path)?;
    if file.server.iter().any(|s| s.name == name) {
        bail!("server {name} already exists");
    }

    let tun = parse_tun(&file.tun)?;
    let mut used: HashSet<Ipv4Addr> = HashSet::new();
    for s in &file.server {
        if let Some(vip) = &s.virtual_ip {
            if let Ok(ip) = vip.parse() {
                used.insert(ip);
            }
        }
    }
    let vip =
        assign_virtual_ip(&tun, &used).context("no free virtual IP left in the tun subnet")?;

    file.server.push(ServerSection {
        name: name.to_string(),
        addr: parsed_addr.to_string(),
        server_pubkey: server_pubkey.to_string(),
        virtual_ip: Some(vip.to_string()),
        key_env: None,
        key_value: None,
        pool_size: None,
    });
    write_file(path, &file)?;
    Ok(vip)
}

pub fn remove_server(path: &str, name: &str) -> anyhow::Result<()> {
    let mut file = read_file(path)?;
    let before = file.server.len();
    file.server.retain(|s| s.name != name);
    if file.server.len() == before {
        bail!("no server named {name}");
    }
    write_file(path, &file)?;
    Ok(())
}

fn normalize_addr(addr: &str) -> String {
    if addr.contains(':') {
        addr.to_string()
    } else {
        format!("{addr}:{DEFAULT_LISTEN_PORT}")
    }
}

fn resolve_psk(s: &ServerSection, default_psk: &Option<Psk>) -> anyhow::Result<Psk> {
    if let Some(var) = &s.key_env {
        let b64 =
            Zeroizing::new(std::env::var(var).with_context(|| format!("env var {var} not set"))?);
        return Psk::from_base64(b64.trim()).context("invalid PSK");
    }
    if let Some(value) = &s.key_value {
        return Psk::from_base64(value.trim()).context("invalid PSK");
    }
    if let Some(psk) = default_psk {
        return Ok(psk.clone());
    }
    bail!("server has no key_env/key_value and no global [key] is configured");
}

fn resolve_default_psk(key: &KeySection) -> anyhow::Result<Psk> {
    if key.source == "passphrase" {
        let salt = key
            .salt
            .as_deref()
            .context("[key] source = passphrase requires salt")?;
        let passphrase = common::read_passphrase(
            "hyperion shared passphrase: ",
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
                .context("[key] source = env requires env_var")?;
            std::env::var(var).with_context(|| format!("env var {var} not set"))?
        }
        "value" => key
            .value
            .clone()
            .context("[key] source = value requires value")?,
        other => bail!("unknown [key] source: {other}"),
    });
    Psk::from_base64(b64.trim()).context("invalid PSK")
}

pub fn check_duplicate_locals(forwards: &[ForwardEntry]) -> anyhow::Result<()> {
    let mut seen = std::collections::HashSet::new();
    for f in forwards {
        if !seen.insert(f.local) {
            bail!("duplicate local forward address: {}", f.local);
        }
    }
    Ok(())
}

pub fn parse_forward_spec(spec: &str) -> anyhow::Result<ForwardEntry> {
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() != 3 {
        bail!("-L expects local_port:server:remote_port");
    }
    let local_port: u16 = parts[0].parse().context("bad local port in -L")?;
    let remote_port: u16 = parts[2].parse().context("bad remote port in -L")?;
    Ok(ForwardEntry {
        local: SocketAddr::from(([127, 0, 0, 1], local_port)),
        server: parts[1].to_string(),
        remote_port,
    })
}

#[allow(dead_code)]
pub fn server_ips(loaded: &LoadedClient) -> Vec<IpAddr> {
    loaded.servers.values().map(|e| e.addr.ip()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_config_parses() {
        let toml = r#"
admin_static_key_file = "admin.key"

[knock]
enabled = true

[[server]]
name = "srvA"
addr = "203.0.113.10:8443"
server_pubkey = "AAA"
key_env = "HYPERION_PSK_SRVA"
pool_size = 3

[[forward]]
local = "127.0.0.1:2201"
server = "srvA"
remote_port = 22
"#;
        let file: FileConfig = toml::from_str(toml).unwrap();
        assert_eq!(file.server.len(), 1);
        assert_eq!(file.server[0].name, "srvA");
        assert_eq!(file.server[0].pool_size, Some(3));
        assert_eq!(file.forward[0].remote_port, 22);
    }

    #[test]
    fn unknown_config_keys_are_rejected() {
        let toml = r#"
admin_static_key_file = "admin.key"

[knock]
transport = "udp"
"#;
        assert!(toml::from_str::<FileConfig>(toml).is_err());

        let toml = r#"
admin_static_key_file = "admin.key"
pool_sizes = 3
"#;
        assert!(toml::from_str::<FileConfig>(toml).is_err());
    }

    #[test]
    fn forward_spec_round_trips() {
        let f = parse_forward_spec("2201:srvA:22").unwrap();
        assert_eq!(f.local.port(), 2201);
        assert_eq!(f.server, "srvA");
        assert_eq!(f.remote_port, 22);
    }

    #[test]
    fn forward_spec_rejects_malformed() {
        assert!(parse_forward_spec("nope").is_err());
        assert!(parse_forward_spec("2201:srvA:127.0.0.1:22").is_err());
    }

    #[test]
    fn virtual_ip_assignment_is_sequential_and_skips_used() {
        let tun = TunConfig {
            addr: "10.99.0.1".parse().unwrap(),
            prefix: 24,
            mtu: 1420,
        };
        let mut used = HashSet::new();
        let a = assign_virtual_ip(&tun, &used).unwrap();
        assert_eq!(a, "10.99.0.10".parse::<Ipv4Addr>().unwrap());
        used.insert(a);
        let b = assign_virtual_ip(&tun, &used).unwrap();
        assert_eq!(b, "10.99.0.11".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn resolve_mixes_explicit_and_auto_ips() {
        let tun = TunConfig {
            addr: "10.99.0.1".parse().unwrap(),
            prefix: 24,
            mtu: 1420,
        };
        let servers = vec![
            ServerSection {
                name: "a".into(),
                addr: "203.0.113.10:8443".into(),
                server_pubkey: "x".into(),
                virtual_ip: Some("10.99.0.50".into()),
                key_env: None,
                key_value: None,
                pool_size: None,
            },
            ServerSection {
                name: "b".into(),
                addr: "203.0.113.11:8443".into(),
                server_pubkey: "x".into(),
                virtual_ip: None,
                key_env: None,
                key_value: None,
                pool_size: None,
            },
        ];
        let vips = resolve_virtual_ips(&tun, &servers).unwrap();
        assert_eq!(vips[0], "10.99.0.50".parse::<Ipv4Addr>().unwrap());
        assert_eq!(vips[1], "10.99.0.10".parse::<Ipv4Addr>().unwrap());
    }
}

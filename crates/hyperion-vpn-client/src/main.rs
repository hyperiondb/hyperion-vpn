mod config;
mod daemon;
mod paths;
mod routes;
#[cfg(feature = "tun")]
mod tunmode;

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use hyperion_vpn_core::client::{build_pool, dial, run_forward};
use hyperion_vpn_core::keys::Keypair;
use tokio::net::TcpListener;

#[derive(Parser, Debug)]
#[command(name = "hyperion-client", version, about = "Hyperion VPN admin client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    #[command(about = "Create the admin key + config in your user config dir")]
    Init {
        #[arg(long)]
        force: bool,
    },
    #[command(about = "Add a server (auto-assigns a stable fake IP)")]
    AddServer {
        name: String,
        addr: String,
        pubkey: String,
        #[arg(short, long)]
        config: Option<String>,
    },
    #[command(about = "Remove a server by name")]
    RmServer {
        name: String,
        #[arg(short, long)]
        config: Option<String>,
    },
    #[command(about = "List configured servers and their fake IPs")]
    Ls {
        #[arg(short, long)]
        config: Option<String>,
    },
    #[command(about = "Bring the tunnel up in the background (fake-IP TUN mode)")]
    Up {
        #[arg(short, long)]
        config: Option<String>,
        #[arg(long)]
        foreground: bool,
    },
    #[command(about = "Stop the background tunnel")]
    Down,
    #[command(about = "Show whether the tunnel is up and the server/fake-IP table")]
    Status {
        #[arg(short, long)]
        config: Option<String>,
    },
    #[command(hide = true)]
    Serve {
        #[arg(short, long)]
        config: Option<String>,
    },
    #[command(about = "Run in the foreground with explicit -L local port forwards")]
    Run {
        #[arg(short, long)]
        config: Option<String>,
        #[arg(short = 'L', long = "forward", value_name = "LPORT:SERVER:RHOST:RPORT")]
        forwards: Vec<String>,
    },
    #[command(about = "Generate an admin keypair")]
    Keygen {
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    #[command(about = "Knock + handshake against every server without forwarding")]
    Doctor {
        #[arg(short, long)]
        config: Option<String>,
    },
    #[command(about = "Low-level real-IP L3 TUN mode (Linux/root; advanced)")]
    Tun {
        #[arg(short, long)]
        config: Option<String>,
        #[arg(long, default_value = "10.99.0.1")]
        tun_addr: String,
        #[arg(long, default_value_t = 24)]
        prefix: u8,
        #[arg(long, default_value_t = 1420)]
        mtu: u16,
    },
    #[command(about = "Emit ip route/ip rule commands for real-IP TUN mode (advanced)")]
    PrintRoutes {
        #[arg(short, long)]
        config: Option<String>,
        #[arg(long, default_value = "hyperion0")]
        dev: String,
        #[arg(long, default_value_t = hyperion_vpn_core::client::DEFAULT_FWMARK)]
        mark: u32,
        #[arg(long, default_value_t = 26745)]
        table: u32,
        #[arg(long, default_value_t = 100)]
        priority: u32,
        #[arg(long)]
        down: bool,
    },
}

fn cfg_path(opt: Option<String>) -> String {
    opt.unwrap_or_else(config::default_config_path)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    match Cli::parse().command {
        Command::Init { force } => init(force),
        Command::AddServer {
            name,
            addr,
            pubkey,
            config,
        } => add_server(&cfg_path(config), &name, &addr, &pubkey),
        Command::RmServer { name, config } => {
            config::remove_server(&cfg_path(config), &name)?;
            println!("removed server {name}");
            Ok(())
        }
        Command::Ls { config } => daemon::status(&cfg_path(config)),
        Command::Up { config, foreground } => daemon::up(&cfg_path(config), foreground).await,
        Command::Down => daemon::down(),
        Command::Status { config } => daemon::status(&cfg_path(config)),
        Command::Serve { config } => daemon::run_foreground(&cfg_path(config)).await,
        Command::Run { config, forwards } => run(&cfg_path(config), forwards).await,
        Command::Keygen { out } => keygen(out),
        Command::Doctor { config } => doctor(&cfg_path(config)).await,
        Command::Tun {
            config,
            tun_addr,
            prefix,
            mtu,
        } => {
            #[cfg(feature = "tun")]
            {
                tunmode::run(&cfg_path(config), &tun_addr, prefix, mtu).await
            }
            #[cfg(not(feature = "tun"))]
            {
                let _ = (config, tun_addr, prefix, mtu);
                bail!("built without the `tun` feature; rebuild with: cargo build -p hyperion-vpn-client --features tun")
            }
        }
        Command::PrintRoutes {
            config,
            dev,
            mark,
            table,
            priority,
            down,
        } => {
            let cfg = config::load(&cfg_path(config))?;
            let ips: Vec<std::net::IpAddr> = cfg.servers.values().map(|e| e.addr.ip()).collect();
            print!(
                "{}",
                routes::script(&routes::RouteParams {
                    server_ips: &ips,
                    dev: &dev,
                    mark,
                    table,
                    priority,
                    down,
                })
            );
            Ok(())
        }
    }
}

fn init(force: bool) -> anyhow::Result<()> {
    let (path, admin_pubkey, salt) = config::init_config(force)?;
    println!("hyperion initialized.\n");
    println!("config:  {path}");
    println!("\nadmin public key (allow-list this on every server):");
    println!("  {admin_pubkey}");
    println!("\nshared salt (put the SAME salt in every server's [key].salt):");
    println!("  {salt}");
    println!("\nnext steps:");
    println!("  1. on each Linux server: run the server, allow-list the admin key above");
    println!("  2. here: hyperion-client add-server <name> <host:port> <server_pubkey>");
    println!("  3. hyperion-client up");
    Ok(())
}

fn add_server(config_path: &str, name: &str, addr: &str, pubkey: &str) -> anyhow::Result<()> {
    let vip = config::add_server(config_path, name, addr, pubkey)?;
    println!("added server '{name}' — fake IP {vip}");
    println!("reach it (once `up`): ssh user@{vip}");
    Ok(())
}

async fn run(config_path: &str, extra_forwards: Vec<String>) -> anyhow::Result<()> {
    let mut cfg = config::load(config_path)?;
    for spec in &extra_forwards {
        cfg.forwards.push(config::parse_forward_spec(spec)?);
    }
    if cfg.forwards.is_empty() {
        bail!("no forwards configured (use [[forward]] in config or -L)");
    }
    config::check_duplicate_locals(&cfg.forwards)?;

    let connect_timeout = std::time::Duration::from_secs(10);
    let mut pools = std::collections::HashMap::new();
    for (name, entry) in cfg.servers {
        let pool = build_pool(entry.addr, entry.params, entry.pool_size, connect_timeout)
            .await
            .with_context(|| format!("connecting to server {name} at {}", entry.addr))?;
        tracing::info!(server = %name, addr = %entry.addr, pool = pool.size(), "tunnel up");
        pools.insert(name, pool);
    }

    let mut tasks = Vec::new();
    for fwd in cfg.forwards {
        let pool = pools
            .get(&fwd.server)
            .cloned()
            .with_context(|| format!("forward references unknown server: {}", fwd.server))?;
        let listener = TcpListener::bind(fwd.local)
            .await
            .with_context(|| format!("binding local forward {}", fwd.local))?;
        tracing::info!(
            local = %fwd.local,
            server = %fwd.server,
            remote_port = fwd.remote_port,
            "forwarding"
        );
        tasks.push(tokio::spawn(run_forward(listener, pool, fwd.remote_port)));
    }

    shutdown_signal().await;
    tracing::info!("shutdown signal received");
    for t in tasks {
        t.abort();
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        tokio::select! {
            _ = ctrl_c => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        ctrl_c.await;
    }
}

async fn doctor(config_path: &str) -> anyhow::Result<()> {
    use std::io::Write;
    let cfg = config::load(config_path)?;
    if cfg.servers.is_empty() {
        bail!("no servers configured");
    }
    let timeout = std::time::Duration::from_secs(10);
    let mut all_ok = true;
    for (name, entry) in &cfg.servers {
        print!("{name} ({}) ... ", entry.addr);
        let _ = std::io::stdout().flush();
        match tokio::time::timeout(timeout, dial(entry.addr, &entry.params)).await {
            Ok(Ok(_)) => println!("ok (knock + handshake)"),
            Ok(Err(e)) => {
                println!("FAIL: {e}");
                all_ok = false;
            }
            Err(_) => {
                println!("FAIL: timed out");
                all_ok = false;
            }
        }
    }
    if all_ok {
        Ok(())
    } else {
        bail!("one or more servers failed the connectivity check");
    }
}

fn keygen(out: Option<PathBuf>) -> anyhow::Result<()> {
    let keypair = Keypair::generate();
    println!("admin public key (add to each server's admin allowlist):");
    println!("{}", keypair.public.to_base64());
    match out {
        Some(path) => {
            write_secret(&path, &keypair.secret.to_base64())?;
            println!("admin secret key written to {}", path.display());
        }
        None => {
            println!();
            println!("admin secret key (keep private):");
            println!("{}", keypair.secret.to_base64());
        }
    }
    Ok(())
}

fn write_secret(path: &Path, contents: &str) -> anyhow::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.write_all(contents.as_bytes())?;
    file.write_all(b"\n")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

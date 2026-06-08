mod config;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use hyperion_vpn_core::client::{build_pool, run_forward};
use hyperion_vpn_core::keys::Keypair;
use hyperion_vpn_core::protocol::ConnectRequest;
use tokio::net::TcpListener;

#[derive(Parser, Debug)]
#[command(name = "hyperion-client", version, about = "Hyperion VPN admin client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Run {
        #[arg(short, long, default_value = "hyperion-client.toml")]
        config: String,
        #[arg(short = 'L', long = "forward", value_name = "LPORT:SERVER:RHOST:RPORT")]
        forwards: Vec<String>,
    },
    Keygen {
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    match Cli::parse().command {
        Command::Run { config, forwards } => run(&config, forwards).await,
        Command::Keygen { out } => keygen(out),
    }
}

async fn run(config_path: &str, extra_forwards: Vec<String>) -> anyhow::Result<()> {
    let mut cfg = config::load(config_path)?;
    for spec in &extra_forwards {
        cfg.forwards.push(config::parse_forward_spec(spec)?);
    }
    if cfg.forwards.is_empty() {
        bail!("no forwards configured (use [[forward]] in config or -L)");
    }

    let mut pools = std::collections::HashMap::new();
    for (name, entry) in cfg.servers {
        let pool = build_pool(entry.addr, &entry.params, entry.pool_size)
            .await
            .with_context(|| format!("connecting to server {name} at {}", entry.addr))?;
        tracing::info!(server = %name, addr = %entry.addr, pool = pool.size(), "tunnel up");
        pools.insert(name, Arc::new(pool));
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
            remote = %format!("{}:{}", fwd.remote_host, fwd.remote_port),
            "forwarding"
        );
        let target = ConnectRequest {
            host: fwd.remote_host,
            port: fwd.remote_port,
        };
        tasks.push(tokio::spawn(run_forward(listener, pool, target)));
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

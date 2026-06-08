mod config;

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use hyperion_vpn_core::keys::Keypair;
use hyperion_vpn_core::server::serve_connection;
use tokio::net::TcpListener;

#[derive(Parser, Debug)]
#[command(name = "hyperion-server", version, about = "Hyperion VPN server daemon")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Run {
        #[arg(short, long, default_value = "hyperion-server.toml")]
        config: String,
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
        Command::Run { config } => run(&config).await,
        Command::Keygen { out } => keygen(out),
    }
}

async fn run(config_path: &str) -> anyhow::Result<()> {
    let cfg = config::load(config_path)?;
    let listener = TcpListener::bind(cfg.listen).await?;
    tracing::info!(listen = %cfg.listen, "hyperion-server listening");

    let server = cfg.server;
    loop {
        tokio::select! {
            _ = shutdown_signal() => {
                tracing::info!("shutdown signal received");
                break;
            }
            accepted = listener.accept() => {
                let (sock, peer) = accepted?;
                let _ = sock.set_nodelay(true);
                let server = server.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_connection(sock, server).await {
                        tracing::debug!(%peer, error = %e, "connection ended");
                    }
                });
            }
        }
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
    println!("server public key (put in each client's server config):");
    println!("{}", keypair.public.to_base64());
    match out {
        Some(path) => {
            write_secret(&path, &keypair.secret.to_base64())?;
            println!("server secret key written to {}", path.display());
        }
        None => {
            println!();
            println!("server secret key (keep private):");
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

mod config;
mod daemon;
mod firewall;
mod paths;
mod serve;
#[cfg(target_os = "linux")]
mod sniffer;

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use hyperion_vpn_core::keys::Keypair;

#[derive(Parser, Debug)]
#[command(
    name = "hyperion-server",
    version,
    about = "Hyperion VPN server daemon"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    #[command(about = "Create server key + config in your user config dir")]
    Init {
        #[arg(long)]
        salt: String,
        #[arg(long)]
        admin_key: String,
        #[arg(long, value_delimiter = ',')]
        allow: Vec<u16>,
        #[arg(long, default_value = "0.0.0.0:8443")]
        listen: String,
        #[arg(long)]
        force: bool,
    },
    #[command(about = "Start the server daemon in the background")]
    Up {
        #[arg(short, long)]
        config: Option<String>,
        #[arg(long)]
        foreground: bool,
    },
    #[command(about = "Stop the background server daemon")]
    Down,
    #[command(about = "Show daemon state and config summary")]
    Status {
        #[arg(short, long)]
        config: Option<String>,
    },
    #[command(about = "Run in the foreground (load config, start SPA, listen, relay)")]
    Run {
        #[arg(short, long)]
        config: Option<String>,
    },
    #[command(about = "Generate a server static keypair")]
    Keygen {
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    #[command(about = "Emit the base nftables ruleset (review before applying)")]
    PrintFirewall {
        #[arg(long)]
        tunnel_port: u16,
        #[arg(long, default_value = "hyperion")]
        table: String,
        #[arg(long, default_value = "knock_allow")]
        set: String,
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
    harden();

    match Cli::parse().command {
        Command::Init {
            salt,
            admin_key,
            allow,
            listen,
            force,
        } => init(&salt, &admin_key, &allow, &listen, force),
        Command::Up { config, foreground } => daemon::up(&cfg_path(config), foreground).await,
        Command::Down => daemon::down(),
        Command::Status { config } => daemon::status(&cfg_path(config)),
        Command::Run { config } => serve::run(&cfg_path(config)).await,
        Command::Keygen { out } => keygen(out),
        Command::PrintFirewall {
            tunnel_port,
            table,
            set,
        } => {
            print!("{}", firewall::base_ruleset(&table, &set, tunnel_port));
            Ok(())
        }
    }
}

fn init(
    salt: &str,
    admin_key: &str,
    allow: &[u16],
    listen: &str,
    force: bool,
) -> anyhow::Result<()> {
    let (path, server_pubkey) = config::init_config(salt, admin_key, allow, listen, force)?;
    println!("hyperion-server initialized.\n");
    println!("config:  {path}");
    println!("\nserver public key (give this to the admin for `add-server`):");
    println!("  {server_pubkey}");
    if allow.is_empty() {
        println!("\nNOTE: egress is deny-all. Re-run init with --allow 22,5432 to permit ports,");
        println!("      or edit [egress].allow in the config.");
    }
    println!("\nnext steps:");
    println!(
        "  1. hyperion-server print-firewall --tunnel-port {} | sudo nft -f -",
        port_of(listen)
    );
    println!("     (review first — this is default-DROP and can lock you out)");
    println!("  2. hyperion-server up");
    Ok(())
}

fn port_of(listen: &str) -> String {
    listen
        .rsplit(':')
        .next()
        .filter(|p| p.parse::<u16>().is_ok())
        .unwrap_or("8443")
        .to_string()
}

fn harden() {
    #[cfg(target_os = "linux")]
    {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
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

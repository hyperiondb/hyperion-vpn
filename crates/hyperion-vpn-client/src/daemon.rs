use std::path::Path;

use anyhow::{bail, Context};
use hyperion_vpn_cli_common as common;

use crate::config;
use crate::paths;

const PROC_NEEDLE: &str = "hyperion";

pub async fn up(config_path: &str, foreground: bool) -> anyhow::Result<()> {
    if !Path::new(config_path).exists() {
        bail!(
            "no config at {config_path}\n\
             run `hyperion-client init` first, then add a server with `add-server`"
        );
    }
    let summary = config::summarize(config_path).context("reading config")?;
    if summary.servers.is_empty() {
        bail!(
            "no servers configured\n\
             add one: hyperion-client add-server <name> <host:port> <server_pubkey>"
        );
    }
    if let Some(pid) = common::running_pid(&paths::pid_file(), PROC_NEEDLE) {
        bail!("hyperion is already up (pid {pid}); run `hyperion-client down` first");
    }

    let pass_var = summary
        .passphrase_env
        .clone()
        .unwrap_or_else(|| "HYPERION_PASSPHRASE".into());
    let passphrase = if summary.key_is_passphrase && std::env::var(&pass_var).is_err() {
        Some(common::prompt_passphrase("hyperion shared passphrase: ")?)
    } else {
        None
    };

    if foreground {
        if let Some(p) = &passphrase {
            std::env::set_var(&pass_var, p.as_str());
        }
        return run_foreground(config_path).await;
    }

    paths::ensure_config_dir().ok();
    let pid = common::spawn_daemon(
        &["serve", "--config", config_path],
        &paths::pid_file(),
        &paths::log_file(),
        passphrase.as_ref().map(|p| (pass_var.as_str(), p.as_str())),
    )
    .await?;

    print_up_banner(&summary, pid);
    Ok(())
}

pub fn down() -> anyhow::Result<()> {
    common::stop_daemon(&paths::pid_file(), PROC_NEEDLE, "hyperion")
}

pub fn status(config_path: &str) -> anyhow::Result<()> {
    match common::running_pid(&paths::pid_file(), PROC_NEEDLE) {
        Some(pid) => println!("hyperion: UP (pid {pid})"),
        None => println!("hyperion: down"),
    }
    if Path::new(config_path).exists() {
        let summary = config::summarize(config_path)?;
        print_table(&summary);
    } else {
        println!("no config yet — run `hyperion-client init`");
    }
    Ok(())
}

pub async fn run_foreground(config_path: &str) -> anyhow::Result<()> {
    #[cfg(feature = "tun")]
    {
        let cfg = config::load(config_path)?;
        crate::tunmode::run_managed(cfg).await
    }
    #[cfg(not(feature = "tun"))]
    {
        let _ = config_path;
        bail!(
            "built without the `tun` feature; fake-IP mode needs it \
             (rebuild with default features)"
        )
    }
}

fn print_up_banner(summary: &config::Summary, pid: u32) {
    println!("hyperion up (pid {pid}) — tunnels establishing in the background.\n");
    print_table(summary);
    println!("\nstop with: hyperion-client down");
    println!("logs:      {}", paths::log_file().display());
}

fn print_table(summary: &config::Summary) {
    println!("tun device hyperion0 at {}", summary.tun_addr);
    if summary.servers.is_empty() {
        println!("(no servers — add one: hyperion-client add-server <name> <host:port> <pubkey>)");
        return;
    }
    let name_w = summary
        .servers
        .iter()
        .map(|s| s.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    println!("{:<name_w$}  {:<15}  reach it at", "name", "fake ip");
    for s in &summary.servers {
        println!(
            "{:<name_w$}  {:<15}  ssh user@{}   ({})",
            s.name, s.virtual_ip, s.virtual_ip, s.addr
        );
    }
}

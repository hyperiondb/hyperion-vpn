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
             run `hyperion-server init --salt <salt> --admin-key <admin_pubkey>` first"
        );
    }
    let summary = config::summarize(config_path).context("reading config")?;
    if summary.admin_count == 0 {
        bail!("no admin pubkeys configured — re-run init with --admin-key");
    }
    if let Some(pid) = common::running_pid(&paths::pid_file(), PROC_NEEDLE) {
        bail!("hyperion-server is already up (pid {pid}); run `hyperion-server down` first");
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
        return crate::serve::run(config_path).await;
    }

    paths::ensure_config_dir().ok();
    let pid = common::spawn_daemon(
        &["run", "--config", config_path],
        &paths::pid_file(),
        &paths::log_file(),
        passphrase.as_ref().map(|p| (pass_var.as_str(), p.as_str())),
    )
    .await?;

    print_up_banner(&summary, pid);
    Ok(())
}

pub fn down() -> anyhow::Result<()> {
    common::stop_daemon(&paths::pid_file(), PROC_NEEDLE, "hyperion-server")
}

pub fn status(config_path: &str) -> anyhow::Result<()> {
    match common::running_pid(&paths::pid_file(), PROC_NEEDLE) {
        Some(pid) => println!("hyperion-server: UP (pid {pid})"),
        None => println!("hyperion-server: down"),
    }
    if Path::new(config_path).exists() {
        let s = config::summarize(config_path)?;
        println!("listen:  {}", s.listen);
        println!(
            "knock:   {}",
            if s.knock_enabled { "enabled" } else { "off" }
        );
        println!("admins:  {}", s.admin_count);
        println!(
            "egress:  {}",
            if s.egress.is_empty() {
                "deny-all (no ports allowed yet)".to_string()
            } else {
                s.egress
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        );
    } else {
        println!("no config yet — run `hyperion-server init`");
    }
    Ok(())
}

fn print_up_banner(summary: &config::Summary, pid: u32) {
    println!("hyperion-server up (pid {pid}).\n");
    println!("listen:  {}", summary.listen);
    println!(
        "knock:   {}",
        if summary.knock_enabled {
            "enabled"
        } else {
            "off"
        }
    );
    println!(
        "egress:  {}",
        if summary.egress.is_empty() {
            "deny-all".to_string()
        } else {
            summary
                .egress
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    if summary.knock_enabled {
        println!(
            "\nNOTE: SPA is on, but the firewall is NOT applied automatically.\n\
             Apply it deliberately (you can lock yourself out):\n  \
             hyperion-server print-firewall --tunnel-port {} | sudo nft -f -",
            common::port_of(&summary.listen)
        );
    }
    println!("\nstop with: hyperion-server down");
    println!("logs:      {}", paths::log_file().display());
}

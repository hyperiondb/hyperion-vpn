use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context};

use crate::config;
use crate::paths;

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
    if let Some(pid) = running_pid() {
        bail!("hyperion is already up (pid {pid}); run `hyperion-client down` first");
    }

    let pass_var = summary
        .passphrase_env
        .clone()
        .unwrap_or_else(|| "HYPERION_PASSPHRASE".into());
    let passphrase = if summary.key_is_passphrase && std::env::var(&pass_var).is_err() {
        Some(
            rpassword::prompt_password("hyperion shared passphrase: ")
                .context("reading passphrase")?,
        )
    } else {
        None
    };

    if foreground {
        if let Some(p) = &passphrase {
            std::env::set_var(&pass_var, p);
        }
        return run_foreground(config_path).await;
    }

    paths::ensure_config_dir().ok();
    let log_path = paths::log_file();
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("opening log {}", log_path.display()))?;
    let log_err = log.try_clone()?;
    let exe = std::env::current_exe().context("locating current executable")?;

    let mut cmd = Command::new(exe);
    cmd.arg("serve").arg("--config").arg(config_path);
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::from(log));
    cmd.stderr(std::process::Stdio::from(log_err));
    if let Some(p) = &passphrase {
        cmd.env(&pass_var, p);
    }
    detach(&mut cmd);

    let child = cmd.spawn().context("spawning background daemon")?;
    let pid = child.id();
    write_pid(pid)?;

    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    if !is_alive(pid) {
        let _ = std::fs::remove_file(paths::pid_file());
        bail!(
            "daemon exited immediately — check the log:\n  {}",
            log_path.display()
        );
    }

    print_up_banner(&summary, pid);
    Ok(())
}

pub fn down() -> anyhow::Result<()> {
    let Some(pid) = read_pid() else {
        println!("hyperion is not running (no pid file)");
        return Ok(());
    };
    if is_alive(pid) {
        kill(pid)?;
        println!("hyperion down (stopped pid {pid})");
    } else {
        println!("hyperion was not running (cleaned up stale pid {pid})");
    }
    let _ = std::fs::remove_file(paths::pid_file());
    Ok(())
}

pub fn status(config_path: &str) -> anyhow::Result<()> {
    match running_pid() {
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

fn running_pid() -> Option<u32> {
    let pid = read_pid()?;
    if is_alive(pid) {
        Some(pid)
    } else {
        None
    }
}

fn read_pid() -> Option<u32> {
    std::fs::read_to_string(paths::pid_file())
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn write_pid(pid: u32) -> anyhow::Result<()> {
    std::fs::write(paths::pid_file(), pid.to_string())
        .with_context(|| format!("writing pid file {}", paths::pid_file().display()))
}

#[cfg(windows)]
fn detach(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
}

#[cfg(unix)]
fn detach(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    cmd.process_group(0);
}

#[cfg(windows)]
fn is_alive(pid: u32) -> bool {
    match Command::new("tasklist")
        .args(["/NH", "/FI", &format!("PID eq {pid}")])
        .output()
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()),
        Err(_) => true,
    }
}

#[cfg(target_os = "linux")]
fn is_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

#[cfg(all(unix, not(target_os = "linux")))]
fn is_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(true)
}

#[cfg(windows)]
fn kill(pid: u32) -> anyhow::Result<()> {
    let status = Command::new("taskkill")
        .args(["/F", "/T", "/PID", &pid.to_string()])
        .status()
        .context("running taskkill")?;
    if !status.success() {
        bail!("taskkill failed for pid {pid}");
    }
    Ok(())
}

#[cfg(unix)]
fn kill(pid: u32) -> anyhow::Result<()> {
    let status = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .context("running kill")?;
    if !status.success() {
        bail!("kill failed for pid {pid}");
    }
    Ok(())
}

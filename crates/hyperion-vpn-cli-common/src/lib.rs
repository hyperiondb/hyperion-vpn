use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{bail, Context};

pub use zeroize::Zeroizing;

pub fn config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("HYPERION_HOME") {
        return PathBuf::from(dir);
    }
    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return PathBuf::from(appdata).join("hyperion");
        }
        if let Ok(profile) = std::env::var("USERPROFILE") {
            return PathBuf::from(profile)
                .join("AppData")
                .join("Roaming")
                .join("hyperion");
        }
        PathBuf::from("hyperion")
    }
    #[cfg(not(windows))]
    {
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            return PathBuf::from(xdg).join("hyperion");
        }
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(".config").join("hyperion");
        }
        PathBuf::from("hyperion")
    }
}

pub fn ensure_config_dir() -> std::io::Result<PathBuf> {
    let dir = config_dir();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE").ok().map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOME").ok().map(PathBuf::from)
    }
}

pub fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        if let Some(home) = home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

pub fn port_of(listen: &str) -> String {
    listen
        .rsplit(':')
        .next()
        .filter(|p| p.parse::<u16>().is_ok())
        .unwrap_or("8443")
        .to_string()
}

pub fn write_secret(path: &Path, contents: &str) -> anyhow::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    file.write_all(contents.as_bytes())?;
    file.write_all(b"\n")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn prompt_passphrase(prompt: &str) -> anyhow::Result<Zeroizing<String>> {
    Ok(Zeroizing::new(
        rpassword::prompt_password(prompt).context("reading passphrase")?,
    ))
}

pub fn read_passphrase(
    prompt: &str,
    passphrase_env: Option<&str>,
) -> anyhow::Result<Zeroizing<String>> {
    if let Some(var) = passphrase_env {
        if let Ok(val) = std::env::var(var) {
            return Ok(Zeroizing::new(val));
        }
    }
    prompt_passphrase(prompt)
}

pub async fn shutdown_signal() {
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

pub fn read_pid(pid_path: &Path) -> Option<u32> {
    std::fs::read_to_string(pid_path).ok()?.trim().parse().ok()
}

pub fn write_pid(pid_path: &Path, pid: u32) -> anyhow::Result<()> {
    std::fs::write(pid_path, pid.to_string())
        .with_context(|| format!("writing pid file {}", pid_path.display()))
}

pub fn running_pid(pid_path: &Path, proc_needle: &str) -> Option<u32> {
    let pid = read_pid(pid_path)?;
    if is_alive(pid) && process_name_matches(pid, proc_needle) {
        Some(pid)
    } else {
        None
    }
}

pub async fn spawn_daemon(
    args: &[&str],
    pid_path: &Path,
    log_path: &Path,
    env: Option<(&str, &str)>,
) -> anyhow::Result<u32> {
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .with_context(|| format!("opening log {}", log_path.display()))?;
    let log_err = log.try_clone()?;
    let exe = std::env::current_exe().context("locating current executable")?;

    let mut cmd = Command::new(exe);
    cmd.args(args);
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::from(log));
    cmd.stderr(std::process::Stdio::from(log_err));
    if let Some((var, value)) = env {
        cmd.env(var, value);
    }
    detach(&mut cmd);

    let child = cmd.spawn().context("spawning background daemon")?;
    let pid = child.id();
    write_pid(pid_path, pid)?;

    tokio::time::sleep(Duration::from_millis(800)).await;
    if !is_alive(pid) {
        let _ = std::fs::remove_file(pid_path);
        bail!(
            "daemon exited immediately — check the log:\n  {}",
            log_path.display()
        );
    }
    Ok(pid)
}

pub fn stop_daemon(pid_path: &Path, proc_needle: &str, label: &str) -> anyhow::Result<()> {
    let Some(pid) = read_pid(pid_path) else {
        println!("{label} is not running (no pid file)");
        return Ok(());
    };
    if is_alive(pid) && process_name_matches(pid, proc_needle) {
        kill(pid)?;
        println!("{label} down (stopped pid {pid})");
    } else {
        println!("{label} was not running (cleaned up stale pid {pid})");
    }
    let _ = std::fs::remove_file(pid_path);
    Ok(())
}

#[cfg(windows)]
pub fn detach(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
}

#[cfg(unix)]
pub fn detach(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    cmd.process_group(0);
}

#[cfg(windows)]
pub fn is_alive(pid: u32) -> bool {
    match Command::new("tasklist")
        .args(["/NH", "/FI", &format!("PID eq {pid}")])
        .output()
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()),
        Err(_) => true,
    }
}

#[cfg(target_os = "linux")]
pub fn is_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

#[cfg(all(unix, not(target_os = "linux")))]
pub fn is_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(true)
}

#[cfg(windows)]
pub fn process_name_matches(pid: u32, needle: &str) -> bool {
    match Command::new("tasklist")
        .args(["/NH", "/FI", &format!("PID eq {pid}")])
        .output()
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout)
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase()),
        Err(_) => true,
    }
}

#[cfg(target_os = "linux")]
pub fn process_name_matches(pid: u32, needle: &str) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/comm")) {
        Ok(comm) => comm.contains(needle),
        Err(_) => true,
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
pub fn process_name_matches(pid: u32, needle: &str) -> bool {
    match Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output()
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).contains(needle),
        Err(_) => true,
    }
}

#[cfg(windows)]
pub fn kill(pid: u32) -> anyhow::Result<()> {
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
pub fn kill(pid: u32) -> anyhow::Result<()> {
    let status = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .context("running kill")?;
    if !status.success() {
        bail!("kill failed for pid {pid}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_of_extracts_or_defaults() {
        assert_eq!(port_of("0.0.0.0:9000"), "9000");
        assert_eq!(port_of("not-an-addr"), "8443");
    }

    #[test]
    fn expand_home_leaves_plain_paths() {
        assert_eq!(
            expand_home("/etc/hyperion/key"),
            Path::new("/etc/hyperion/key")
        );
        assert_eq!(expand_home("relative/key"), Path::new("relative/key"));
    }

    #[test]
    fn expand_home_resolves_tilde() {
        if let Some(home) = home_dir() {
            assert_eq!(expand_home("~/x/key"), home.join("x/key"));
        }
    }
}

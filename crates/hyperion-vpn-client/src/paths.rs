use std::path::PathBuf;

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

pub fn config_file() -> PathBuf {
    config_dir().join("hyperion.toml")
}

pub fn admin_key_file() -> PathBuf {
    config_dir().join("admin.key")
}

pub fn pid_file() -> PathBuf {
    config_dir().join("hyperion.pid")
}

pub fn log_file() -> PathBuf {
    config_dir().join("hyperion.log")
}

pub fn ensure_config_dir() -> std::io::Result<PathBuf> {
    let dir = config_dir();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

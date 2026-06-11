use std::path::PathBuf;

use hyperion_vpn_cli_common as common;

pub fn config_file() -> PathBuf {
    common::config_dir().join("hyperion.toml")
}

pub fn admin_key_file() -> PathBuf {
    common::config_dir().join("admin.key")
}

pub fn pid_file() -> PathBuf {
    common::config_dir().join("hyperion.pid")
}

pub fn log_file() -> PathBuf {
    common::config_dir().join("hyperion.log")
}

pub fn ensure_config_dir() -> std::io::Result<PathBuf> {
    common::ensure_config_dir()
}

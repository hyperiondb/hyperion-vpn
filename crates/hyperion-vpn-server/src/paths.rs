use std::path::PathBuf;

use hyperion_vpn_cli_common as common;

pub fn config_file() -> PathBuf {
    common::config_dir().join("server.toml")
}

pub fn server_key_file() -> PathBuf {
    common::config_dir().join("server.key")
}

pub fn pid_file() -> PathBuf {
    common::config_dir().join("hyperion-server.pid")
}

pub fn log_file() -> PathBuf {
    common::config_dir().join("hyperion-server.log")
}

pub fn ensure_config_dir() -> std::io::Result<PathBuf> {
    common::ensure_config_dir()
}

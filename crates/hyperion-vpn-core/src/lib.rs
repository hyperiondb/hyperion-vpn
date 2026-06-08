pub const PROTOCOL_VERSION: u16 = 1;

pub const DEFAULT_LISTEN_PORT: u16 = 8443;

pub mod client;
pub mod error;
pub mod keys;
pub mod mux;
pub mod noise;
pub mod protocol;
pub mod psk;
pub mod server;

pub use error::{Error, Result};

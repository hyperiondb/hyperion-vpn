use std::sync::Arc;
use std::time::Duration;

use tokio::io::{copy_bidirectional, AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::keys::{PublicKey, SecretKey};
use crate::mux::{self, MuxStream};
use crate::noise::{accept, ServerHandshake};
use crate::protocol::{
    read_connect_request, write_connect_response, ConnectRequest, ConnectResponse,
};
use crate::psk::Psk;
use crate::{Error, Result};

#[derive(Clone, Copy, Debug)]
enum PortPattern {
    Any,
    Exact(u16),
}

#[derive(Clone, Debug)]
struct EgressRule {
    host: String,
    port: PortPattern,
}

#[derive(Clone, Debug, Default)]
pub struct Egress {
    rules: Vec<EgressRule>,
}

impl Egress {
    pub fn deny_all() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn parse(entries: &[String]) -> Result<Self> {
        let mut rules = Vec::with_capacity(entries.len());
        for entry in entries {
            let (host, port) = entry
                .rsplit_once(':')
                .ok_or_else(|| Error::Protocol(format!("egress entry missing port: {entry}")))?;
            if host.is_empty() {
                return Err(Error::Protocol(format!("egress entry empty host: {entry}")));
            }
            let port = if port == "*" {
                PortPattern::Any
            } else {
                PortPattern::Exact(
                    port.parse()
                        .map_err(|_| Error::Protocol(format!("egress entry bad port: {entry}")))?,
                )
            };
            rules.push(EgressRule {
                host: host.to_string(),
                port,
            });
        }
        Ok(Self { rules })
    }

    pub fn permits(&self, host: &str, port: u16) -> bool {
        self.rules.iter().any(|rule| {
            rule.host == host
                && match rule.port {
                    PortPattern::Any => true,
                    PortPattern::Exact(p) => p == port,
                }
        })
    }
}

pub struct ServerConfig {
    pub static_secret: SecretKey,
    pub psk: Psk,
    pub allowed_admins: Vec<PublicKey>,
    pub egress: Egress,
    pub handshake_timeout: Duration,
}

pub async fn serve_connection<S>(stream: S, config: Arc<ServerConfig>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let handshake = ServerHandshake {
        static_secret: &config.static_secret,
        psk: &config.psk,
        allowed_admins: &config.allowed_admins,
    };
    let (noise, admin) = tokio::time::timeout(config.handshake_timeout, accept(stream, &handshake))
        .await
        .map_err(|_| Error::Handshake)??;
    tracing::debug!(admin = %admin.to_base64(), "tunnel established");

    let (mut acceptor, driver) = mux::server(noise, mux::config());
    let driver = tokio::spawn(driver);

    while let Some(stream) = acceptor.accept().await {
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(stream, config).await {
                tracing::debug!(error = %e, "stream handler ended");
            }
        });
    }

    driver.abort();
    Ok(())
}

async fn handle_stream(mut stream: MuxStream, config: Arc<ServerConfig>) -> Result<()> {
    let ConnectRequest { host, port } = read_connect_request(&mut stream).await?;

    if !config.egress.permits(&host, port) {
        tracing::info!(%host, port, "egress denied");
        write_connect_response(&mut stream, ConnectResponse::Denied).await?;
        return Ok(());
    }

    match TcpStream::connect((host.as_str(), port)).await {
        Ok(mut target) => {
            let _ = target.set_nodelay(true);
            write_connect_response(&mut stream, ConnectResponse::Ok).await?;
            let _ = copy_bidirectional(&mut stream, &mut target).await;
            Ok(())
        }
        Err(_) => {
            tracing::debug!(%host, port, "target unreachable");
            write_connect_response(&mut stream, ConnectResponse::Unreachable).await?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Keypair;
    use crate::noise::{connect, ClientHandshake};
    use crate::protocol::{read_connect_response, write_connect_request};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn spawn_echo() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut r, mut w) = sock.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        port
    }

    async fn open_request(
        egress: Egress,
        req: ConnectRequest,
    ) -> (ConnectResponse, mux::MuxStream) {
        let admin = Keypair::generate();
        let server = Keypair::generate();
        let config = Arc::new(ServerConfig {
            static_secret: server.secret,
            psk: Psk::from_bytes([8u8; 32]),
            allowed_admins: vec![admin.public],
            egress,
            handshake_timeout: Duration::from_secs(5),
        });
        let server_pub = server.public;

        let (c_io, s_io) = tokio::io::duplex(256 * 1024);
        tokio::spawn(serve_connection(s_io, config));

        let client_hs = ClientHandshake {
            static_secret: &admin.secret,
            server_pubkey: &server_pub,
            psk: &Psk::from_bytes([8u8; 32]),
        };
        let noise = connect(c_io, &client_hs).await.unwrap();
        let (control, driver) = mux::client(noise, mux::config());
        tokio::spawn(driver);

        let mut stream = control.open().await.unwrap();
        write_connect_request(&mut stream, &req).await.unwrap();
        let resp = read_connect_response(&mut stream).await.unwrap();
        (resp, stream)
    }

    #[tokio::test]
    async fn allowed_target_relays_bytes() {
        let port = spawn_echo().await;
        let egress = Egress::parse(&[format!("127.0.0.1:{port}")]).unwrap();
        let (resp, mut stream) = open_request(
            egress,
            ConnectRequest { host: "127.0.0.1".into(), port },
        )
        .await;
        assert_eq!(resp, ConnectResponse::Ok);

        stream.write_all(b"through-the-tunnel").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 18];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"through-the-tunnel");
    }

    #[tokio::test]
    async fn unlisted_target_is_denied() {
        let port = spawn_echo().await;
        let (resp, _stream) = open_request(
            Egress::deny_all(),
            ConnectRequest { host: "127.0.0.1".into(), port },
        )
        .await;
        assert_eq!(resp, ConnectResponse::Denied);
    }

    #[tokio::test]
    async fn dead_target_is_unreachable() {
        let dead = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let egress = Egress::parse(&[format!("127.0.0.1:{dead}")]).unwrap();
        let (resp, _stream) = open_request(
            egress,
            ConnectRequest { host: "127.0.0.1".into(), port: dead },
        )
        .await;
        assert_eq!(resp, ConnectResponse::Unreachable);
    }

    #[test]
    fn egress_matching() {
        let e = Egress::parse(&["127.0.0.1:22".into(), "10.0.0.5:*".into()]).unwrap();
        assert!(e.permits("127.0.0.1", 22));
        assert!(!e.permits("127.0.0.1", 23));
        assert!(e.permits("10.0.0.5", 9999));
        assert!(!e.permits("10.0.0.6", 22));
        assert!(!Egress::deny_all().permits("127.0.0.1", 22));
    }
}

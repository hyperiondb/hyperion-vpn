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

#[derive(Clone, Debug, Default)]
pub struct Egress {
    ports: std::collections::HashSet<u16>,
}

impl Egress {
    pub fn deny_all() -> Self {
        Self::default()
    }

    pub fn new(ports: impl IntoIterator<Item = u16>) -> Self {
        Self {
            ports: ports.into_iter().collect(),
        }
    }

    pub fn permits(&self, port: u16) -> bool {
        self.ports.contains(&port)
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

    let accept_loop = async {
        while let Some(stream) = acceptor.accept().await {
            let config = config.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_stream(stream, config).await {
                    tracing::debug!(error = %e, "stream handler ended");
                }
            });
        }
    };

    tokio::select! {
        res = driver => {
            if let Err(e) = res {
                tracing::debug!(error = %e, "tunnel driver ended");
            }
        }
        _ = accept_loop => {}
    }
    Ok(())
}

async fn handle_stream(mut stream: MuxStream, config: Arc<ServerConfig>) -> Result<()> {
    let ConnectRequest { port } = read_connect_request(&mut stream).await?;

    if !config.egress.permits(port) {
        tracing::info!(port, "egress denied");
        write_connect_response(&mut stream, ConnectResponse::Denied).await?;
        return Ok(());
    }

    match TcpStream::connect(("127.0.0.1", port)).await {
        Ok(mut target) => {
            let _ = target.set_nodelay(true);
            write_connect_response(&mut stream, ConnectResponse::Ok).await?;
            let _ = copy_bidirectional(&mut stream, &mut target).await;
            Ok(())
        }
        Err(_) => {
            tracing::debug!(port, "target unreachable");
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
        let (resp, mut stream) = open_request(Egress::new([port]), ConnectRequest { port }).await;
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
        let (resp, _stream) = open_request(Egress::deny_all(), ConnectRequest { port }).await;
        assert_eq!(resp, ConnectResponse::Denied);
    }

    #[tokio::test]
    async fn dead_target_is_unreachable() {
        let dead = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let (resp, _stream) =
            open_request(Egress::new([dead]), ConnectRequest { port: dead }).await;
        assert_eq!(resp, ConnectResponse::Unreachable);
    }

    #[test]
    fn egress_matching() {
        let e = Egress::new([22, 5432]);
        assert!(e.permits(22));
        assert!(!e.permits(23));
        assert!(e.permits(5432));
        assert!(!Egress::deny_all().permits(22));
    }
}

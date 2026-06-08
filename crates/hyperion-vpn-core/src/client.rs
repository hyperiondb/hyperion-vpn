use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};

use crate::keys::{PublicKey, SecretKey};
use crate::mux::{self, MuxControl, MuxStream};
use crate::noise::{connect, ClientHandshake, NoiseStream};
use crate::protocol::{
    read_connect_response, write_connect_request, ConnectRequest, ConnectResponse,
};
use crate::psk::Psk;
use crate::{Error, Result};

pub struct TunnelParams {
    pub static_secret: SecretKey,
    pub server_pubkey: PublicKey,
    pub psk: Psk,
}

pub async fn dial(addr: SocketAddr, params: &TunnelParams) -> Result<NoiseStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    let _ = tcp.set_nodelay(true);
    let handshake = ClientHandshake {
        static_secret: &params.static_secret,
        server_pubkey: &params.server_pubkey,
        psk: &params.psk,
    };
    connect(tcp, &handshake).await
}

pub struct Pool {
    controls: Vec<MuxControl>,
    next: AtomicUsize,
}

impl Pool {
    pub fn size(&self) -> usize {
        self.controls.len()
    }

    fn control(&self) -> MuxControl {
        let i = self.next.fetch_add(1, Ordering::Relaxed) % self.controls.len();
        self.controls[i].clone()
    }

    pub async fn open(&self) -> Result<MuxStream> {
        self.control().open().await
    }
}

pub async fn build_pool(addr: SocketAddr, params: &TunnelParams, size: usize) -> Result<Pool> {
    let size = size.max(1);
    let mut controls = Vec::with_capacity(size);
    for _ in 0..size {
        let noise = dial(addr, params).await?;
        let (control, driver) = mux::client(noise, mux::config());
        tokio::spawn(driver);
        controls.push(control);
    }
    Ok(Pool {
        controls,
        next: AtomicUsize::new(0),
    })
}

pub async fn forward_one(
    mut local: TcpStream,
    pool: Arc<Pool>,
    target: ConnectRequest,
) -> Result<()> {
    let mut stream = pool.open().await?;
    write_connect_request(&mut stream, &target).await?;
    match read_connect_response(&mut stream).await? {
        ConnectResponse::Ok => {
            let _ = copy_bidirectional(&mut local, &mut stream).await;
            Ok(())
        }
        ConnectResponse::Denied => {
            Err(Error::EgressDenied(format!("{}:{}", target.host, target.port)))
        }
        ConnectResponse::Unreachable => Err(Error::Protocol(format!(
            "{}:{} unreachable",
            target.host, target.port
        ))),
    }
}

pub async fn run_forward(listener: TcpListener, pool: Arc<Pool>, target: ConnectRequest) {
    loop {
        match listener.accept().await {
            Ok((local, _peer)) => {
                let _ = local.set_nodelay(true);
                let pool = pool.clone();
                let target = target.clone();
                tokio::spawn(async move {
                    if let Err(e) = forward_one(local, pool, target).await {
                        tracing::debug!(error = %e, "forward ended");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "local accept failed");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Keypair;
    use crate::server::{serve_connection, Egress, ServerConfig};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    #[tokio::test]
    async fn end_to_end_local_forward_through_tunnel() {
        let echo_port = spawn_echo().await;

        let admin = Keypair::generate();
        let server = Keypair::generate();
        let psk_bytes = [7u8; 32];

        let server_cfg = Arc::new(ServerConfig {
            static_secret: server.secret,
            psk: Psk::from_bytes(psk_bytes),
            allowed_admins: vec![admin.public],
            egress: Egress::parse(&[format!("127.0.0.1:{echo_port}")]).unwrap(),
            handshake_timeout: Duration::from_secs(5),
        });

        let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (sock, _) = server_listener.accept().await.unwrap();
                let cfg = server_cfg.clone();
                tokio::spawn(serve_connection(sock, cfg));
            }
        });

        let params = TunnelParams {
            static_secret: admin.secret,
            server_pubkey: server.public,
            psk: Psk::from_bytes(psk_bytes),
        };
        let pool = Arc::new(build_pool(server_addr, &params, 2).await.unwrap());
        assert_eq!(pool.size(), 2);

        let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_listener.local_addr().unwrap();
        let target = ConnectRequest {
            host: "127.0.0.1".into(),
            port: echo_port,
        };
        tokio::spawn(run_forward(local_listener, pool, target));

        let mut c = TcpStream::connect(local_addr).await.unwrap();
        c.write_all(b"end-to-end").await.unwrap();
        let mut buf = [0u8; 10];
        c.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"end-to-end");

        let mut c2 = TcpStream::connect(local_addr).await.unwrap();
        c2.write_all(b"second-conn").await.unwrap();
        let mut buf2 = [0u8; 11];
        c2.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"second-conn");
    }
}

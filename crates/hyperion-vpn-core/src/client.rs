use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use socket2::{SockRef, TcpKeepalive};
use tokio::io::{copy_bidirectional, AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::task::JoinHandle;

use crate::keys::{PublicKey, SecretKey};
use crate::mux::{self, MuxControl, MuxStream};
use crate::noise::{connect, ClientHandshake, NoiseStream};
use crate::protocol::{
    read_connect_response, write_connect_request, ConnectRequest, ConnectResponse,
};
use crate::psk::Psk;
use crate::{knock, Error, Result};

const KNOCK_RETRY_ATTEMPTS: usize = 6;
const KNOCK_RETRY_DELAY: Duration = Duration::from_millis(150);
const BACKOFF_INITIAL: Duration = Duration::from_millis(250);
const BACKOFF_MAX: Duration = Duration::from_secs(15);
const KEEPALIVE_IDLE: Duration = Duration::from_secs(20);
const OPEN_GRACE_ATTEMPTS: usize = 20;
const OPEN_GRACE_DELAY: Duration = Duration::from_millis(100);

/// Default Linux firewall mark set on the tunnel's own sockets so policy routing can
/// exclude them from the TUN device (the WireGuard-style bypass). See `print-routes`.
pub const DEFAULT_FWMARK: u32 = 0x6879;

#[derive(Clone, Copy)]
pub struct KnockSettings {
    pub port: u16,
}

pub struct TunnelParams {
    pub static_secret: SecretKey,
    pub server_pubkey: PublicKey,
    pub psk: Psk,
    pub knock: Option<KnockSettings>,
    pub fwmark: Option<u32>,
}

#[cfg(target_os = "linux")]
fn apply_mark<S: std::os::fd::AsFd>(sock: &S, fwmark: Option<u32>) {
    if let Some(mark) = fwmark {
        if let Err(e) = SockRef::from(sock).set_mark(mark) {
            tracing::warn!(error = %e, "failed to set SO_MARK on tunnel socket");
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn apply_mark<S>(_sock: &S, _fwmark: Option<u32>) {}

pub async fn send_knock(
    target: SocketAddr,
    psk: &Psk,
    tunnel_port: u16,
    fwmark: Option<u32>,
) -> Result<()> {
    let packet = knock::seal(psk, tunnel_port);
    let bind: SocketAddr = if target.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        ([0u16; 8], 0).into()
    };
    let sock = UdpSocket::bind(bind).await?;
    apply_mark(&sock, fwmark);
    sock.send_to(&packet, target).await?;
    Ok(())
}

async fn connect_once(addr: SocketAddr, fwmark: Option<u32>) -> std::io::Result<TcpStream> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    apply_mark(&socket, fwmark);
    socket.connect(addr).await
}

async fn connect_tcp(addr: SocketAddr, knocked: bool, fwmark: Option<u32>) -> Result<TcpStream> {
    let attempts = if knocked { KNOCK_RETRY_ATTEMPTS } else { 1 };
    let mut last = None;
    for i in 0..attempts {
        match connect_once(addr, fwmark).await {
            Ok(s) => return Ok(s),
            Err(e) => {
                last = Some(e);
                if i + 1 < attempts {
                    tokio::time::sleep(KNOCK_RETRY_DELAY).await;
                }
            }
        }
    }
    Err(Error::Io(last.expect("at least one attempt")))
}

pub async fn dial(addr: SocketAddr, params: &TunnelParams) -> Result<NoiseStream<TcpStream>> {
    if let Some(k) = &params.knock {
        let target = SocketAddr::new(addr.ip(), k.port);
        send_knock(target, &params.psk, addr.port(), params.fwmark).await?;
    }
    let tcp = connect_tcp(addr, params.knock.is_some(), params.fwmark).await?;
    let _ = tcp.set_nodelay(true);
    let _ = SockRef::from(&tcp).set_tcp_keepalive(&TcpKeepalive::new().with_time(KEEPALIVE_IDLE));
    let handshake = ClientHandshake {
        static_secret: &params.static_secret,
        server_pubkey: &params.server_pubkey,
        psk: &params.psk,
    };
    connect(tcp, &handshake).await
}

struct Slot {
    control: Mutex<Option<MuxControl>>,
}

pub struct SupervisedPool {
    slots: Vec<Arc<Slot>>,
    next: AtomicUsize,
    supervisors: Vec<JoinHandle<()>>,
}

impl Drop for SupervisedPool {
    fn drop(&mut self) {
        for h in &self.supervisors {
            h.abort();
        }
    }
}

impl SupervisedPool {
    pub fn size(&self) -> usize {
        self.slots.len()
    }

    pub fn live_slots(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.control.lock().unwrap().is_some())
            .count()
    }

    pub async fn open(&self) -> Result<MuxStream> {
        for _ in 0..OPEN_GRACE_ATTEMPTS {
            for _ in 0..self.slots.len() {
                let i = self.next.fetch_add(1, Ordering::Relaxed) % self.slots.len();
                let control = self.slots[i].control.lock().unwrap().clone();
                if let Some(c) = control {
                    if let Ok(s) = c.open().await {
                        return Ok(s);
                    }
                }
            }
            tokio::time::sleep(OPEN_GRACE_DELAY).await;
        }
        Err(Error::Protocol("no live tunnel to server".into()))
    }
}

fn backoff_jitter() -> Duration {
    let mut b = [0u8; 2];
    let _ = getrandom::fill(&mut b);
    Duration::from_millis(u16::from_le_bytes(b) as u64 % 500)
}

async fn supervise(slot: Arc<Slot>, addr: SocketAddr, params: Arc<TunnelParams>) {
    let mut backoff = BACKOFF_INITIAL;
    loop {
        match dial(addr, &params).await {
            Ok(noise) => {
                let (control, driver) = mux::client(noise, mux::config());
                *slot.control.lock().unwrap() = Some(control);
                backoff = BACKOFF_INITIAL;
                let _ = driver.await;
                *slot.control.lock().unwrap() = None;
                tracing::warn!(%addr, "tunnel dropped; reconnecting");
            }
            Err(e) => {
                tracing::warn!(%addr, error = %e, "tunnel dial failed; backing off");
            }
        }
        tokio::time::sleep(backoff + backoff_jitter()).await;
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

pub async fn build_pool(
    addr: SocketAddr,
    params: TunnelParams,
    size: usize,
    connect_timeout: Duration,
) -> Result<Arc<SupervisedPool>> {
    let size = size.max(1);
    let params = Arc::new(params);
    let mut slots = Vec::with_capacity(size);
    let mut supervisors = Vec::with_capacity(size);
    for _ in 0..size {
        let slot = Arc::new(Slot {
            control: Mutex::new(None),
        });
        slots.push(slot.clone());
        supervisors.push(tokio::spawn(supervise(slot, addr, params.clone())));
    }
    let pool = Arc::new(SupervisedPool {
        slots,
        next: AtomicUsize::new(0),
        supervisors,
    });

    let pool_for_wait = pool.clone();
    let wait = async move {
        loop {
            if pool_for_wait.live_slots() > 0 {
                return;
            }
            tokio::time::sleep(OPEN_GRACE_DELAY).await;
        }
    };
    match tokio::time::timeout(connect_timeout, wait).await {
        Ok(()) => Ok(pool),
        Err(_) => Err(Error::Protocol(format!("timed out connecting to {addr}"))),
    }
}

pub async fn forward_one<L>(mut local: L, pool: Arc<SupervisedPool>, port: u16) -> Result<()>
where
    L: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = pool.open().await?;
    write_connect_request(&mut stream, &ConnectRequest { port }).await?;
    match read_connect_response(&mut stream).await? {
        ConnectResponse::Ok => {
            let _ = copy_bidirectional(&mut local, &mut stream).await;
            Ok(())
        }
        ConnectResponse::Denied => Err(Error::EgressDenied(format!("port {port}"))),
        ConnectResponse::Unreachable => Err(Error::Protocol(format!("port {port} unreachable"))),
    }
}

pub async fn run_forward(listener: TcpListener, pool: Arc<SupervisedPool>, port: u16) {
    loop {
        match listener.accept().await {
            Ok((local, _peer)) => {
                let _ = local.set_nodelay(true);
                let pool = pool.clone();
                tokio::spawn(async move {
                    if let Err(e) = forward_one(local, pool, port).await {
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
            egress: Egress::new([echo_port]),
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
            knock: None,
            fwmark: None,
        };
        let pool = build_pool(server_addr, params, 2, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(pool.size(), 2);

        let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_listener.local_addr().unwrap();
        tokio::spawn(run_forward(local_listener, pool, echo_port));

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

    #[tokio::test]
    async fn udp_knock_send_then_open() {
        use crate::knock::{open, ReplayGuard, DEFAULT_WINDOW_SECS};
        use std::time::{SystemTime, UNIX_EPOCH};

        let psk = Psk::from_bytes([6u8; 32]);
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();

        send_knock(addr, &psk, 8443, None).await.unwrap();

        let mut buf = vec![0u8; 128];
        let (n, _from) = server.recv_from(&mut buf).await.unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut guard = ReplayGuard::new(DEFAULT_WINDOW_SECS);
        let k = open(&psk, &buf[..n], now, &mut guard).unwrap();
        assert_eq!(k.tunnel_port, 8443);
    }

    async fn try_roundtrip(local: SocketAddr, msg: &[u8]) -> bool {
        let Ok(mut c) = TcpStream::connect(local).await else {
            return false;
        };
        if c.write_all(msg).await.is_err() {
            return false;
        }
        let mut buf = vec![0u8; msg.len()];
        matches!(
            tokio::time::timeout(Duration::from_secs(2), c.read_exact(&mut buf)).await,
            Ok(Ok(_))
        ) && buf == msg
    }

    async fn bind_retry(addr: SocketAddr) -> TcpListener {
        for _ in 0..50 {
            if let Ok(l) = TcpListener::bind(addr).await {
                return l;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("could not rebind {addr}");
    }

    #[tokio::test]
    async fn pool_recovers_after_server_restart() {
        use tokio::sync::Notify;

        let echo_port = spawn_echo().await;
        let admin = Keypair::generate();
        let server = Keypair::generate();
        let psk_bytes = [9u8; 32];
        let server_pub = server.public;
        let make_cfg = || {
            Arc::new(ServerConfig {
                static_secret: server.secret.clone(),
                psk: Psk::from_bytes(psk_bytes),
                allowed_admins: vec![admin.public],
                egress: Egress::new([echo_port]),
                handshake_timeout: Duration::from_secs(5),
            })
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let kill = Arc::new(Notify::new());
        {
            let cfg = make_cfg();
            let kill = kill.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = kill.notified() => break,
                        res = listener.accept() => {
                            if let Ok((sock, _)) = res {
                                let cfg = cfg.clone();
                                let kill = kill.clone();
                                tokio::spawn(async move {
                                    tokio::select! {
                                        _ = serve_connection(sock, cfg) => {}
                                        _ = kill.notified() => {}
                                    }
                                });
                            }
                        }
                    }
                }
            });
        }

        let params = TunnelParams {
            static_secret: admin.secret.clone(),
            server_pubkey: server_pub,
            psk: Psk::from_bytes(psk_bytes),
            knock: None,
            fwmark: None,
        };
        let pool = build_pool(addr, params, 1, Duration::from_secs(5))
            .await
            .unwrap();

        let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_listener.local_addr().unwrap();
        tokio::spawn(run_forward(local_listener, pool.clone(), echo_port));

        assert!(
            try_roundtrip(local_addr, b"before").await,
            "initial round-trip failed"
        );

        kill.notify_waiters();

        let listener2 = bind_retry(addr).await;
        let cfg2 = make_cfg();
        tokio::spawn(async move {
            loop {
                if let Ok((sock, _)) = listener2.accept().await {
                    tokio::spawn(serve_connection(sock, cfg2.clone()));
                }
            }
        });

        let recovered = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if try_roundtrip(local_addr, b"after").await {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await;
        assert!(recovered.is_ok(), "pool did not recover after server restart");
    }
}

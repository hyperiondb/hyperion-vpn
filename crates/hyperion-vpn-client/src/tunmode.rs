use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::Context as _;
use hyperion_vpn_core::client::{build_pool, forward_one, SupervisedPool, DEFAULT_FWMARK};
use ipstack::{IpStack, IpStackConfig, IpStackStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tun_rs::{AsyncDevice, DeviceBuilder};

struct TunIo(AsyncDevice);

impl AsyncRead for TunIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let unfilled = buf.initialize_unfilled();
        match this.0.poll_recv(cx, unfilled) {
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TunIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.get_mut().0.poll_send(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

type Routes = Arc<HashMap<IpAddr, Arc<SupervisedPool>>>;

async fn serve(device: AsyncDevice, routes: Routes, mtu: u16) -> anyhow::Result<()> {
    let mut ipstack_cfg = IpStackConfig::default();
    let _ = ipstack_cfg.mtu(mtu);
    let mut ip_stack = IpStack::new(ipstack_cfg, TunIo(device));

    loop {
        match ip_stack.accept().await? {
            IpStackStream::Tcp(tcp) => {
                let dest = tcp.local_addr();
                match routes.get(&dest.ip()).cloned() {
                    Some(pool) => {
                        let port = dest.port();
                        tokio::spawn(async move {
                            if let Err(e) = forward_one(tcp, pool, port).await {
                                tracing::debug!(error = %e, "tun forward ended");
                            }
                        });
                    }
                    None => tracing::debug!(%dest, "no tunnel for destination IP; dropping"),
                }
            }
            IpStackStream::Udp(_) => {
                tracing::trace!("UDP not supported over the TCP tunnel; dropping");
            }
            _ => {}
        }
    }
}

pub async fn run_managed(cfg: crate::config::LoadedClient) -> anyhow::Result<()> {
    if cfg.servers.is_empty() {
        anyhow::bail!("no servers configured; add one with `hyperion-client add-server`");
    }

    let connect_timeout = Duration::from_secs(10);
    let mut routes: HashMap<IpAddr, Arc<SupervisedPool>> = HashMap::new();
    for (name, entry) in cfg.servers {
        let vip = IpAddr::V4(entry.virtual_ip);
        let real = entry.addr;
        let pool = build_pool(real, entry.params, entry.pool_size);
        if pool.wait_connected(connect_timeout).await {
            tracing::info!(server = %name, %real, virtual_ip = %vip, "tunnel up");
        } else {
            tracing::warn!(
                server = %name,
                %real,
                virtual_ip = %vip,
                "not reachable yet; retrying in background"
            );
        }
        routes.insert(vip, pool);
    }

    let addr = cfg.tun.addr.to_string();
    let device = DeviceBuilder::new()
        .name("hyperion0")
        .ipv4(addr.as_str(), cfg.tun.prefix, None)
        .mtu(cfg.tun.mtu)
        .build_async()
        .context("creating TUN device (needs Administrator on Windows / root on Linux)")?;

    tracing::info!(
        tun = %addr,
        "hyperion0 up; reach each server at its fake IP (see `hyperion-client status`)"
    );

    serve(device, Arc::new(routes), cfg.tun.mtu).await
}

pub async fn run(config_path: &str, tun_addr: &str, prefix: u8, mtu: u16) -> anyhow::Result<()> {
    let cfg = crate::config::load(config_path)?;
    if cfg.servers.is_empty() {
        anyhow::bail!("no servers configured");
    }

    let connect_timeout = Duration::from_secs(10);
    let mut routes: HashMap<IpAddr, Arc<SupervisedPool>> = HashMap::new();
    for (name, mut entry) in cfg.servers {
        let ip = entry.addr.ip();
        entry.params.fwmark = Some(DEFAULT_FWMARK);
        let pool = build_pool(entry.addr, entry.params, entry.pool_size);
        if pool.wait_connected(connect_timeout).await {
            tracing::info!(server = %name, %ip, "tunnel up; route this IP via the tun device");
        } else {
            tracing::warn!(server = %name, %ip, "not reachable yet; retrying in background");
        }
        routes.insert(ip, pool);
    }

    let device = DeviceBuilder::new()
        .name("hyperion0")
        .ipv4(tun_addr, prefix, None)
        .mtu(mtu)
        .build_async()
        .context("creating TUN device (needs root / CAP_NET_ADMIN)")?;

    tracing::warn!(
        "L3 TUN mode active on 'hyperion0'. You MUST route each server IP via this device AND \
         exclude the tunnel's own sockets from it (fwmark + policy routing), or the tunnel loops. \
         See README 'L3 TUN mode'."
    );

    serve(device, Arc::new(routes), mtu).await
}

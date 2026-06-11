use std::time::Duration;

use hyperion_vpn_cli_common as common;
use hyperion_vpn_core::server::serve_connection;
use tokio::net::TcpListener;

use crate::config;

const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

pub async fn run(config_path: &str) -> anyhow::Result<()> {
    let cfg = config::load(config_path)?;
    start_spa(cfg.knock);
    let listener = TcpListener::bind(cfg.listen).await?;
    tracing::info!(listen = %cfg.listen, "hyperion-server listening");

    let server = cfg.server;
    loop {
        tokio::select! {
            _ = common::shutdown_signal() => {
                tracing::info!("shutdown signal received");
                break;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((sock, peer)) => {
                        let _ = sock.set_nodelay(true);
                        let server = server.clone();
                        tokio::spawn(async move {
                            if let Err(e) = serve_connection(sock, server).await {
                                tracing::debug!(%peer, error = %e, "connection ended");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed; retrying");
                        tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                    }
                }
            }
        }
    }
    Ok(())
}

fn start_spa(knock: Option<config::KnockRuntime>) {
    let Some(k) = knock else { return };
    #[cfg(target_os = "linux")]
    {
        let fw = crate::firewall::Firewall::new(k.table, k.set, k.ttl_secs);
        let knock_port = k.knock_port;
        let tunnel_port = k.tunnel_port;
        let psk = k.psk;
        let server_pub = k.server_pub;
        let window = k.window_secs;
        let cooldown = (k.ttl_secs / 2).max(1);
        tokio::task::spawn_blocking(move || {
            if let Err(e) = crate::sniffer::run_blocking(
                knock_port,
                tunnel_port,
                psk,
                server_pub,
                window,
                cooldown,
                fw,
            ) {
                tracing::error!(error = %e, "SPA sniffer stopped");
            }
        });
        tracing::info!(knock_port, "SPA enabled (port-knock gating active)");
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = k;
        tracing::warn!(
            "knock.enabled = true but SPA (AF_PACKET + nftables) is Linux-only; \
             running WITHOUT port-knock gating"
        );
    }
}

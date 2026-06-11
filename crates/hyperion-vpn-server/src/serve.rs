use hyperion_vpn_core::server::serve_connection;
use tokio::net::TcpListener;

use crate::config;

pub async fn run(config_path: &str) -> anyhow::Result<()> {
    let cfg = config::load(config_path)?;
    start_spa(cfg.knock);
    let listener = TcpListener::bind(cfg.listen).await?;
    tracing::info!(listen = %cfg.listen, "hyperion-server listening");

    let server = cfg.server;
    loop {
        tokio::select! {
            _ = shutdown_signal() => {
                tracing::info!("shutdown signal received");
                break;
            }
            accepted = listener.accept() => {
                let (sock, peer) = accepted?;
                let _ = sock.set_nodelay(true);
                let server = server.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_connection(sock, server).await {
                        tracing::debug!(%peer, error = %e, "connection ended");
                    }
                });
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
        let psk = k.psk;
        let window = k.window_secs;
        tokio::task::spawn_blocking(move || {
            if let Err(e) = crate::sniffer::run_blocking(knock_port, psk, window, fw) {
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

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        tokio::select! {
            _ = ctrl_c => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        ctrl_c.await;
    }
}

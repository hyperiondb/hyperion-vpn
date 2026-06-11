use std::time::{SystemTime, UNIX_EPOCH};

use hyperion_vpn_core::knock::{self, ReplayGuard};
use hyperion_vpn_core::packet;
use hyperion_vpn_core::psk::Psk;

use crate::firewall::Firewall;

pub fn run_blocking(
    knock_port: u16,
    psk: Psk,
    window_secs: u64,
    firewall: Firewall,
) -> anyhow::Result<()> {
    let proto = (libc::ETH_P_ALL as u16).to_be() as libc::c_int;
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    let mut guard = ReplayGuard::new(window_secs);
    let mut buf = vec![0u8; 65536];
    tracing::info!(knock_port, "SPA sniffer started (AF_PACKET, no bound port)");

    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            tracing::warn!(error = %err, "AF_PACKET recv failed");
            continue;
        }
        if n == 0 {
            continue;
        }

        let frame = &buf[..n as usize];
        let Some((src, dst_port, payload)) = packet::parse_ethernet_ipv4_udp(frame) else {
            continue;
        };
        if dst_port != knock_port {
            continue;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        match knock::open(&psk, payload, now, &mut guard) {
            Ok(k) => {
                if k.tunnel_port != knock_port {
                    tracing::debug!(
                        requested = k.tunnel_port,
                        "knock for non-listening port; ignoring"
                    );
                    continue;
                }
                match firewall.allow(src) {
                    Ok(()) => {
                        tracing::info!(%src, port = k.tunnel_port, "knock accepted; firewall opened")
                    }
                    Err(e) => tracing::error!(%src, error = %e, "firewall allow failed"),
                }
            }
            Err(_) => {}
        }
    }
}

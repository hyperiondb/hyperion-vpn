use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use hyperion_vpn_core::keys::PublicKey;
use hyperion_vpn_core::knock::{self, KnockVerifier};
use hyperion_vpn_core::packet;
use hyperion_vpn_core::psk::Psk;

use crate::firewall::Firewall;

const RECENT_ALLOW_CAP: usize = 4096;

fn bpf(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

fn attach_knock_filter(fd: libc::c_int, knock_port: u16) -> std::io::Result<()> {
    let mut prog = [
        bpf(0x28, 0, 0, 12),
        bpf(0x15, 0, 8, 0x0800),
        bpf(0x30, 0, 0, 23),
        bpf(0x15, 0, 6, 17),
        bpf(0x28, 0, 0, 20),
        bpf(0x45, 4, 0, 0x1fff),
        bpf(0xb1, 0, 0, 14),
        bpf(0x48, 0, 0, 16),
        bpf(0x15, 0, 1, u32::from(knock_port)),
        bpf(0x06, 0, 0, 0x0004_0000),
        bpf(0x06, 0, 0, 0),
    ];
    let fprog = libc::sock_fprog {
        len: prog.len() as libc::c_ushort,
        filter: prog.as_mut_ptr(),
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &fprog as *const libc::sock_fprog as *const libc::c_void,
            std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn run_blocking(
    knock_port: u16,
    tunnel_port: u16,
    psk: Psk,
    server_pub: PublicKey,
    window_secs: u64,
    allow_cooldown_secs: u64,
    firewall: Firewall,
) -> anyhow::Result<()> {
    let proto = (libc::ETH_P_ALL as u16).to_be() as libc::c_int;
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    match attach_knock_filter(fd, knock_port) {
        Ok(()) => tracing::debug!(knock_port, "BPF knock filter attached"),
        Err(e) => tracing::warn!(error = %e, "BPF filter attach failed; sniffing unfiltered"),
    }

    let mut verifier = KnockVerifier::new(&psk, &server_pub, window_secs);
    let mut recent_allows: HashMap<Ipv4Addr, u64> = HashMap::new();
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
        if dst_port != knock_port || payload.len() != knock::PACKET_LEN {
            continue;
        }

        let now = now_unix();

        let Ok(k) = verifier.open(payload, now) else {
            continue;
        };
        if k.tunnel_port != tunnel_port {
            tracing::debug!(
                requested = k.tunnel_port,
                "knock for non-listening port; ignoring"
            );
            continue;
        }
        if recent_allows
            .get(&src)
            .is_some_and(|t| now.saturating_sub(*t) < allow_cooldown_secs)
        {
            continue;
        }
        if recent_allows.len() >= RECENT_ALLOW_CAP {
            recent_allows.retain(|_, t| now.saturating_sub(*t) < allow_cooldown_secs);
        }
        match firewall.allow(src) {
            Ok(()) => {
                recent_allows.insert(src, now);
                tracing::info!(%src, port = k.tunnel_port, "knock accepted; firewall opened")
            }
            Err(e) => tracing::error!(%src, error = %e, "firewall allow failed"),
        }
    }
}

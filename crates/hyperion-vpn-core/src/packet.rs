use std::net::Ipv4Addr;

pub const ETHERNET_HEADER_LEN: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const IPPROTO_UDP: u8 = 17;

pub fn parse_ipv4_udp(ip: &[u8]) -> Option<(Ipv4Addr, u16, &[u8])> {
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ip.len() < ihl || ip[9] != IPPROTO_UDP {
        return None;
    }
    let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let udp = &ip[ihl..];
    if udp.len() < 8 {
        return None;
    }
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp_len > udp.len() {
        return None;
    }
    Some((src, dst_port, &udp[8..udp_len]))
}

pub fn parse_ethernet_ipv4_udp(frame: &[u8]) -> Option<(Ipv4Addr, u16, &[u8])> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != ETHERTYPE_IPV4 {
        return None;
    }
    parse_ipv4_udp(&frame[ETHERNET_HEADER_LEN..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_frame(src: [u8; 4], dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0xff; 6]);
        f.extend_from_slice(&[0xaa; 6]);
        f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[9] = IPPROTO_UDP;
        ip[12..16].copy_from_slice(&src);
        let udp_len = 8 + payload.len();
        let mut udp = vec![0u8; 8];
        udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        udp.extend_from_slice(payload);
        f.extend_from_slice(&ip);
        f.extend_from_slice(&udp);
        f
    }

    #[test]
    fn parses_knock_frame() {
        let frame = build_frame([203, 0, 113, 7], 8443, b"knock-bytes");
        let (src, port, payload) = parse_ethernet_ipv4_udp(&frame).unwrap();
        assert_eq!(src, Ipv4Addr::new(203, 0, 113, 7));
        assert_eq!(port, 8443);
        assert_eq!(payload, b"knock-bytes");
    }

    #[test]
    fn trims_ethernet_padding() {
        let mut frame = build_frame([10, 0, 0, 1], 9000, b"abc");
        frame.extend_from_slice(&[0u8; 20]);
        let (_, _, payload) = parse_ethernet_ipv4_udp(&frame).unwrap();
        assert_eq!(payload, b"abc");
    }

    #[test]
    fn rejects_non_ipv4_and_non_udp() {
        let mut tcp = build_frame([10, 0, 0, 1], 9000, b"x");
        tcp[ETHERNET_HEADER_LEN + 9] = 6;
        assert!(parse_ethernet_ipv4_udp(&tcp).is_none());
        assert!(parse_ethernet_ipv4_udp(&[0u8; 4]).is_none());
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        let mut buf = [0u8; 128];
        for _ in 0..5000 {
            getrandom::fill(&mut buf).unwrap();
            let len = buf[0] as usize % buf.len();
            let _ = parse_ethernet_ipv4_udp(&buf[..len]);
            let _ = parse_ipv4_udp(&buf[..len]);
        }
    }
}

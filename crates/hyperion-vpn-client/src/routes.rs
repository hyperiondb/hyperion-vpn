use std::fmt::Write as _;
use std::net::IpAddr;

pub struct RouteParams<'a> {
    pub server_ips: &'a [IpAddr],
    pub dev: &'a str,
    pub mark: u32,
    pub table: u32,
    pub priority: u32,
    pub down: bool,
}

pub fn script(p: &RouteParams) -> String {
    let mut out = String::from("#!/bin/sh\nset -e\n");
    if p.down {
        let _ = writeln!(out, "# Hyperion L3 TUN routing — teardown");
        for ip in p.server_ips {
            let _ = writeln!(
                out,
                "ip rule del to {ip}/32 not fwmark {mark:#x} lookup {table} priority {prio}",
                mark = p.mark,
                table = p.table,
                prio = p.priority
            );
            let _ = writeln!(
                out,
                "ip route del {ip}/32 dev {dev} table {table}",
                dev = p.dev,
                table = p.table
            );
        }
    } else {
        let _ = writeln!(
            out,
            "# Hyperion L3 TUN routing — route each server IP via '{}', except the tunnel's own",
            p.dev
        );
        let _ = writeln!(
            out,
            "# (SO_MARK {:#x}) sockets, which keep the physical route.",
            p.mark
        );
        for ip in p.server_ips {
            let _ = writeln!(
                out,
                "ip route add {ip}/32 dev {dev} table {table}",
                dev = p.dev,
                table = p.table
            );
            let _ = writeln!(
                out,
                "ip rule add to {ip}/32 not fwmark {mark:#x} lookup {table} priority {prio}",
                mark = p.mark,
                table = p.table,
                prio = p.priority
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ips() -> Vec<IpAddr> {
        vec![
            "203.0.113.10".parse().unwrap(),
            "203.0.113.11".parse().unwrap(),
        ]
    }

    #[test]
    fn up_script_routes_and_excludes_marked() {
        let ips = ips();
        let s = script(&RouteParams {
            server_ips: &ips,
            dev: "hyperion0",
            mark: 0x6879,
            table: 26745,
            priority: 100,
            down: false,
        });
        assert!(s.contains("ip route add 203.0.113.10/32 dev hyperion0 table 26745"));
        assert!(s.contains(
            "ip rule add to 203.0.113.11/32 not fwmark 0x6879 lookup 26745 priority 100"
        ));
    }

    #[test]
    fn down_script_uses_del() {
        let ips = ips();
        let s = script(&RouteParams {
            server_ips: &ips,
            dev: "hyperion0",
            mark: 0x6879,
            table: 26745,
            priority: 100,
            down: true,
        });
        assert!(s.contains("ip rule del to 203.0.113.10/32"));
        assert!(s.contains("ip route del 203.0.113.10/32 dev hyperion0 table 26745"));
    }
}

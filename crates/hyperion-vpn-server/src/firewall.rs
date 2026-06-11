use std::net::Ipv4Addr;

#[derive(Clone)]
pub struct Firewall {
    table: String,
    set: String,
    ttl_secs: u64,
}

impl Firewall {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn new(table: String, set: String, ttl_secs: u64) -> Self {
        Self {
            table,
            set,
            ttl_secs,
        }
    }

    pub fn add_element_args(&self, ip: Ipv4Addr) -> Vec<String> {
        vec![
            "add".into(),
            "element".into(),
            "inet".into(),
            self.table.clone(),
            self.set.clone(),
            format!("{{ {ip} timeout {}s }}", self.ttl_secs),
        ]
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn allow(&self, ip: Ipv4Addr) -> std::io::Result<()> {
        let status = std::process::Command::new("nft")
            .args(self.add_element_args(ip))
            .status()?;
        if !status.success() {
            return Err(std::io::Error::other(format!("nft exited with {status}")));
        }
        Ok(())
    }
}

pub fn base_ruleset(table: &str, set: &str, tunnel_port: u16) -> String {
    format!(
        "table inet {table} {{\n  \
           set {set} {{ type ipv4_addr; flags timeout; }}\n  \
           chain input {{\n    \
             type filter hook input priority 0; policy drop;\n    \
             ct state established,related accept\n    \
             iif lo accept\n    \
             ip saddr @{set} tcp dport {tunnel_port} accept\n  \
           }}\n\
         }}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_element_args_builds_nft_command() {
        let fw = Firewall::new("hyperion".into(), "knock_allow".into(), 30);
        let args = fw.add_element_args("203.0.113.7".parse().unwrap());
        assert_eq!(
            args,
            vec![
                "add",
                "element",
                "inet",
                "hyperion",
                "knock_allow",
                "{ 203.0.113.7 timeout 30s }"
            ]
        );
    }

    #[test]
    fn base_ruleset_has_drop_policy_and_gated_port() {
        let r = base_ruleset("hyperion", "knock_allow", 8443);
        assert!(r.contains("policy drop"));
        assert!(r.contains("ip saddr @knock_allow tcp dport 8443 accept"));
        assert!(r.contains("ct state established,related accept"));
    }
}

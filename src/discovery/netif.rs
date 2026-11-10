//! Which of this device's network addresses to advertise, and which of a
//! peer's addresses to try first (issue #32).
//!
//! Windows PCs with WSL or Hyper-V, and Macs or Linux boxes with Docker or
//! a VPN, have virtual adapters whose addresses other devices can't reach
//! (WSL's `vEthernet (WSL)` at 172.28.80.1, for example). We leave those
//! adapters out of mDNS entirely, and when a peer still advertises several
//! addresses (an older build, say), we try the ones on a network we share
//! first.

use std::net::IpAddr;

/// One address of one of this device's network interfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAddr {
    /// The interface's name: `en0`, `eth0`, or on Windows its friendly name
    /// such as `Wi-Fi` or `vEthernet (WSL)`.
    pub name: String,
    pub ip: IpAddr,
    /// Network prefix length (24 for a 255.255.255.0 netmask).
    pub prefix: u8,
}

impl LocalAddr {
    pub fn new(name: &str, ip: &str, prefix: u8) -> Self {
        Self {
            name: name.to_owned(),
            ip: ip.parse().expect("valid IP"),
            prefix,
        }
    }

    /// Whether `ip` is on this address's network.
    pub fn same_network(&self, ip: &IpAddr) -> bool {
        match (self.ip, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let bits = u32::from(self.prefix.min(32));
                let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
                u32::from(a) & mask == u32::from(*b) & mask
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let bits = u32::from(self.prefix.min(128));
                let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
                u128::from(a) & mask == u128::from(*b) & mask
            }
            _ => false,
        }
    }

    pub fn is_virtual(&self) -> bool {
        is_virtual(&self.name)
    }
}

/// Whether an interface name looks like a virtual adapter (WSL, Hyper-V,
/// Docker, VMs, VPNs, Apple's peer-to-peer links) rather than the Wi-Fi or
/// Ethernet connection other devices on the LAN can reach.
pub fn is_virtual(name: &str) -> bool {
    let name = name.to_lowercase();
    // Windows friendly names and descriptive names.
    const CONTAINS: &[&str] = &[
        "vethernet",
        "wsl",
        "hyper-v",
        "virtualbox",
        "vmware",
        "docker",
        "tailscale",
        "zerotier",
        "wireguard",
        "openvpn",
        "vpn",
        "npcap",
        "loopback pseudo",
        "bluetooth",
    ];
    // Unix interface names.
    const PREFIXES: &[&str] = &[
        "docker", "br-", "veth", "virbr", "vboxnet", "vmnet", "utun", "tun", "tap", "wg", "zt",
        "awdl", "llw", "anpi", "bridge", "gif", "stf", "ap1",
    ];
    CONTAINS.iter().any(|s| name.contains(s)) || PREFIXES.iter().any(|p| name.starts_with(p))
}

/// How usable an address is on its own: LAN IPv4 first (the listener is
/// IPv4-only, and IPv6 link-local needs an interface scope we don't track),
/// then link-local and loopback IPv4, then IPv6.
fn class(ip: &IpAddr) -> u8 {
    match ip {
        IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_link_local() => 0,
        IpAddr::V4(v4) if v4.is_link_local() => 1,
        IpAddr::V4(_) => 2,
        IpAddr::V6(v6) if !v6.is_loopback() && !v6.is_unicast_link_local() => 3,
        IpAddr::V6(_) => 4,
    }
}

/// This device's addresses, best first: physical adapters before virtual
/// ones, LAN IPv4 before the rest.
pub fn rank_local(mut addrs: Vec<LocalAddr>) -> Vec<LocalAddr> {
    addrs.sort_by_key(|a| (a.is_virtual(), class(&a.ip)));
    addrs
}

/// A peer's addresses, best first: by [`class`], and within a class the ones
/// on a network one of our physical adapters is on. The sort is stable, so
/// otherwise the peer's order stands.
pub fn rank_peer(mut addrs: Vec<IpAddr>, local: &[LocalAddr]) -> Vec<IpAddr> {
    let shared = |ip: &IpAddr| {
        local
            .iter()
            .any(|l| !l.is_virtual() && class(&l.ip) == 0 && l.same_network(ip))
    };
    addrs.sort_by_key(|ip| (class(ip), !shared(ip)));
    addrs
}

/// The address to tell people to use: the best physical LAN IPv4.
pub fn best_lan_ip(local: &[LocalAddr]) -> Option<IpAddr> {
    rank_local(local.to_vec())
        .into_iter()
        .find(|a| !a.is_virtual() && class(&a.ip) == 0)
        .map(|a| a.ip)
}

/// This device's interface addresses that are up. Empty if they can't be
/// listed.
pub fn local_addrs() -> Vec<LocalAddr> {
    let Ok(interfaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    interfaces
        .into_iter()
        .filter(|i| i.oper_status != if_addrs::IfOperStatus::Down)
        .map(|i| {
            let (ip, prefix) = match &i.addr {
                if_addrs::IfAddr::V4(a) => (IpAddr::V4(a.ip), prefix_len(a.netmask.octets())),
                if_addrs::IfAddr::V6(a) => (IpAddr::V6(a.ip), prefix_len(a.netmask.octets())),
            };
            LocalAddr {
                name: i.name,
                ip,
                prefix,
            }
        })
        .collect()
}

fn prefix_len(mask: impl AsRef<[u8]>) -> u8 {
    mask.as_ref().iter().map(|b| b.count_ones() as u8).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pc() -> Vec<LocalAddr> {
        vec![
            LocalAddr::new("vEthernet (WSL)", "172.28.80.1", 20),
            LocalAddr::new("Wi-Fi", "fe80::1c2d:3e4f:5a6b:7c8d", 64),
            LocalAddr::new("Wi-Fi", "192.168.1.177", 24),
            LocalAddr::new("Loopback Pseudo-Interface 1", "127.0.0.1", 8),
        ]
    }

    /// Acceptance (#32): Wi-Fi 192.168.1.177, vEthernet (WSL) 172.28.80.1
    /// and IPv6 fe80::… pick 192.168.1.177 first.
    #[test]
    fn the_wifi_address_beats_wsl_and_ipv6() {
        let ranked = rank_local(pc());
        assert_eq!(ranked[0].ip.to_string(), "192.168.1.177");
        let names: Vec<&str> = ranked.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names[..2], ["Wi-Fi", "Wi-Fi"], "{ranked:?}");
        assert_eq!(names[2], "vEthernet (WSL)", "{ranked:?}");
        assert_eq!(best_lan_ip(&pc()), Some("192.168.1.177".parse().unwrap()));
        // Whatever order the OS lists them in.
        let mut reversed = pc();
        reversed.reverse();
        assert_eq!(rank_local(reversed)[0].ip.to_string(), "192.168.1.177");
    }

    #[test]
    fn virtual_adapters_are_recognised() {
        for name in [
            "vEthernet (WSL)",
            "vEthernet (Default Switch)",
            "vEthernet (WSL (Hyper-V firewall))",
            "VirtualBox Host-Only Network",
            "VMware Network Adapter VMnet8",
            "docker0",
            "br-3f2a9c1e5b7d",
            "veth12ab",
            "utun3",
            "awdl0",
            "llw0",
            "Tailscale",
            "wg0",
            "Bluetooth Network Connection",
        ] {
            assert!(is_virtual(name), "{name}");
        }
        for name in [
            "Wi-Fi",
            "Ethernet",
            "Ethernet 2",
            "en0",
            "en1",
            "eth0",
            "wlan0",
            "wlp2s0",
            "enp3s0",
        ] {
            assert!(!is_virtual(name), "{name}");
        }
    }

    /// The Mac (192.168.1.53/24) choosing among an old PC build's addresses:
    /// the one on its own network goes first, though 172.x sorts lower.
    #[test]
    fn a_peer_address_on_our_network_goes_first() {
        let mac = vec![
            LocalAddr::new("en0", "192.168.1.53", 24),
            LocalAddr::new("bridge100", "172.28.80.9", 20),
        ];
        let advertised: Vec<IpAddr> = ["172.28.80.1", "fe80::1", "192.168.1.177"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let ranked = rank_peer(advertised, &mac);
        assert_eq!(ranked[0].to_string(), "192.168.1.177");
        assert_eq!(ranked[1].to_string(), "172.28.80.1");
        assert_eq!(ranked[2].to_string(), "fe80::1");
        // Knowing nothing about our own interfaces keeps the peer's order.
        let ranked = rank_peer(
            vec![
                "10.0.0.2".parse().unwrap(),
                "192.168.1.177".parse().unwrap(),
            ],
            &[],
        );
        assert_eq!(ranked[0].to_string(), "10.0.0.2");
    }

    #[test]
    fn networks_compare_by_prefix() {
        let wifi = LocalAddr::new("en0", "192.168.1.53", 24);
        assert!(wifi.same_network(&"192.168.1.177".parse().unwrap()));
        assert!(!wifi.same_network(&"192.168.2.177".parse().unwrap()));
        assert!(!wifi.same_network(&"fe80::1".parse().unwrap()));
        let wide = LocalAddr::new("en0", "10.1.2.3", 8);
        assert!(wide.same_network(&"10.200.0.1".parse().unwrap()));
        assert_eq!(prefix_len([255, 255, 240, 0]), 20);
    }
}

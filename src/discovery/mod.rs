//! Device discovery over mDNS (`_opendrop._tcp.local.`).
//!
//! Every device advertises one service instance named after its device id,
//! with its TCP port and these TXT properties:
//!
//! | Key | Value |
//! |---|---|
//! | `device_id` | stable id from [`DeviceIdentity`] |
//! | `device_name` | display name, at most [`MAX_NAME_LEN`] bytes |
//! | `protocol_version` | [`PROTOCOL_VERSION`] |
//!
//! At the same time it browses for other instances and keeps a table of the
//! peers it has resolved, dropping them when their advertisement goes away.
//! Our own advertisement is ignored.

pub mod netif;

use crate::network::{BoxError, DeviceIdentity};
use crate::protocol::PROTOCOL_VERSION;
use mdns_sd::{IfKind, ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;

/// mDNS service type every OpenDrop device advertises.
pub const SERVICE_TYPE: &str = "_opendrop._tcp.local.";

/// TXT values are limited to 255 bytes including the key, so long display
/// names are cut short (on a character boundary) before advertising.
pub const MAX_NAME_LEN: usize = 200;

const TXT_DEVICE_ID: &str = "device_id";
const TXT_DEVICE_NAME: &str = "device_name";
const TXT_PROTOCOL_VERSION: &str = "protocol_version";

/// A device found on the local network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub id: String,
    pub name: String,
    pub protocol_version: u32,
    pub addresses: Vec<IpAddr>,
    pub port: u16,
}

impl Peer {
    /// The best address to connect to; see [`Peer::socket_addrs`].
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.socket_addrs().into_iter().next()
    }

    /// Every advertised address, best first: LAN IPv4 before the rest
    /// (the listener is IPv4-only, and IPv6 link-local addresses would need
    /// an interface scope we don't track), and among those the ones on a
    /// network we're on (so a PC's Wi-Fi address beats its WSL adapter's).
    pub fn socket_addrs(&self) -> Vec<SocketAddr> {
        self.socket_addrs_from(&netif::local_addrs())
    }

    /// [`Peer::socket_addrs`], judged against the given local addresses.
    pub fn socket_addrs_from(&self, local: &[netif::LocalAddr]) -> Vec<SocketAddr> {
        netif::rank_peer(self.addresses.clone(), local)
            .into_iter()
            .map(|ip| SocketAddr::new(ip, self.port))
            .collect()
    }

    /// Whether `query` names this peer: its device id, or its display name
    /// ignoring case.
    pub fn matches(&self, query: &str) -> bool {
        self.id == query || same_name(&self.name, query)
    }
}

/// Whether `a` and `b` name the same device, the way people type names:
/// ignoring case, spacing and apostrophes, so `AJs macbook air` finds
/// `AJ’s MacBook Air` (macOS names use the curly ’).
pub fn same_name(a: &str, b: &str) -> bool {
    fn key(name: &str) -> String {
        name.split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .chars()
            .filter(|c| !matches!(c, '\'' | '’' | '‘' | '`' | '´' | 'ʼ'))
            .flat_map(char::to_lowercase)
            .collect()
    }
    key(a) == key(b)
}

/// A change to the set of discovered peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerEvent {
    Found(Peer),
    Updated(Peer),
    Lost(Peer),
}

/// Discovered peers, keyed by mDNS instance fullname.
///
/// Kept separate from the daemon so the add/remove rules can be tested
/// without a network.
#[derive(Debug, Default)]
pub struct PeerTable {
    own_id: String,
    peers: HashMap<String, Peer>,
    /// When each instance was last resolved, as a running count.
    seen: HashMap<String, u64>,
    clock: u64,
}

impl PeerTable {
    pub fn new(own_id: impl Into<String>) -> Self {
        Self {
            own_id: own_id.into(),
            peers: HashMap::new(),
            seen: HashMap::new(),
            clock: 0,
        }
    }

    /// Record a resolved instance. Returns what changed, or `None` if the
    /// instance is ours or nothing new was learned.
    ///
    /// An instance is resolved once per network interface, each time with
    /// only that interface's addresses, so addresses accumulate while the
    /// port stays the same.
    pub fn resolved(&mut self, fullname: &str, mut peer: Peer) -> Option<PeerEvent> {
        if peer.id == self.own_id {
            return None;
        }
        if let Some(old) = self.peers.get(fullname)
            && old.port == peer.port
        {
            peer.addresses.extend(&old.addresses);
            peer.addresses.sort();
            peer.addresses.dedup();
        }
        let change = match self.peers.insert(fullname.to_owned(), peer.clone()) {
            None => PeerEvent::Found(peer),
            Some(old) if old != peer => PeerEvent::Updated(peer),
            Some(_) => return None,
        };
        // Only news counts, so periodic re-announcements don't flip which
        // of two same-device instances stands for it.
        self.clock += 1;
        self.seen.insert(fullname.to_owned(), self.clock);
        Some(change)
    }

    /// Forget a removed instance. Returns the peer that went away, if known.
    pub fn removed(&mut self, fullname: &str) -> Option<PeerEvent> {
        self.seen.remove(fullname);
        self.peers.remove(fullname).map(PeerEvent::Lost)
    }

    /// All known peers, sorted by name then id.
    ///
    /// One per device: when two instances carry the same device id (the
    /// CLI's `listen` and the app running on one computer), the one heard
    /// from last stands for it.
    pub fn peers(&self) -> Vec<Peer> {
        let mut latest: HashMap<&str, (u64, &Peer)> = HashMap::new();
        for (fullname, peer) in &self.peers {
            let seen = self.seen.get(fullname).copied().unwrap_or_default();
            let entry = latest.entry(peer.id.as_str()).or_insert((seen, peer));
            if seen > entry.0 {
                *entry = (seen, peer);
            }
        }
        let mut peers: Vec<Peer> = latest.into_values().map(|(_, p)| p.clone()).collect();
        peers.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
        peers
    }
}

/// Build a [`Peer`] from an instance's TXT properties. Instances missing a
/// device id are not OpenDrop devices we can talk to, so they are skipped.
pub fn peer_from_txt(
    get: impl Fn(&str) -> Option<String>,
    mut addresses: Vec<IpAddr>,
    port: u16,
) -> Option<Peer> {
    let id = get(TXT_DEVICE_ID).filter(|id| !id.is_empty())?;
    let name = get(TXT_DEVICE_NAME)
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| id.clone());
    let protocol_version = get(TXT_PROTOCOL_VERSION)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    addresses.sort();
    addresses.dedup();
    Some(Peer {
        id,
        name,
        protocol_version,
        addresses,
        port,
    })
}

/// Advertises this device (optionally) and keeps track of peers.
///
/// Must be started from within a Tokio runtime. Dropping it stops
/// advertising and browsing.
pub struct Discovery {
    daemon: ServiceDaemon,
    advertised: Option<String>,
    table: Arc<Mutex<PeerTable>>,
    events: broadcast::Sender<PeerEvent>,
}

impl Discovery {
    /// Start browsing for peers. With `advertise_port`, also announce this
    /// device as reachable on that TCP port.
    pub fn start(identity: &DeviceIdentity, advertise_port: Option<u16>) -> Result<Self, BoxError> {
        let daemon = ServiceDaemon::new()?;

        let advertised = match advertise_port {
            Some(port) => {
                // Keep virtual adapters (WSL, Hyper-V, Docker, VPNs) out of
                // our records: nobody else on the LAN can reach them.
                let skipped = virtual_interfaces();
                if !skipped.is_empty() {
                    daemon.disable_interface(
                        skipped.into_iter().map(IfKind::Name).collect::<Vec<_>>(),
                    )?;
                }
                let info = service_info(identity, port)?;
                let fullname = info.get_fullname().to_owned();
                daemon.register(info)?;
                Some(fullname)
            }
            None => None,
        };

        let receiver = daemon.browse(SERVICE_TYPE)?;
        let table = Arc::new(Mutex::new(PeerTable::new(identity.id.clone())));
        let (events, _) = broadcast::channel(64);

        let task_table = Arc::clone(&table);
        let task_events = events.clone();
        tokio::spawn(async move {
            while let Ok(event) = receiver.recv_async().await {
                let change = match event {
                    ServiceEvent::ServiceResolved(info) => {
                        let fullname = info.fullname.clone();
                        let addresses = info.addresses.iter().map(|a| a.to_ip_addr()).collect();
                        let get = |key: &str| {
                            info.txt_properties
                                .get_property_val_str(key)
                                .map(str::to_owned)
                        };
                        peer_from_txt(get, addresses, info.port)
                            .and_then(|peer| task_table.lock().unwrap().resolved(&fullname, peer))
                    }
                    ServiceEvent::ServiceRemoved(_, fullname) => {
                        task_table.lock().unwrap().removed(&fullname)
                    }
                    _ => None,
                };
                if let Some(change) = change {
                    // No subscribers is fine; the table is still updated.
                    let _ = task_events.send(change);
                }
            }
        });

        Ok(Self {
            daemon,
            advertised,
            table,
            events,
        })
    }

    /// Peers discovered so far.
    pub fn peers(&self) -> Vec<Peer> {
        self.table.lock().unwrap().peers()
    }

    /// Receive changes from now on.
    pub fn subscribe(&self) -> broadcast::Receiver<PeerEvent> {
        self.events.subscribe()
    }

    /// Wait up to `limit` for a peer matching `query` (device id or name).
    ///
    /// Returns as soon as the peer has an IPv4 address. A peer seen only over
    /// IPv6 so far is returned when the time is up.
    pub async fn find(&self, query: &str, limit: Duration) -> Option<Peer> {
        let mut events = self.subscribe();
        let lookup = || self.peers().into_iter().find(|p| p.matches(query));
        let reachable = |p: &Peer| p.addresses.iter().any(IpAddr::is_ipv4);
        if let Some(peer) = lookup().filter(reachable) {
            return Some(peer);
        }
        let _ = tokio::time::timeout(limit, async {
            loop {
                match events.recv().await {
                    Ok(PeerEvent::Found(p) | PeerEvent::Updated(p))
                        if p.matches(query) && reachable(&p) =>
                    {
                        return;
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        })
        .await;
        lookup()
    }
}

impl Drop for Discovery {
    fn drop(&mut self) {
        // Announce our departure so peers drop us right away instead of
        // waiting for the record to expire.
        if let Some(fullname) = &self.advertised
            && let Ok(done) = self.daemon.unregister(fullname)
        {
            let _ = done.recv_timeout(Duration::from_secs(1));
        }
        let _ = self.daemon.shutdown();
    }
}

/// Names of this device's interfaces that look virtual (see
/// [`netif::is_virtual`]), each once.
pub fn virtual_interfaces() -> Vec<String> {
    let mut names: Vec<String> = netif::local_addrs()
        .into_iter()
        .filter(netif::LocalAddr::is_virtual)
        .map(|a| a.name)
        .collect();
    names.sort();
    names.dedup();
    names
}

fn service_info(identity: &DeviceIdentity, port: u16) -> Result<ServiceInfo, BoxError> {
    let name = truncate(&identity.name, MAX_NAME_LEN);
    let version = PROTOCOL_VERSION.to_string();
    let properties = [
        (TXT_DEVICE_ID, identity.id.as_str()),
        (TXT_DEVICE_NAME, name),
        (TXT_PROTOCOL_VERSION, version.as_str()),
    ];
    // The instance and host names use the device id: it is unique and
    // DNS-safe, unlike display names.
    let host = format!("{}.local.", identity.id);
    let info = ServiceInfo::new(SERVICE_TYPE, &identity.id, &host, (), port, &properties[..])?
        .enable_addr_auto();
    Ok(info)
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_match_however_the_apostrophe_is_typed() {
        let mac = "AJ’s MacBook Air (2)";
        for typed in [
            "AJ’s MacBook Air (2)",
            "AJ's MacBook Air (2)",
            "AJs MacBook Air (2)",
            "aj's  macbook air (2)",
        ] {
            assert!(same_name(mac, typed), "{typed}");
        }
        assert!(!same_name(mac, "AJ's MacBook Air"));
        assert!(!same_name(mac, "AJ's MacBook Pro (2)"));
    }

    fn peer(id: &str, name: &str) -> Peer {
        Peer {
            id: id.into(),
            name: name.into(),
            protocol_version: 1,
            addresses: vec!["192.168.1.20".parse().unwrap()],
            port: 45454,
        }
    }

    #[test]
    fn table_adds_updates_and_removes_peers() {
        let mut table = PeerTable::new("device-me");
        let a = peer("device-a", "Laptop");
        assert_eq!(
            table.resolved("a._opendrop._tcp.local.", a.clone()),
            Some(PeerEvent::Found(a.clone()))
        );
        // Resolving the same record again is not news.
        assert_eq!(table.resolved("a._opendrop._tcp.local.", a.clone()), None);

        let moved = Peer { port: 50000, ..a };
        assert_eq!(
            table.resolved("a._opendrop._tcp.local.", moved.clone()),
            Some(PeerEvent::Updated(moved.clone()))
        );
        assert_eq!(table.peers(), vec![moved.clone()]);

        assert_eq!(
            table.removed("a._opendrop._tcp.local."),
            Some(PeerEvent::Lost(moved))
        );
        assert_eq!(table.removed("a._opendrop._tcp.local."), None);
        assert!(table.peers().is_empty());
    }

    /// The CLI's `listen` and the app on one Mac share a device id: they
    /// show as one device, the one heard from last, and the other takes
    /// over when it goes away.
    #[test]
    fn two_instances_of_one_device_show_once() {
        let mut table = PeerTable::new("device-me");
        let cli = Peer {
            port: 45454,
            ..peer("device-mac", "AJs-MacBook-Air-2")
        };
        let app = Peer {
            port: 61861,
            ..peer("device-mac", "AJ’s MacBook Air (2)")
        };
        table.resolved("cli._opendrop._tcp.local.", cli.clone());
        table.resolved("app._opendrop._tcp.local.", app.clone());
        table.resolved("pc._opendrop._tcp.local.", peer("device-pc", "PCp7"));
        let names = |t: &PeerTable| t.peers().into_iter().map(|p| p.name).collect::<Vec<_>>();
        assert_eq!(names(&table), ["AJ’s MacBook Air (2)", "PCp7"]);
        // A re-announcement that says nothing new doesn't flip it.
        table.resolved("cli._opendrop._tcp.local.", cli.clone());
        assert_eq!(table.peers()[0].port, 61861);
        table.removed("app._opendrop._tcp.local.");
        assert_eq!(names(&table), ["AJs-MacBook-Air-2", "PCp7"]);
    }

    #[test]
    fn table_merges_addresses_from_each_interface() {
        let mut table = PeerTable::new("device-me");
        let on = |ip: &str| Peer {
            addresses: vec![ip.parse().unwrap()],
            ..peer("device-a", "Laptop")
        };
        table.resolved("a", on("::1"));
        assert!(matches!(
            table.resolved("a", on("192.168.1.20")),
            Some(PeerEvent::Updated(_))
        ));
        assert_eq!(table.resolved("a", on("::1")), None);
        assert_eq!(table.peers()[0].addresses.len(), 2);
    }

    #[test]
    fn table_ignores_own_advertisement() {
        let mut table = PeerTable::new("device-me");
        assert_eq!(table.resolved("me", peer("device-me", "Me")), None);
        assert!(table.peers().is_empty());
    }

    #[test]
    fn peer_from_txt_reads_properties() {
        let txt: HashMap<&str, &str> = [
            ("device_id", "device-a"),
            ("device_name", "Laptop"),
            ("protocol_version", "1"),
        ]
        .into();
        let ips: Vec<IpAddr> = vec![
            "fe80::1".parse().unwrap(),
            "192.168.1.20".parse().unwrap(),
            "192.168.1.20".parse().unwrap(),
        ];
        let p = peer_from_txt(|k| txt.get(k).map(|v| v.to_string()), ips, 45454).unwrap();
        assert_eq!(p.name, "Laptop");
        assert_eq!(p.protocol_version, 1);
        assert_eq!(p.addresses.len(), 2);
        assert_eq!(p.socket_addr(), Some("192.168.1.20:45454".parse().unwrap()));
    }

    #[test]
    fn socket_addr_prefers_lan_over_loopback() {
        let with = |ips: &[&str]| Peer {
            addresses: ips.iter().map(|ip| ip.parse().unwrap()).collect(),
            ..peer("device-a", "Laptop")
        };
        let addr = |p: Peer| p.socket_addrs_from(&[]).first().map(|a| a.ip().to_string());
        assert_eq!(
            addr(with(&["127.0.0.1", "fe80::1", "192.168.1.20"])),
            Some("192.168.1.20".into())
        );
        assert_eq!(
            addr(with(&["::1", "fd00::5", "127.0.0.1"])),
            Some("127.0.0.1".into())
        );
        assert_eq!(addr(with(&["::1", "fd00::5"])), Some("fd00::5".into()));
        assert_eq!(addr(with(&["127.0.0.1"])), Some("127.0.0.1".into()));
        assert_eq!(addr(with(&[])), None);
        let ranked: Vec<String> = with(&["::1", "127.0.0.1", "fe80::1", "10.0.0.2"])
            .socket_addrs_from(&[])
            .iter()
            .map(|a| a.ip().to_string())
            .collect();
        assert_eq!(ranked, ["10.0.0.2", "127.0.0.1", "::1", "fe80::1"]);
    }

    #[test]
    fn peer_from_txt_requires_device_id() {
        assert_eq!(peer_from_txt(|_| None, vec![], 1), None);
        let p =
            peer_from_txt(|k| (k == "device_id").then(|| "device-a".into()), vec![], 1).unwrap();
        assert_eq!(p.name, "device-a");
    }

    #[test]
    fn peer_matches_id_or_name_ignoring_case() {
        let p = peer("device-a", "AJ's MacBook");
        assert!(p.matches("device-a"));
        assert!(p.matches("aj's macbook"));
        assert!(!p.matches("macbook"));
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        assert_eq!(truncate("héllo", 2), "h");
        assert_eq!(truncate("short", 200), "short");
    }

    /// Two devices on this machine find each other over real multicast.
    /// Needs a network interface with multicast, so it's opt-in:
    /// `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn two_devices_discover_each_other() {
        let a = DeviceIdentity::new("Test A");
        let b = DeviceIdentity::new("Test B");
        let disc_a = Discovery::start(&a, Some(40001)).unwrap();
        let disc_b = Discovery::start(&b, Some(40002)).unwrap();

        let found = disc_a.find(&b.id, Duration::from_secs(10)).await.unwrap();
        assert_eq!(found.name, "Test B");
        assert_eq!(found.port, 40002);
        assert!(disc_b.find(&a.id, Duration::from_secs(10)).await.is_some());
        assert!(disc_a.peers().iter().all(|p| p.id != a.id));

        let mut events = disc_a.subscribe();
        drop(disc_b);
        let lost = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Ok(PeerEvent::Lost(p)) = events.recv().await
                    && p.id == b.id
                {
                    return p;
                }
            }
        })
        .await;
        assert!(
            lost.is_ok(),
            "peer B was not removed after it stopped advertising"
        );
    }
}

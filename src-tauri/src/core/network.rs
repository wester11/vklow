#![cfg(windows)]

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CStr,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use windows_sys::Win32::{
    NetworkManagement::IpHelper::{
        FreeMibTable, GetAdaptersAddresses, GetIfEntry2, GetIpForwardTable2,
        IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211, IP_ADAPTER_ADDRESSES_LH, MIB_IF_ROW2,
        MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    },
    NetworkManagement::Ndis::NET_IF_OPER_STATUS_UP,
    Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC},
};

const ERROR_BUFFER_OVERFLOW: u32 = 111;
const ADAPTERS_ADDRESSES_INITIAL_BUFFER: usize = 15 * 1024;

/// DNS state of a physical, default-route-capable adapter. Values are copied out
/// of the Windows-owned `GetAdaptersAddresses` buffer before that buffer is freed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhysicalAdapterDnsSnapshot {
    pub adapter_identity: String,
    pub if_index_v4: u32,
    pub if_index_v6: u32,
    pub luid: u64,
    pub friendly_name: String,
    pub interface_type: u32,
    pub operational_status: i32,
    pub hardware_interface: bool,
    pub dns_servers: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhysicalDnsSnapshot {
    pub adapters: Vec<PhysicalAdapterDnsSnapshot>,
    pub void_tun_dns: Vec<PhysicalAdapterDnsSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PhysicalDnsComparison {
    Equal,
    SmokeInconclusiveNetworkChanged,
    PhysicalDnsMutated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv4Route {
    pub destination: [u8; 4],
    pub prefix_length: u8,
    pub interface_index: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceMetadata {
    pub index: u32,
    pub alias: String,
    pub luid: u64,
    pub in_octets: u64,
    pub out_octets: u64,
}

pub fn interface_metadata(index: u32) -> Result<InterfaceMetadata, String> {
    let mut row = MIB_IF_ROW2 {
        InterfaceIndex: index,
        ..Default::default()
    };
    if unsafe { GetIfEntry2(&mut row) } != 0 {
        return Err("Unable to read Windows interface metadata".into());
    }
    let alias = String::from_utf16_lossy(&row.Alias)
        .trim_end_matches('\0')
        .to_owned();
    Ok(InterfaceMetadata {
        index,
        alias,
        luid: unsafe { row.InterfaceLuid.Value },
        in_octets: row.InOctets,
        out_octets: row.OutOctets,
    })
}

pub fn ipv4_routes() -> Result<Vec<Ipv4Route>, String> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    if unsafe { GetIpForwardTable2(AF_INET, &mut table) } != 0 || table.is_null() {
        return Err("Unable to read Windows IPv4 route table".into());
    }
    let rows = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
    };
    let routes = rows.iter().map(route_from_row).collect();
    unsafe { FreeMibTable(table.cast()) };
    Ok(routes)
}

fn route_from_row(row: &MIB_IPFORWARD_ROW2) -> Ipv4Route {
    let raw = unsafe { row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr };
    Ipv4Route {
        destination: raw.to_be_bytes(),
        prefix_length: row.DestinationPrefix.PrefixLength,
        interface_index: row.InterfaceIndex,
    }
}

pub fn scoped_smoke_route() -> Result<Option<Ipv4Route>, String> {
    Ok(ipv4_routes()?
        .into_iter()
        .find(|route| route.destination == [1, 1, 1, 1] && route.prefix_length == 32))
}

pub fn has_default_route_on(interface_index: u32) -> Result<bool, String> {
    Ok(ipv4_routes()?.into_iter().any(|route| {
        route.destination == [0, 0, 0, 0]
            && route.prefix_length == 0
            && route.interface_index == interface_index
    }))
}

/// Takes a read-only snapshot of the DNS servers assigned to the physical
/// adapter(s) carrying the current IPv4 default route. It intentionally does
/// not include VPN, loopback, tunnel or VM adapters that are not an uplink.
pub fn physical_dns_snapshot() -> Result<PhysicalDnsSnapshot, String> {
    let default_indices = ipv4_routes()?
        .into_iter()
        .filter(|route| route.destination == [0, 0, 0, 0] && route.prefix_length == 0)
        .map(|route| route.interface_index)
        .collect::<BTreeSet<_>>();
    if default_indices.is_empty() {
        return Err("No IPv4 default route is available for DNS smoke verification".into());
    }

    let adapters = read_adapter_dns()?;
    let mut physical = adapters
        .iter()
        .filter(|adapter| {
            default_indices.contains(&adapter.if_index_v4)
                && is_physical_uplink(adapter)
                && adapter.operational_status == NET_IF_OPER_STATUS_UP
        })
        .cloned()
        .collect::<Vec<_>>();
    physical.sort_by(|left, right| left.adapter_identity.cmp(&right.adapter_identity));
    if physical.is_empty() {
        return Err("The active default route does not use an Ethernet or Wi-Fi uplink".into());
    }

    let mut void_tun_dns = adapters
        .into_iter()
        .filter(|adapter| adapter.friendly_name.starts_with("VOID Tunnel "))
        .collect::<Vec<_>>();
    void_tun_dns.sort_by(|left, right| left.adapter_identity.cmp(&right.adapter_identity));
    Ok(PhysicalDnsSnapshot {
        adapters: physical,
        void_tun_dns,
    })
}

/// A changed active uplink is an inconclusive smoke run, not evidence that
/// VOID modified DNS. With the same physical identities, a DNS-set difference
/// is a factual physical DNS mutation.
pub fn compare_physical_dns(
    before: &PhysicalDnsSnapshot,
    observed: &PhysicalDnsSnapshot,
) -> PhysicalDnsComparison {
    let before_by_identity = adapter_map(&before.adapters);
    let observed_by_identity = adapter_map(&observed.adapters);
    if before_by_identity.keys().collect::<Vec<_>>()
        != observed_by_identity.keys().collect::<Vec<_>>()
    {
        return PhysicalDnsComparison::SmokeInconclusiveNetworkChanged;
    }
    for (identity, before_adapter) in before_by_identity {
        let Some(observed_adapter) = observed_by_identity.get(identity) else {
            return PhysicalDnsComparison::SmokeInconclusiveNetworkChanged;
        };
        if before_adapter.luid != observed_adapter.luid
            || before_adapter.if_index_v4 != observed_adapter.if_index_v4
            || before_adapter.if_index_v6 != observed_adapter.if_index_v6
            || before_adapter.interface_type != observed_adapter.interface_type
            || before_adapter.operational_status != observed_adapter.operational_status
            || before_adapter.hardware_interface != observed_adapter.hardware_interface
        {
            return PhysicalDnsComparison::SmokeInconclusiveNetworkChanged;
        }
        if before_adapter.dns_servers != observed_adapter.dns_servers {
            return PhysicalDnsComparison::PhysicalDnsMutated;
        }
    }
    PhysicalDnsComparison::Equal
}

fn adapter_map(
    adapters: &[PhysicalAdapterDnsSnapshot],
) -> BTreeMap<&str, &PhysicalAdapterDnsSnapshot> {
    adapters
        .iter()
        .map(|adapter| (adapter.adapter_identity.as_str(), adapter))
        .collect()
}

fn is_physical_uplink(adapter: &PhysicalAdapterDnsSnapshot) -> bool {
    adapter.hardware_interface
        && matches!(
            adapter.interface_type,
            IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211
        )
}

fn hardware_interface(index: u32) -> Result<bool, String> {
    let mut row = MIB_IF_ROW2 {
        InterfaceIndex: index,
        ..Default::default()
    };
    if unsafe { GetIfEntry2(&mut row) } != 0 {
        return Err("Unable to read Windows physical-interface metadata".into());
    }
    // MIB_IF_ROW2::InterfaceAndOperStatusFlags.HardwareInterface is bit 0.
    Ok(row.InterfaceAndOperStatusFlags._bitfield & 0b0000_0001 != 0)
}

fn read_adapter_dns() -> Result<Vec<PhysicalAdapterDnsSnapshot>, String> {
    let mut size = ADAPTERS_ADDRESSES_INITIAL_BUFFER as u32;
    let mut buffer = vec![0u8; size as usize];
    let mut status = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            0,
            std::ptr::null(),
            buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
            &mut size,
        )
    };
    if status == ERROR_BUFFER_OVERFLOW {
        buffer.resize(size as usize, 0);
        status = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                0,
                std::ptr::null(),
                buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                &mut size,
            )
        };
    }
    if status != 0 {
        return Err("Unable to read Windows adapter DNS state".into());
    }

    let mut snapshots = Vec::new();
    let mut current = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while !current.is_null() {
        let adapter = unsafe { &*current };
        snapshots.push(PhysicalAdapterDnsSnapshot {
            adapter_identity: unsafe { narrow_string(adapter.AdapterName) },
            if_index_v4: unsafe { adapter.Anonymous1.Anonymous.IfIndex },
            if_index_v6: adapter.Ipv6IfIndex,
            luid: unsafe { adapter.Luid.Value },
            friendly_name: unsafe { wide_string(adapter.FriendlyName) },
            interface_type: adapter.IfType,
            operational_status: adapter.OperStatus,
            hardware_interface: hardware_interface(unsafe {
                adapter.Anonymous1.Anonymous.IfIndex
            })?,
            dns_servers: unsafe { dns_servers(adapter.FirstDnsServerAddress) },
        });
        current = adapter.Next;
    }
    Ok(snapshots)
}

unsafe fn narrow_string(value: windows_sys::core::PSTR) -> String {
    if value.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(value.cast()).to_string_lossy().into_owned() }
}

unsafe fn wide_string(value: windows_sys::core::PWSTR) -> String {
    if value.is_null() {
        return String::new();
    }
    let mut length = 0usize;
    while unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(value, length) })
}

unsafe fn dns_servers(
    mut current: *mut windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_DNS_SERVER_ADDRESS_XP,
) -> Vec<String> {
    let mut servers = Vec::new();
    while !current.is_null() {
        let entry = unsafe { &*current };
        let address = &entry.Address;
        if !address.lpSockaddr.is_null() && address.iSockaddrLength > 0 {
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    address.lpSockaddr.cast::<u8>(),
                    address.iSockaddrLength as usize,
                )
            };
            if let Some(server) = parse_dns_sockaddr(bytes) {
                servers.push(server);
            }
        }
        current = entry.Next;
    }
    normalize_dns_servers(servers)
}

fn parse_dns_sockaddr(bytes: &[u8]) -> Option<String> {
    let family = u16::from_ne_bytes(bytes.get(..2)?.try_into().ok()?);
    match family {
        AF_INET if bytes.len() >= 8 => {
            Some(IpAddr::V4(Ipv4Addr::from([bytes[4], bytes[5], bytes[6], bytes[7]])).to_string())
        }
        AF_INET6 if bytes.len() >= 24 => {
            Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).ok()?)).to_string())
        }
        _ => None,
    }
}

fn normalize_dns_servers(servers: Vec<String>) -> Vec<String> {
    let mut normalized = servers
        .into_iter()
        .filter_map(|server| server.parse::<IpAddr>().ok())
        .map(|server| server.to_string())
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter(identity: &str, dns_servers: &[&str]) -> PhysicalAdapterDnsSnapshot {
        PhysicalAdapterDnsSnapshot {
            adapter_identity: identity.into(),
            if_index_v4: 7,
            if_index_v6: 7,
            luid: 42,
            friendly_name: "Wi-Fi".into(),
            interface_type: IF_TYPE_IEEE80211,
            operational_status: NET_IF_OPER_STATUS_UP,
            hardware_interface: true,
            dns_servers: normalize_dns_servers(
                dns_servers.iter().map(ToString::to_string).collect(),
            ),
        }
    }

    fn snapshot(adapters: Vec<PhysicalAdapterDnsSnapshot>) -> PhysicalDnsSnapshot {
        PhysicalDnsSnapshot {
            adapters,
            void_tun_dns: vec![adapter("VOID tunnel diagnostic only", &["198.18.0.1"])],
        }
    }

    #[test]
    fn parses_ipv4_dns_socket_address() {
        assert_eq!(
            parse_dns_sockaddr(&[AF_INET as u8, 0, 0, 0, 1, 1, 1, 1]),
            Some("1.1.1.1".into())
        );
    }

    #[test]
    fn parses_ipv6_dns_socket_address() {
        let mut address = vec![0u8; 24];
        address[..2].copy_from_slice(&AF_INET6.to_ne_bytes());
        address[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        assert_eq!(parse_dns_sockaddr(&address), Some("::1".into()));
    }

    #[test]
    fn normalization_deduplicates_and_ignores_order() {
        assert_eq!(
            normalize_dns_servers(vec!["8.8.8.8".into(), "1.1.1.1".into(), "8.8.8.8".into()]),
            vec!["1.1.1.1", "8.8.8.8"]
        );
    }

    #[test]
    fn equal_dns_in_different_order_is_equal() {
        assert_eq!(
            compare_physical_dns(
                &snapshot(vec![adapter("wifi", &["8.8.8.8", "1.1.1.1"])]),
                &snapshot(vec![adapter("wifi", &["1.1.1.1", "8.8.8.8"])]),
            ),
            PhysicalDnsComparison::Equal
        );
    }

    #[test]
    fn detects_actual_physical_dns_change() {
        assert_eq!(
            compare_physical_dns(
                &snapshot(vec![adapter("wifi", &["1.1.1.1"])]),
                &snapshot(vec![adapter("wifi", &["8.8.8.8"])]),
            ),
            PhysicalDnsComparison::PhysicalDnsMutated
        );
    }

    #[test]
    fn identity_mismatch_is_network_change_not_dns_mutation() {
        assert_eq!(
            compare_physical_dns(
                &snapshot(vec![adapter("wifi", &["1.1.1.1"])]),
                &snapshot(vec![adapter("ethernet", &["8.8.8.8"])]),
            ),
            PhysicalDnsComparison::SmokeInconclusiveNetworkChanged
        );
    }

    #[test]
    fn void_dns_is_excluded_from_physical_equality() {
        let before = snapshot(vec![adapter("wifi", &["1.1.1.1"])]);
        let mut observed = snapshot(vec![adapter("wifi", &["1.1.1.1"])]);
        observed.void_tun_dns[0].dns_servers = vec!["9.9.9.9".into()];
        assert_eq!(
            compare_physical_dns(&before, &observed),
            PhysicalDnsComparison::Equal
        );
    }

    #[test]
    fn virtual_ethernet_is_not_treated_as_a_physical_uplink() {
        let mut virtual_adapter = adapter("vpn", &["1.1.1.1"]);
        virtual_adapter.hardware_interface = false;
        assert!(!is_physical_uplink(&virtual_adapter));
    }

    #[test]
    fn changed_operational_context_is_inconclusive() {
        let before = snapshot(vec![adapter("wifi", &["1.1.1.1"])]);
        let mut observed = snapshot(vec![adapter("wifi", &["1.1.1.1"])]);
        observed.adapters[0].operational_status = 2;
        assert_eq!(
            compare_physical_dns(&before, &observed),
            PhysicalDnsComparison::SmokeInconclusiveNetworkChanged
        );
    }

    #[test]
    fn can_read_ipv4_route_table() {
        assert!(!ipv4_routes().unwrap().is_empty());
    }

    #[test]
    fn can_read_physical_dns_read_only() {
        assert!(!physical_dns_snapshot().unwrap().adapters.is_empty());
    }
}

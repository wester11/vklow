#![cfg(windows)]

use windows_sys::Win32::{
    NetworkManagement::IpHelper::{
        FreeMibTable, GetIfEntry2, GetIpForwardTable2, MIB_IF_ROW2, MIB_IPFORWARD_ROW2,
        MIB_IPFORWARD_TABLE2,
    },
    Networking::WinSock::AF_INET,
};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_read_ipv4_route_table() {
        assert!(!ipv4_routes().unwrap().is_empty());
    }
}

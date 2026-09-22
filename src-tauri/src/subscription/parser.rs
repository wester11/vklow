use crate::domain::{
    Protocol, Server, ServerEndpoint, ServerHealth, ServerSummary, VlessEncryption,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use url::Url;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawHostKind {
    Domain,
    Ipv4,
    Ipv6,
    Empty,
    Invalid,
}

impl RawHostKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Empty => "empty",
            Self::Invalid => "invalid",
        }
    }
}

/// An address-free authority observation used only for the development
/// provenance diagnostic. `canonical` must be fingerprinted immediately and
/// never printed or persisted.
#[derive(Clone, Debug)]
pub struct RawAuthorityObservation {
    pub present: bool,
    pub kind: RawHostKind,
    pub unspecified: bool,
    pub canonical: Option<String>,
}

pub fn inspect_uri_authority(input: &str) -> RawAuthorityObservation {
    let Ok(url) = Url::parse(input) else {
        return RawAuthorityObservation {
            present: false,
            kind: RawHostKind::Invalid,
            unspecified: false,
            canonical: None,
        };
    };
    let Some(host) = url.host_str() else {
        return RawAuthorityObservation {
            present: false,
            kind: RawHostKind::Empty,
            unspecified: false,
            canonical: None,
        };
    };
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => RawAuthorityObservation {
            present: true,
            kind: RawHostKind::Ipv4,
            unspecified: address.is_unspecified(),
            canonical: Some(address.to_string()),
        },
        Ok(IpAddr::V6(address)) => RawAuthorityObservation {
            present: true,
            kind: RawHostKind::Ipv6,
            unspecified: address.is_unspecified(),
            canonical: Some(address.to_string()),
        },
        Err(_) => match ServerEndpoint::from_uri_host(Some(host)) {
            Ok(ServerEndpoint::Domain(domain)) => RawAuthorityObservation {
                present: true,
                kind: RawHostKind::Domain,
                unspecified: false,
                canonical: Some(domain),
            },
            Ok(_) => unreachable!("IP endpoints are handled before domain parsing"),
            Err(_) => RawAuthorityObservation {
                present: true,
                kind: RawHostKind::Invalid,
                unspecified: false,
                canonical: None,
            },
        },
    }
}
pub fn parse_uri(input: &str) -> Result<Server, String> {
    let scheme = input
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    match scheme.as_str() {
        "vless" => parse_standard(input, Protocol::Vless),
        "trojan" => parse_standard(input, Protocol::Trojan),
        "ss" => parse_shadowsocks(input),
        "vmess" => parse_vmess(input),
        _ => Err("Неподдерживаемый протокол".into()),
    }
}
struct ServerInput {
    protocol: Protocol,
    name: String,
    endpoint: ServerEndpoint,
    port: u16,
    transport: Option<String>,
    credential: String,
    security: Option<String>,
    sni: Option<String>,
    vless_encryption: VlessEncryption,
    options: HashMap<String, String>,
}
fn base_server(input: ServerInput) -> Server {
    Server {
        summary: ServerSummary {
            id: Uuid::new_v4().to_string(),
            name: if input.name.trim().is_empty() {
                "Unnamed server".into()
            } else {
                input.name
            },
            protocol: input.protocol,
            endpoint_kind: input.endpoint.kind(),
            port: input.port,
            transport: input.transport,
            country: None,
            health: ServerHealth::Unknown,
            latency_ms: None,
        },
        endpoint: input.endpoint,
        credential: input.credential,
        security: input.security,
        sni: input.sni,
        vless_encryption: input.vless_encryption,
        options: input.options,
    }
}
fn parse_standard(input: &str, protocol: Protocol) -> Result<Server, String> {
    let url = Url::parse(input).map_err(|_| String::from(standard_authority_error(input)))?;
    let endpoint = ServerEndpoint::from_uri_host(url.host_str())?;
    let port = url.port().unwrap_or(443);
    let credential = url.username();
    if credential.is_empty() {
        return Err("В URI отсутствуют учётные данные".into());
    }
    if matches!(protocol, Protocol::Vless) && Uuid::parse_str(credential).is_err() {
        return Err("VLESS URI содержит некорректный UUID".into());
    }
    let mut query: HashMap<_, _> = url.query_pairs().into_owned().collect();
    let vless_encryption = matches!(protocol, Protocol::Vless)
        .then(|| VlessEncryption::from_sharing_link(query.remove("encryption")))
        .unwrap_or(VlessEncryption::Absent);
    let name = percent_decode_str(url.fragment().unwrap_or_default())
        .decode_utf8_lossy()
        .into_owned();
    Ok(base_server(ServerInput {
        protocol,
        name,
        endpoint,
        port,
        transport: query.get("type").cloned(),
        credential: credential.to_owned(),
        security: query.get("security").cloned(),
        sni: query.get("sni").cloned(),
        vless_encryption,
        options: query,
    }))
}

fn standard_authority_error(input: &str) -> &'static str {
    let authority = input
        .split_once("://")
        .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or_default())
        .unwrap_or_default();
    if authority
        .rsplit_once('@')
        .is_some_and(|(_, host)| host.is_empty())
    {
        "MissingServerAddress"
    } else {
        "InvalidServerAddress"
    }
}
fn parse_shadowsocks(input: &str) -> Result<Server, String> {
    let raw = input
        .strip_prefix("ss://")
        .ok_or("Некорректный Shadowsocks URI")?;
    let (without_name, name) = raw.split_once('#').unwrap_or((raw, ""));
    let decoded = if without_name.contains('@') {
        without_name.to_owned()
    } else {
        String::from_utf8(
            STANDARD
                .decode(without_name)
                .or_else(|_| URL_SAFE_NO_PAD.decode(without_name))
                .map_err(|_| "Некорректный Shadowsocks URI")?,
        )
        .map_err(|_| "Некорректная кодировка Shadowsocks URI")?
    };
    let url =
        Url::parse(&format!("ss://{}", decoded)).map_err(|_| "Некорректный Shadowsocks URI")?;
    let endpoint = ServerEndpoint::from_uri_host(url.host_str())?;
    let port = url.port().ok_or("В URI отсутствует порт")?;
    let password = url.password().ok_or("В URI отсутствует пароль")?;
    Ok(base_server(ServerInput {
        protocol: Protocol::Shadowsocks,
        name: name.to_owned(),
        endpoint,
        port,
        transport: None,
        credential: format!("{}:{}", url.username(), password),
        security: None,
        sni: None,
        vless_encryption: VlessEncryption::Absent,
        options: HashMap::new(),
    }))
}
#[derive(Deserialize)]
struct Vmess {
    #[serde(rename = "add")]
    address: String,
    #[serde(default)]
    port: serde_json::Value,
    #[serde(default, rename = "ps")]
    name: String,
    #[serde(rename = "id")]
    id: String,
    #[serde(default, rename = "net")]
    transport: String,
    #[serde(default)]
    tls: String,
    #[serde(default)]
    sni: String,
}
fn parse_vmess(input: &str) -> Result<Server, String> {
    let encoded = input
        .strip_prefix("vmess://")
        .ok_or("Некорректный VMess URI")?
        .split('#')
        .next()
        .unwrap_or_default();
    let bytes = STANDARD
        .decode(encoded)
        .or_else(|_| URL_SAFE_NO_PAD.decode(encoded))
        .map_err(|_| "Некорректный VMess URI")?;
    let item: Vmess =
        serde_json::from_slice(&bytes).map_err(|_| "Некорректная VMess-конфигурация")?;
    let port = match item.port {
        serde_json::Value::Number(n) => n.as_u64().unwrap_or(443) as u16,
        serde_json::Value::String(s) => s.parse().unwrap_or(443),
        _ => 443,
    };
    if item.address.trim().is_empty() || item.id.trim().is_empty() {
        return Err("VMess-конфигурация неполная".into());
    }
    let endpoint = ServerEndpoint::from_uri_host(Some(&item.address))?;
    Ok(base_server(ServerInput {
        protocol: Protocol::Vmess,
        name: item.name,
        endpoint,
        port,
        transport: (!item.transport.is_empty()).then_some(item.transport),
        credential: item.id,
        security: (!item.tls.is_empty()).then_some(item.tls),
        sni: (!item.sni.is_empty()).then_some(item.sni),
        vless_encryption: VlessEncryption::Absent,
        options: HashMap::new(),
    }))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_vless_reality() {
        let item = parse_uri("vless://11111111-1111-1111-1111-111111111111@node.example:443?security=reality&type=grpc&sni=site.example#NL%20Edge").unwrap();
        assert_eq!(item.endpoint.canonical(), "node.example");
        assert_eq!(item.summary.port, 443);
        assert_eq!(item.summary.name, "NL Edge");
        assert!(matches!(item.summary.protocol, Protocol::Vless));
        assert_eq!(item.options["security"], "reality");
    }

    #[test]
    fn preserves_vless_tcp_reality_metadata_in_the_normalized_model() {
        let item = parse_uri("vless://11111111-1111-1111-1111-111111111111@198.51.100.7:8443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=cover.example&pbk=fake-public-key&sid=aabb&fp=chrome&spx=%2Ffake-spider#Synthetic").unwrap();
        assert_eq!(item.endpoint.canonical(), "198.51.100.7");
        assert_eq!(item.summary.port, 8443);
        assert_eq!(item.summary.transport.as_deref(), Some("tcp"));
        assert_eq!(item.security.as_deref(), Some("reality"));
        assert_eq!(item.sni.as_deref(), Some("cover.example"));
        assert_eq!(
            item.options.get("flow").map(String::as_str),
            Some("xtls-rprx-vision")
        );
        assert_eq!(
            item.options.get("pbk").map(String::as_str),
            Some("fake-public-key")
        );
        assert_eq!(item.options.get("sid").map(String::as_str), Some("aabb"));
        assert_eq!(item.options.get("fp").map(String::as_str), Some("chrome"));
        assert_eq!(
            item.options.get("spx").map(String::as_str),
            Some("/fake-spider")
        );
    }

    #[test]
    fn parses_typed_vless_encryption_without_retaining_it_in_generic_options() {
        let encryption = "mlkem768x25519plus.native.1rtt.100-111-1111.75-0-111.50-0-3333.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let item = parse_uri(&format!("vless://11111111-1111-1111-1111-111111111111@198.51.100.7:443?type=tcp&security=none&encryption={encryption}#Synthetic")).unwrap();
        assert!(item.vless_encryption.field_present());
        assert_eq!(item.vless_encryption.safe_status(), "enabled");
        assert_eq!(
            item.vless_encryption
                .enabled_config()
                .unwrap()
                .safe_metadata(),
            "mlkem768x25519plus/native/1rtt"
        );
        assert!(!item.options.contains_key("encryption"));
    }

    #[test]
    fn authoritative_endpoint_preserves_domain_ipv4_and_ipv6_without_defaults() {
        let domain =
            parse_uri("vless://11111111-1111-1111-1111-111111111111@MiXeD.Example:443?type=tcp")
                .unwrap();
        assert!(matches!(domain.endpoint, ServerEndpoint::Domain(_)));
        assert_eq!(domain.endpoint.canonical(), "mixed.example");

        let ipv4 =
            parse_uri("vless://11111111-1111-1111-1111-111111111111@198.51.100.7:443?type=tcp")
                .unwrap();
        assert!(matches!(ipv4.endpoint, ServerEndpoint::Ipv4(_)));

        let ipv6 =
            parse_uri("vless://11111111-1111-1111-1111-111111111111@[2001:db8::7]:443?type=tcp")
                .unwrap();
        assert!(matches!(ipv6.endpoint, ServerEndpoint::Ipv6(_)));
    }

    #[test]
    fn rejects_missing_invalid_and_unspecified_vless_authorities() {
        for input in [
            "vless://11111111-1111-1111-1111-111111111111@:443?type=tcp",
            "vless://11111111-1111-1111-1111-111111111111@bad_host:443?type=tcp",
            "vless://11111111-1111-1111-1111-111111111111@0.0.0.0:443?type=tcp",
            "vless://11111111-1111-1111-1111-111111111111@[::]:443?type=tcp",
        ] {
            let error = parse_uri(input).err().unwrap();
            assert!(matches!(
                error.as_str(),
                "MissingServerAddress" | "InvalidServerAddress"
            ));
        }
    }

    #[test]
    fn authority_observation_is_independent_from_query_parameters() {
        let observation = inspect_uri_authority(
            "vless://11111111-1111-1111-1111-111111111111@node.example:443?host=0.0.0.0&type=tcp",
        );
        assert!(observation.present);
        assert_eq!(observation.kind, RawHostKind::Domain);
        assert!(!observation.unspecified);
        assert_eq!(observation.canonical.as_deref(), Some("node.example"));
    }

    #[test]
    fn rejects_unknown_scheme() {
        assert!(parse_uri("file:///etc/passwd").is_err());
    }
    #[test]
    fn rejects_invalid_vless_uuid() {
        assert!(parse_uri("vless://not-a-uuid@node.example:443#bad").is_err());
    }
}

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use zeroize::Zeroize;
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Vless,
    Vmess,
    Shadowsocks,
    Trojan,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ServerHealth {
    Unknown,
    Testing,
    Available,
    Degraded,
    Unavailable,
}

/// The only authoritative remote endpoint representation.  An unspecified,
/// missing or malformed address cannot be constructed as a connectable server.
#[derive(Clone, Eq, PartialEq)]
pub enum ServerEndpoint {
    Domain(String),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum PersistedServerEndpoint {
    Domain(String),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

impl std::fmt::Debug for ServerEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ServerEndpoint([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerEndpointKind {
    Domain,
    Ipv4,
    Ipv6,
}

impl ServerEndpointKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

impl ServerEndpoint {
    pub fn from_uri_host(host: Option<&str>) -> Result<Self, &'static str> {
        let host = host.ok_or("MissingServerAddress")?;
        let host = host
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .unwrap_or(host);
        if host.is_empty() || host.chars().any(char::is_control) {
            return Err("InvalidServerAddress");
        }
        match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(address)) if address.is_unspecified() => Err("InvalidServerAddress"),
            Ok(IpAddr::V6(address)) if address.is_unspecified() => Err("InvalidServerAddress"),
            Ok(IpAddr::V4(address)) => Ok(Self::Ipv4(address)),
            Ok(IpAddr::V6(address)) => Ok(Self::Ipv6(address)),
            Err(_) if valid_domain(host) => Ok(Self::Domain(host.to_ascii_lowercase())),
            Err(_) => Err("InvalidServerAddress"),
        }
    }

    pub const fn kind(&self) -> ServerEndpointKind {
        match self {
            Self::Domain(_) => ServerEndpointKind::Domain,
            Self::Ipv4(_) => ServerEndpointKind::Ipv4,
            Self::Ipv6(_) => ServerEndpointKind::Ipv6,
        }
    }

    pub const fn classification(&self) -> &'static str {
        match self {
            Self::Domain(_) => "domain",
            Self::Ipv4(address) if address.is_loopback() => "loopback",
            Self::Ipv4(address) if address.is_private() => "private",
            Self::Ipv4(address) if address.is_link_local() => "link_local",
            Self::Ipv4(address) if address.is_multicast() || address.is_broadcast() => "multicast",
            Self::Ipv4(_) => "public",
            Self::Ipv6(address) if address.is_loopback() => "loopback",
            Self::Ipv6(address) if address.is_unique_local() => "private",
            Self::Ipv6(address) if address.is_unicast_link_local() => "link_local",
            Self::Ipv6(address) if address.is_multicast() => "multicast",
            Self::Ipv6(_) => "public",
        }
    }

    pub fn canonical(&self) -> String {
        match self {
            Self::Domain(value) => value.clone(),
            Self::Ipv4(value) => value.to_string(),
            Self::Ipv6(value) => value.to_string(),
        }
    }

    pub fn authority_value(&self) -> String {
        self.canonical()
    }

    /// The protected persistence codec used by provenance checks.  It never
    /// passes through a UI or diagnostics DTO and rejects invalid values again
    /// when reloaded.
    pub fn persistence_round_trip(&self) -> Result<Self, String> {
        let record = match self {
            Self::Domain(value) => PersistedServerEndpoint::Domain(value.clone()),
            Self::Ipv4(value) => PersistedServerEndpoint::Ipv4(*value),
            Self::Ipv6(value) => PersistedServerEndpoint::Ipv6(*value),
        };
        let bytes = serde_json::to_vec(&record).map_err(|_| "EndpointPersistenceEncodeFailed")?;
        let record = serde_json::from_slice::<PersistedServerEndpoint>(&bytes)
            .map_err(|_| "EndpointPersistenceDecodeFailed")?;
        match record {
            PersistedServerEndpoint::Domain(value) => Self::from_uri_host(Some(&value)),
            PersistedServerEndpoint::Ipv4(value) => Self::from_uri_host(Some(&value.to_string())),
            PersistedServerEndpoint::Ipv6(value) => Self::from_uri_host(Some(&value.to_string())),
        }
        .map_err(str::to_owned)
    }
}

fn valid_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|character| character.is_ascii_alphanumeric() || character == b'-')
        })
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerSummary {
    pub id: String,
    pub name: String,
    pub protocol: Protocol,
    pub endpoint_kind: ServerEndpointKind,
    pub port: u16,
    pub transport: Option<String>,
    pub country: Option<String>,
    pub health: ServerHealth,
    pub latency_ms: Option<u32>,
}

/// The protocol-level VLESS encryption setting. It is intentionally distinct
/// from transport security (`none` / TLS / REALITY).  The enabled value is
/// credential-bearing and therefore never implements a revealing Debug view.
#[derive(Clone, Eq, PartialEq)]
pub enum VlessEncryption {
    Absent,
    None,
    Enabled(VlessEncryptionConfig),
    UnknownUnsupported(VlessEncryptionMaterial),
}

impl std::fmt::Debug for VlessEncryption {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Absent => "VlessEncryption::Absent",
            Self::None => "VlessEncryption::None",
            Self::Enabled(_) => "VlessEncryption::Enabled([redacted])",
            Self::UnknownUnsupported(_) => "VlessEncryption::UnknownUnsupported([redacted])",
        })
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VlessEncryptionConfig(String);

impl std::fmt::Debug for VlessEncryptionConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VlessEncryptionConfig([redacted])")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct VlessEncryptionMaterial(String);

impl std::fmt::Debug for VlessEncryptionMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VlessEncryptionMaterial([redacted])")
    }
}

impl VlessEncryption {
    pub fn from_sharing_link(value: Option<String>) -> Self {
        let Some(value) = value else {
            return Self::Absent;
        };
        if value == "none" {
            return Self::None;
        }
        match VlessEncryptionConfig::parse(value.clone()) {
            Some(config) => Self::Enabled(config),
            None => Self::UnknownUnsupported(VlessEncryptionMaterial(value)),
        }
    }

    pub const fn field_present(&self) -> bool {
        !matches!(self, Self::Absent)
    }

    pub const fn safe_status(&self) -> &'static str {
        match self {
            Self::Absent | Self::None => "none",
            Self::Enabled(_) => "enabled",
            Self::UnknownUnsupported(_) => "unknown_unsupported",
        }
    }

    pub const fn enabled_config(&self) -> Option<&VlessEncryptionConfig> {
        match self {
            Self::Enabled(config) => Some(config),
            Self::Absent | Self::None | Self::UnknownUnsupported(_) => None,
        }
    }

    pub fn sensitive_value(&self) -> Option<&str> {
        match self {
            Self::Enabled(config) => Some(config.as_config_value()),
            Self::UnknownUnsupported(material) => Some(material.as_str()),
            Self::Absent | Self::None => None,
        }
    }

    pub fn zeroize(&mut self) {
        match self {
            Self::Enabled(config) => config.0.zeroize(),
            Self::UnknownUnsupported(material) => material.0.zeroize(),
            Self::Absent | Self::None => {}
        }
    }
}

impl VlessEncryptionConfig {
    fn parse(value: String) -> Option<Self> {
        let fields = value.split('.').collect::<Vec<_>>();
        if fields.len() < 4
            || fields[0] != "mlkem768x25519plus"
            || !matches!(fields[1], "native" | "xorpub" | "random")
            || !matches!(fields[2], "0rtt" | "1rtt")
        {
            return None;
        }
        let authenticator = fields.last()?;
        let bytes = URL_SAFE_NO_PAD.decode(authenticator).ok()?;
        if !matches!(bytes.len(), 32 | 1184) {
            return None;
        }
        Some(Self(value))
    }

    pub fn as_config_value(&self) -> &str {
        &self.0
    }

    pub fn safe_metadata(&self) -> &'static str {
        let fields = self.0.split('.').collect::<Vec<_>>();
        match (fields.get(1), fields.get(2)) {
            (Some(&"native"), Some(&"0rtt")) => "mlkem768x25519plus/native/0rtt",
            (Some(&"native"), Some(&"1rtt")) => "mlkem768x25519plus/native/1rtt",
            (Some(&"xorpub"), Some(&"0rtt")) => "mlkem768x25519plus/xorpub/0rtt",
            (Some(&"xorpub"), Some(&"1rtt")) => "mlkem768x25519plus/xorpub/1rtt",
            (Some(&"random"), Some(&"0rtt")) => "mlkem768x25519plus/random/0rtt",
            (Some(&"random"), Some(&"1rtt")) => "mlkem768x25519plus/random/1rtt",
            _ => "unknown",
        }
    }
}

impl VlessEncryptionMaterial {
    fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct Server {
    pub summary: ServerSummary,
    pub endpoint: ServerEndpoint,
    pub credential: String,
    pub security: Option<String>,
    pub sni: Option<String>,
    pub vless_encryption: VlessEncryption,
    /// Connection parameters are backend-only because they may contain credentials.
    pub options: HashMap<String, String>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub updated_at: String,
    pub server_count: usize,
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConnectionState {
    Idle,
    Preparing,
    ValidatingConfig,
    StartingCore,
    WaitingForProxy,
    SystemVpnStarting,
    SystemVpnConnected,
    #[serde(rename = "connected")]
    ProxyReady {
        socks_port: u16,
    },
    Stopping,
    Crashed {
        message: String,
    },
    Error {
        message: String,
    },
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSnapshot {
    pub connection: ConnectionState,
    pub servers: Vec<ServerSummary>,
    pub subscriptions: Vec<Subscription>,
    pub selected_server_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_persistence_round_trip_preserves_the_authoritative_value() {
        for endpoint in [
            ServerEndpoint::Domain("node.example".into()),
            ServerEndpoint::Ipv4("198.51.100.7".parse().unwrap()),
            ServerEndpoint::Ipv6("2001:db8::7".parse().unwrap()),
        ] {
            assert_eq!(endpoint.persistence_round_trip().unwrap(), endpoint);
        }
    }

    #[test]
    fn safe_summary_and_redaction_cannot_mutate_the_authoritative_endpoint() {
        let server = crate::subscription::parser::parse_uri(
            "vless://11111111-1111-1111-1111-111111111111@node.example:443?type=tcp#Synthetic",
        )
        .unwrap();
        let before = server.endpoint.canonical();
        let summary = serde_json::to_string(&server.summary).unwrap();
        assert!(!summary.contains(&before));
        let _safe = crate::core::xray::redaction::redact(&summary, std::slice::from_ref(&before));
        assert_eq!(server.endpoint.canonical(), before);
    }
}

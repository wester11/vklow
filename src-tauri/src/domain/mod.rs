use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerSummary {
    pub id: String,
    pub name: String,
    pub protocol: Protocol,
    pub address: String,
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

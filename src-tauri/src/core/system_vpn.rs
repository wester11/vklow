//! Strict credential-bearing session model for the elevated TUN helper.
//! No IPC field can select an executable, route, DNS server, shell command or
//! arbitrary JSON configuration.

use crate::{
    core::xray::config::{
        full_ipv4_tun_config, CommonVlessOutbound, VlessEncryptedTcpOutbound, VlessRealityOutbound,
    },
    domain::{Protocol, Server, ServerEndpoint, VlessEncryptionConfig},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const SYSTEM_VPN_SPEC_VERSION: u8 = 1;
pub const PINNED_EXPERIMENTAL_TUN_VERSION: &str = "v26.9.8";

/// A deliberately value-free explanation of why an imported normalized server
/// cannot enter the privileged System VPN flow.  These identifiers are safe to
/// surface in diagnostics; no URI field or credential is ever included.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum SystemVpnRejectionReason {
    UnsupportedProtocol,
    UnsupportedTransport,
    UnsupportedSecurity,
    PublicVlessRequiresTransportSecurityOrEncryption,
    PrivateVlessRequiresExplicitTrustedPolicy,
    UnroutableVlessEndpoint,
    UnsupportedFlow,
    MissingRealityPublicKey,
    MissingServerName,
    MissingFingerprint,
    InvalidShortId,
    ParserDroppedRealityMetadata,
    UnsupportedNormalizedVariant,
}

impl SystemVpnRejectionReason {
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedProtocol => "UnsupportedProtocol",
            Self::UnsupportedTransport => "UnsupportedTransport",
            Self::UnsupportedSecurity => "UnsupportedSecurity",
            Self::PublicVlessRequiresTransportSecurityOrEncryption => {
                "PublicVlessRequiresTransportSecurityOrEncryption"
            }
            Self::PrivateVlessRequiresExplicitTrustedPolicy => {
                "PrivateVlessRequiresExplicitTrustedPolicy"
            }
            Self::UnroutableVlessEndpoint => "UnroutableVlessEndpoint",
            Self::UnsupportedFlow => "UnsupportedFlow",
            Self::MissingRealityPublicKey => "MissingRealityPublicKey",
            Self::MissingServerName => "MissingServerName",
            Self::MissingFingerprint => "MissingFingerprint",
            Self::InvalidShortId => "InvalidShortId",
            Self::ParserDroppedRealityMetadata => "ParserDroppedRealityMetadata",
            Self::UnsupportedNormalizedVariant => "UnsupportedNormalizedVariant",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemVpnCompatibility {
    Eligible,
    Rejected(SystemVpnRejectionReason),
}

/// A safe compatibility record for development diagnostics.  Type fields are
/// constrained labels, while credential-bearing values remain private.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SafeSystemVpnCompatibilityDiagnostic {
    pub protocol: &'static str,
    pub transport: &'static str,
    pub security_type: &'static str,
    pub vless_encryption_field_present: bool,
    pub vless_encryption_status: &'static str,
    pub vless_encryption_metadata: Option<&'static str>,
    pub flow_type: &'static str,
    pub sni_present: bool,
    pub reality_public_key_present: bool,
    pub short_id_present: bool,
    pub fingerprint_present: bool,
    pub spider_x_present: bool,
    pub address_kind: &'static str,
    pub address_class: &'static str,
    pub compatibility: &'static str,
    pub rejection_reason: Option<SystemVpnRejectionReason>,
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemVpnMode {
    SystemIpv4Experimental,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct VlessRealityTcpSpec {
    pub address: String,
    pub port: u16,
    pub uuid: String,
    pub flow: Option<String>,
    pub server_name: String,
    pub fingerprint: String,
    pub public_key: String,
    pub short_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct VlessEncryptedTcpSpec {
    pub address: String,
    pub port: u16,
    pub uuid: String,
    pub flow: Option<String>,
    pub encryption: VlessEncryptionConfig,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "protocol", content = "settings", rename_all = "snake_case")]
pub enum SystemVpnOutbound {
    VlessRealityTcp(VlessRealityTcpSpec),
    VlessEncryptedTcp(VlessEncryptedTcpSpec),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SystemVpnSessionSpec {
    pub spec_version: u8,
    pub session_id: String,
    pub selected_server_id: String,
    pub mode: SystemVpnMode,
    pub outbound: SystemVpnOutbound,
}

impl SystemVpnSessionSpec {
    pub fn from_selected_server(server: &Server) -> Result<Self, String> {
        let outbound = outbound_from_server(server)?;
        let spec = Self {
            spec_version: SYSTEM_VPN_SPEC_VERSION,
            session_id: Uuid::new_v4().to_string(),
            selected_server_id: server.summary.id.clone(),
            mode: SystemVpnMode::SystemIpv4Experimental,
            outbound: match outbound {
                CommonVlessOutbound::RealityTcp(outbound) => {
                    SystemVpnOutbound::VlessRealityTcp(VlessRealityTcpSpec {
                        address: outbound.address,
                        port: outbound.port,
                        uuid: outbound.uuid,
                        flow: outbound.flow,
                        server_name: outbound.server_name,
                        fingerprint: outbound.fingerprint,
                        public_key: outbound.public_key,
                        short_id: outbound.short_id,
                    })
                }
                CommonVlessOutbound::EncryptedTcp(outbound) => {
                    SystemVpnOutbound::VlessEncryptedTcp(VlessEncryptedTcpSpec {
                        address: outbound.address,
                        port: outbound.port,
                        uuid: outbound.uuid,
                        flow: outbound.flow,
                        encryption: outbound.encryption,
                    })
                }
            },
        };
        spec.validate()?;
        Ok(spec)
    }

    pub fn adapter_name(&self) -> Result<String, String> {
        let session = Uuid::parse_str(&self.session_id).map_err(|_| "InvalidSystemVpnSession")?;
        Ok(format!(
            "VOID Tunnel {}",
            &session.simple().to_string()[..8]
        ))
    }

    pub fn config(&self) -> Result<serde_json::Value, String> {
        self.validate()?;
        full_ipv4_tun_config(&self.adapter_name()?, &self.outbound_config()?)
    }

    pub fn config_digest(&self) -> Result<String, String> {
        let bytes =
            serde_json::to_vec(&self.config()?).map_err(|_| "UnableToSerializeSystemVpnConfig")?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    pub(crate) fn sensitive_values(&self) -> Vec<String> {
        match &self.outbound {
            SystemVpnOutbound::VlessRealityTcp(value) => {
                let mut values = vec![
                    value.uuid.clone(),
                    value.public_key.clone(),
                    value.short_id.clone(),
                ];
                if let Some(flow) = &value.flow {
                    values.push(flow.clone());
                }
                values
            }
            SystemVpnOutbound::VlessEncryptedTcp(value) => {
                let mut values = vec![
                    value.uuid.clone(),
                    value.encryption.as_config_value().into(),
                ];
                if let Some(flow) = &value.flow {
                    values.push(flow.clone());
                }
                values
            }
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.spec_version != SYSTEM_VPN_SPEC_VERSION {
            return Err("UnsupportedSystemVpnSpecVersion".into());
        }
        Uuid::parse_str(&self.session_id).map_err(|_| "InvalidSystemVpnSession")?;
        Uuid::parse_str(&self.selected_server_id).map_err(|_| "InvalidSelectedServerId")?;
        if self.mode != SystemVpnMode::SystemIpv4Experimental {
            return Err("UnsupportedSystemVpnMode".into());
        }
        let outbound = self.outbound_config()?;
        // The shared config builder also validates shortId and Xray field shape.
        let _ = full_ipv4_tun_config(&self.adapter_name()?, &outbound)?;
        Ok(())
    }

    fn outbound_config(&self) -> Result<CommonVlessOutbound, String> {
        match &self.outbound {
            SystemVpnOutbound::VlessRealityTcp(value) => {
                validate_text(&value.address, 253, "InvalidSystemVpnAddress")?;
                validate_text(&value.server_name, 253, "InvalidSystemVpnServerName")?;
                validate_text(&value.fingerprint, 32, "InvalidSystemVpnFingerprint")?;
                validate_text(&value.public_key, 128, "InvalidSystemVpnPublicKey")?;
                if value.port == 0 {
                    return Err("InvalidSystemVpnPort".into());
                }
                Uuid::parse_str(&value.uuid).map_err(|_| "InvalidSystemVpnUserId")?;
                if let Some(flow) = &value.flow {
                    validate_text(flow, 64, "InvalidSystemVpnFlow")?;
                }
                Ok(CommonVlessOutbound::RealityTcp(VlessRealityOutbound {
                    address: value.address.clone(),
                    port: value.port,
                    uuid: value.uuid.clone(),
                    flow: value.flow.clone(),
                    server_name: value.server_name.clone(),
                    fingerprint: value.fingerprint.clone(),
                    public_key: value.public_key.clone(),
                    short_id: value.short_id.clone(),
                }))
            }
            SystemVpnOutbound::VlessEncryptedTcp(value) => {
                validate_text(&value.address, 253, "InvalidSystemVpnAddress")?;
                if value.port == 0 {
                    return Err("InvalidSystemVpnPort".into());
                }
                Uuid::parse_str(&value.uuid).map_err(|_| "InvalidSystemVpnUserId")?;
                if let Some(flow) = &value.flow {
                    validate_text(flow, 64, "InvalidSystemVpnFlow")?;
                }
                Ok(CommonVlessOutbound::EncryptedTcp(
                    VlessEncryptedTcpOutbound {
                        address: value.address.clone(),
                        port: value.port,
                        uuid: value.uuid.clone(),
                        flow: value.flow.clone(),
                        encryption: value.encryption.clone(),
                    },
                ))
            }
        }
    }
}

pub fn compatibility_for(server: &Server) -> SystemVpnCompatibility {
    if !matches!(server.summary.protocol, Protocol::Vless) {
        return SystemVpnCompatibility::Rejected(SystemVpnRejectionReason::UnsupportedProtocol);
    }
    if normalized_type(server.summary.transport.as_deref()) != "tcp" {
        return SystemVpnCompatibility::Rejected(SystemVpnRejectionReason::UnsupportedTransport);
    }
    let security = normalized_type(server.security.as_deref());
    if security == "none" {
        if server.vless_encryption.enabled_config().is_some() {
            return supported_vless_flow(server);
        }
        return SystemVpnCompatibility::Rejected(
            match authoritative_endpoint_for_system_vpn(server).classification() {
                "public" | "domain" => {
                    SystemVpnRejectionReason::PublicVlessRequiresTransportSecurityOrEncryption
                }
                "private" => SystemVpnRejectionReason::PrivateVlessRequiresExplicitTrustedPolicy,
                _ => SystemVpnRejectionReason::UnroutableVlessEndpoint,
            },
        );
    }
    if security != "reality" {
        return SystemVpnCompatibility::Rejected(SystemVpnRejectionReason::UnsupportedSecurity);
    }
    if let SystemVpnCompatibility::Rejected(reason) = supported_vless_flow(server) {
        return SystemVpnCompatibility::Rejected(reason);
    }
    if !has_nonempty(server.sni.as_deref())
        .or_else(|| has_nonempty(server.options.get("sni").map(String::as_str)))
        .unwrap_or(false)
    {
        return SystemVpnCompatibility::Rejected(SystemVpnRejectionReason::MissingServerName);
    }
    if !has_nonempty(server.options.get("pbk").map(String::as_str)).unwrap_or(false) {
        return SystemVpnCompatibility::Rejected(SystemVpnRejectionReason::MissingRealityPublicKey);
    }
    if !has_nonempty(server.options.get("fp").map(String::as_str)).unwrap_or(false) {
        return SystemVpnCompatibility::Rejected(SystemVpnRejectionReason::MissingFingerprint);
    }
    if let Some(short_id) = server.options.get("sid") {
        if !valid_short_id(short_id) {
            return SystemVpnCompatibility::Rejected(SystemVpnRejectionReason::InvalidShortId);
        }
    }
    SystemVpnCompatibility::Eligible
}

/// System VPN receives its endpoint only from the authoritative backend model;
/// `ServerSummary` intentionally has no address field and cannot be a source.
pub fn authoritative_endpoint_for_system_vpn(server: &Server) -> &ServerEndpoint {
    &server.endpoint
}

fn supported_vless_flow(server: &Server) -> SystemVpnCompatibility {
    if matches!(
        flow_type(server.options.get("flow").map(String::as_str)),
        "empty" | "xtls-rprx-vision" | "xtls-rprx-vision-udp443"
    ) {
        SystemVpnCompatibility::Eligible
    } else {
        SystemVpnCompatibility::Rejected(SystemVpnRejectionReason::UnsupportedFlow)
    }
}

pub fn compatibility_diagnostic(server: &Server) -> SafeSystemVpnCompatibilityDiagnostic {
    let compatibility = compatibility_for(server);
    let rejection_reason = match compatibility {
        SystemVpnCompatibility::Eligible => None,
        SystemVpnCompatibility::Rejected(reason) => Some(reason),
    };
    SafeSystemVpnCompatibilityDiagnostic {
        protocol: protocol_type(server.summary.protocol),
        transport: normalized_type(server.summary.transport.as_deref()),
        security_type: normalized_type(server.security.as_deref()),
        vless_encryption_field_present: server.vless_encryption.field_present(),
        vless_encryption_status: server.vless_encryption.safe_status(),
        vless_encryption_metadata: server
            .vless_encryption
            .enabled_config()
            .map(VlessEncryptionConfig::safe_metadata),
        flow_type: flow_type(server.options.get("flow").map(String::as_str)),
        sni_present: has_nonempty(server.sni.as_deref())
            .or_else(|| has_nonempty(server.options.get("sni").map(String::as_str)))
            .unwrap_or(false),
        reality_public_key_present: has_nonempty(server.options.get("pbk").map(String::as_str))
            .unwrap_or(false),
        short_id_present: has_nonempty(server.options.get("sid").map(String::as_str))
            .unwrap_or(false),
        fingerprint_present: has_nonempty(server.options.get("fp").map(String::as_str))
            .unwrap_or(false),
        spider_x_present: has_nonempty(server.options.get("spx").map(String::as_str))
            .unwrap_or(false),
        address_kind: authoritative_endpoint_for_system_vpn(server).kind().code(),
        address_class: authoritative_endpoint_for_system_vpn(server).classification(),
        compatibility: if rejection_reason.is_some() {
            "rejected"
        } else {
            "eligible"
        },
        rejection_reason,
    }
}

pub fn outbound_from_server(server: &Server) -> Result<CommonVlessOutbound, String> {
    if let SystemVpnCompatibility::Rejected(reason) = compatibility_for(server) {
        return Err(reason.code().into());
    }
    let security = normalized_type(server.security.as_deref());
    if security == "none" {
        return server
            .vless_encryption
            .enabled_config()
            .cloned()
            .map(|encryption| {
                CommonVlessOutbound::EncryptedTcp(VlessEncryptedTcpOutbound {
                    address: authoritative_endpoint_for_system_vpn(server).authority_value(),
                    port: server.summary.port,
                    uuid: server.credential.clone(),
                    flow: server.options.get("flow").cloned(),
                    encryption,
                })
            })
            .ok_or_else(|| "MissingVlessEncryptionMaterial".into());
    }
    let option = |key| server.options.get(key).cloned().unwrap_or_default();
    Ok(CommonVlessOutbound::RealityTcp(VlessRealityOutbound {
        address: authoritative_endpoint_for_system_vpn(server).authority_value(),
        port: server.summary.port,
        uuid: server.credential.clone(),
        flow: server.options.get("flow").cloned(),
        server_name: server.sni.clone().unwrap_or_else(|| option("sni")),
        fingerprint: option("fp"),
        public_key: option("pbk"),
        short_id: option("sid"),
    }))
}

fn protocol_type(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Vless => "vless",
        Protocol::Vmess => "vmess",
        Protocol::Shadowsocks => "shadowsocks",
        Protocol::Trojan => "trojan",
    }
}

fn normalized_type(value: Option<&str>) -> &'static str {
    match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("tcp") | Some("raw") => "tcp",
        Some("reality") => "reality",
        Some("tls") => "tls",
        Some("none") => "none",
        Some("grpc") => "grpc",
        Some("ws") | Some("websocket") => "websocket",
        Some("") | None => "empty",
        Some(_) => "other",
    }
}

fn flow_type(value: Option<&str>) -> &'static str {
    match value.map(str::trim) {
        None | Some("") => "empty",
        Some("xtls-rprx-vision") => "xtls-rprx-vision",
        Some("xtls-rprx-vision-udp443") => "xtls-rprx-vision-udp443",
        Some(_) => "other",
    }
}

fn has_nonempty(value: Option<&str>) -> Option<bool> {
    value.map(|value| !value.trim().is_empty())
}

fn valid_short_id(value: &str) -> bool {
    value.len() <= 16
        && value.len().is_multiple_of(2)
        && value.bytes().all(|character| character.is_ascii_hexdigit())
}

fn validate_text(value: &str, limit: usize, error: &'static str) -> Result<(), String> {
    if value.is_empty() || value.len() > limit || value.chars().any(char::is_control) {
        return Err(error.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        ServerEndpoint, ServerEndpointKind, ServerHealth, ServerSummary, VlessEncryption,
    };
    use std::collections::HashMap;

    fn fixture() -> Server {
        Server {
            summary: ServerSummary {
                id: "11111111-1111-1111-1111-111111111111".into(),
                name: "fixture".into(),
                protocol: Protocol::Vless,
                endpoint_kind: ServerEndpointKind::Domain,
                port: 443,
                transport: Some("tcp".into()),
                country: None,
                health: ServerHealth::Unknown,
                latency_ms: None,
            },
            endpoint: ServerEndpoint::Domain("edge.example".into()),
            credential: "22222222-2222-2222-2222-222222222222".into(),
            security: Some("reality".into()),
            sni: Some("www.example.com".into()),
            vless_encryption: VlessEncryption::Absent,
            options: HashMap::from([
                ("fp".into(), "chrome".into()),
                ("pbk".into(), "public-key".into()),
                ("sid".into(), "aabb".into()),
                ("flow".into(), "xtls-rprx-vision".into()),
            ]),
        }
    }

    #[test]
    fn selected_vless_reality_builds_only_fixed_system_ipv4_config() {
        let spec = SystemVpnSessionSpec::from_selected_server(&fixture()).unwrap();
        let config = spec.config().unwrap();
        assert_eq!(config["inbounds"][0]["settings"]["dns"][0], "1.1.1.1");
        assert_eq!(
            config["inbounds"][0]["settings"]["autoSystemRoutingTable"][0],
            "0.0.0.0/1"
        );
        assert_eq!(config["outbounds"][0]["protocol"], "vless");
    }

    #[test]
    fn rejects_invalid_specs_before_helper_or_uac() {
        let mut spec = SystemVpnSessionSpec::from_selected_server(&fixture()).unwrap();
        spec.spec_version = 99;
        assert_eq!(
            spec.validate().unwrap_err(),
            "UnsupportedSystemVpnSpecVersion"
        );
        spec.spec_version = SYSTEM_VPN_SPEC_VERSION;
        spec.selected_server_id = "not-a-uuid".into();
        assert_eq!(spec.validate().unwrap_err(), "InvalidSelectedServerId");
        spec.selected_server_id = fixture().summary.id;
        let SystemVpnOutbound::VlessRealityTcp(outbound) = &mut spec.outbound else {
            panic!("fixture must remain a Reality outbound");
        };
        outbound.port = 0;
        assert_eq!(spec.validate().unwrap_err(), "InvalidSystemVpnPort");
    }

    #[test]
    fn rejects_unsupported_protocol_without_silent_freedom_fallback() {
        let mut server = fixture();
        server.summary.protocol = Protocol::Trojan;
        assert_eq!(
            SystemVpnSessionSpec::from_selected_server(&server)
                .err()
                .unwrap(),
            "UnsupportedProtocol"
        );
    }

    #[test]
    fn diagnosis_is_value_free_and_allows_empty_reality_flow() {
        let mut server = fixture();
        server.options.insert("flow".into(), String::new());
        server.options.insert("spx".into(), "/fake-path".into());
        let diagnostic = compatibility_diagnostic(&server);
        assert_eq!(diagnostic.protocol, "vless");
        assert_eq!(diagnostic.transport, "tcp");
        assert_eq!(diagnostic.security_type, "reality");
        assert_eq!(diagnostic.flow_type, "empty");
        assert!(diagnostic.spider_x_present);
        assert_eq!(diagnostic.compatibility, "eligible");
        assert_eq!(diagnostic.rejection_reason, None);
    }

    #[test]
    fn tls_is_reported_as_a_specific_unsupported_security_variant() {
        let mut server = fixture();
        server.security = Some("tls".into());
        let diagnostic = compatibility_diagnostic(&server);
        assert_eq!(diagnostic.security_type, "tls");
        assert_eq!(
            diagnostic.rejection_reason,
            Some(SystemVpnRejectionReason::UnsupportedSecurity)
        );
    }

    #[test]
    fn plain_vless_is_rejected_before_uac_or_config_generation() {
        let mut server = fixture();
        server.security = Some("none".into());
        server.endpoint = ServerEndpoint::Ipv4("198.51.100.7".parse().unwrap());
        assert_eq!(
            SystemVpnSessionSpec::from_selected_server(&server)
                .err()
                .unwrap(),
            "PublicVlessRequiresTransportSecurityOrEncryption"
        );
    }

    #[test]
    fn unspecified_vless_endpoint_is_rejected_before_uac_or_config_generation() {
        assert_eq!(
            crate::subscription::parser::parse_uri(
                "vless://11111111-1111-1111-1111-111111111111@0.0.0.0:443?type=tcp"
            )
            .err()
            .unwrap(),
            "InvalidServerAddress"
        );
    }

    #[test]
    fn public_vless_with_typed_protocol_encryption_builds_a_system_vpn_config() {
        let mut server = fixture();
        server.endpoint = ServerEndpoint::Ipv4("198.51.100.7".parse().unwrap());
        server.security = Some("none".into());
        server.vless_encryption = VlessEncryption::from_sharing_link(Some("mlkem768x25519plus.native.1rtt.100-111-1111.75-0-111.50-0-3333.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()));
        let diagnostic = compatibility_diagnostic(&server);
        assert_eq!(diagnostic.address_class, "public");
        assert_eq!(diagnostic.vless_encryption_status, "enabled");
        let config = SystemVpnSessionSpec::from_selected_server(&server)
            .unwrap()
            .config()
            .unwrap();
        assert_eq!(
            config["outbounds"][0]["settings"]["vnext"][0]["users"][0]["encryption"],
            serde_json::json!("mlkem768x25519plus.native.1rtt.100-111-1111.75-0-111.50-0-3333.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        );
        assert_eq!(config["outbounds"][0]["streamSettings"]["security"], "none");
    }

    #[test]
    fn system_vpn_uses_the_authoritative_endpoint_not_the_safe_summary() {
        let server = fixture();
        let summary = serde_json::to_string(&server.summary).unwrap();
        assert!(!summary.contains("edge.example"));
        assert_eq!(
            authoritative_endpoint_for_system_vpn(&server).canonical(),
            "edge.example"
        );
        let CommonVlessOutbound::RealityTcp(outbound) = outbound_from_server(&server).unwrap()
        else {
            panic!("fixture must build a Reality outbound");
        };
        assert_eq!(outbound.address, "edge.example");
    }

    #[test]
    fn synthetic_vless_encryption_config_validates_with_the_pinned_core_when_enabled() {
        if std::env::var_os("VOID_XRAY_VLESS_ENCRYPTION_VALIDATION").is_none() {
            return;
        }
        let app_data = std::env::var_os("APPDATA")
            .map(std::path::PathBuf::from)
            .expect("APPDATA must be available")
            .join("com.void.desktop");
        let mut server = fixture();
        server.endpoint = ServerEndpoint::Ipv4("198.51.100.7".parse().unwrap());
        server.security = Some("none".into());
        server.vless_encryption = VlessEncryption::from_sharing_link(Some("mlkem768x25519plus.native.1rtt.100-111-1111.75-0-111.50-0-3333.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()));
        let spec = SystemVpnSessionSpec::from_selected_server(&server).unwrap();
        crate::core::xray::manager::XrayCoreManager::load(app_data)
            .preflight_system_vpn(&spec)
            .expect("pinned Xray must accept the synthetic VLESS Encryption config");
    }
}

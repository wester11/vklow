//! Strict credential-bearing session model for the elevated TUN helper.
//! No IPC field can select an executable, route, DNS server, shell command or
//! arbitrary JSON configuration.

use crate::{
    core::xray::config::{full_ipv4_tun_config, VlessRealityOutbound},
    domain::{Protocol, Server},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const SYSTEM_VPN_SPEC_VERSION: u8 = 1;
pub const PINNED_EXPERIMENTAL_TUN_VERSION: &str = "v26.9.8";

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
#[serde(tag = "protocol", content = "settings", rename_all = "snake_case")]
pub enum SystemVpnOutbound {
    VlessRealityTcp(VlessRealityTcpSpec),
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
            outbound: SystemVpnOutbound::VlessRealityTcp(VlessRealityTcpSpec {
                address: outbound.address,
                port: outbound.port,
                uuid: outbound.uuid,
                flow: outbound.flow,
                server_name: outbound.server_name,
                fingerprint: outbound.fingerprint,
                public_key: outbound.public_key,
                short_id: outbound.short_id,
            }),
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

    fn outbound_config(&self) -> Result<VlessRealityOutbound, String> {
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
                Ok(VlessRealityOutbound {
                    address: value.address.clone(),
                    port: value.port,
                    uuid: value.uuid.clone(),
                    flow: value.flow.clone(),
                    server_name: value.server_name.clone(),
                    fingerprint: value.fingerprint.clone(),
                    public_key: value.public_key.clone(),
                    short_id: value.short_id.clone(),
                })
            }
        }
    }
}

pub fn outbound_from_server(server: &Server) -> Result<VlessRealityOutbound, String> {
    if !matches!(server.summary.protocol, Protocol::Vless)
        || server.security.as_deref() != Some("reality")
    {
        return Err("UnsupportedServerForSystemVpn".into());
    }
    let option = |key| server.options.get(key).cloned().unwrap_or_default();
    Ok(VlessRealityOutbound {
        address: server.summary.address.clone(),
        port: server.summary.port,
        uuid: server.credential.clone(),
        flow: server.options.get("flow").cloned(),
        server_name: server.sni.clone().unwrap_or_else(|| option("sni")),
        fingerprint: option("fp"),
        public_key: option("pbk"),
        short_id: option("sid"),
    })
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
    use crate::domain::{ServerHealth, ServerSummary};
    use std::collections::HashMap;

    fn fixture() -> Server {
        Server {
            summary: ServerSummary {
                id: "11111111-1111-1111-1111-111111111111".into(),
                name: "fixture".into(),
                protocol: Protocol::Vless,
                address: "edge.example".into(),
                port: 443,
                transport: Some("tcp".into()),
                country: None,
                health: ServerHealth::Unknown,
                latency_ms: None,
            },
            credential: "22222222-2222-2222-2222-222222222222".into(),
            security: Some("reality".into()),
            sni: Some("www.example.com".into()),
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
        let SystemVpnOutbound::VlessRealityTcp(outbound) = &mut spec.outbound;
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
            "UnsupportedServerForSystemVpn"
        );
    }
}

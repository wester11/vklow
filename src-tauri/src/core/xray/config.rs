use crate::domain::VlessEncryptionConfig;
use serde::Serialize;
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunInboundSettings {
    pub name: String,
    pub desc: String,
    pub mtu: u32,
    pub gateway: Vec<String>,
    pub dns: Vec<String>,
    pub auto_system_routing_table: Vec<String>,
    pub auto_outbounds_interface: String,
}
#[derive(Clone, Serialize)]
struct TunInbound {
    port: u16,
    protocol: &'static str,
    settings: TunInboundSettings,
}
#[derive(Serialize)]
struct TunValidationConfig {
    inbounds: Vec<TunInbound>,
    outbounds: Vec<serde_json::Value>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VlessRealityOutbound {
    pub address: String,
    pub port: u16,
    pub uuid: String,
    pub flow: Option<String>,
    pub server_name: String,
    pub fingerprint: String,
    pub public_key: String,
    pub short_id: String,
}

#[derive(Clone)]
pub struct VlessEncryptedTcpOutbound {
    pub address: String,
    pub port: u16,
    pub uuid: String,
    pub flow: Option<String>,
    pub encryption: VlessEncryptionConfig,
}

#[derive(Clone)]
pub enum CommonVlessOutbound {
    RealityTcp(VlessRealityOutbound),
    EncryptedTcp(VlessEncryptedTcpOutbound),
}
pub fn vless_reality_tcp(
    input: &VlessRealityOutbound,
    socks_port: u16,
) -> Result<serde_json::Value, String> {
    let outbound = vless_reality_outbound(input)?;
    Ok(
        serde_json::json!({"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":socks_port,"protocol":"socks","settings":{"udp":true}}],"outbounds":[outbound]}),
    )
}

pub fn vless_encrypted_tcp(
    input: &VlessEncryptedTcpOutbound,
    socks_port: u16,
) -> Result<serde_json::Value, String> {
    let outbound = common_vless_outbound(&CommonVlessOutbound::EncryptedTcp(input.clone()))?;
    Ok(
        serde_json::json!({"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":socks_port,"protocol":"socks","settings":{"udp":true}}],"outbounds":[outbound]}),
    )
}

/// Backend-only common production outbound. It deliberately has no knowledge
/// of SOCKS, TUN, frontend input or any runtime filesystem location.
pub fn vless_reality_outbound(input: &VlessRealityOutbound) -> Result<serde_json::Value, String> {
    if input.address.is_empty() || input.server_name.is_empty() || input.public_key.is_empty() {
        return Err("Reality-конфигурация неполная".into());
    }
    if input.short_id.len() > 16
        || !input.short_id.len().is_multiple_of(2)
        || !input.short_id.bytes().all(|c| c.is_ascii_hexdigit())
    {
        return Err(
            "Reality shortId должен быть пустой или чётной hex-строкой до 16 символов".into(),
        );
    }
    Ok(
        serde_json::json!({"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":input.address,"port":input.port,"users":[{"id":input.uuid,"encryption":"none","flow":input.flow}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":input.server_name,"fingerprint":input.fingerprint,"password":input.public_key,"shortId":input.short_id}}}),
    )
}

/// The only common credential-bearing VLESS outbound surface. Both SOCKS and
/// System VPN call this builder; neither can inject arbitrary Xray JSON.
pub fn common_vless_outbound(input: &CommonVlessOutbound) -> Result<serde_json::Value, String> {
    match input {
        CommonVlessOutbound::RealityTcp(value) => vless_reality_outbound(value),
        CommonVlessOutbound::EncryptedTcp(value) => {
            if value.address.is_empty() || value.port == 0 || value.uuid.is_empty() {
                return Err("VlessEncryption-конфигурация неполная".into());
            }
            if let Some(flow) = &value.flow {
                if !matches!(
                    flow.as_str(),
                    "" | "xtls-rprx-vision" | "xtls-rprx-vision-udp443"
                ) {
                    return Err("VLESS flow не поддерживается".into());
                }
            }
            Ok(
                serde_json::json!({"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":value.address,"port":value.port,"users":[{"id":value.uuid,"encryption":value.encryption.as_config_value(),"flow":value.flow}]}]},"streamSettings":{"network":"tcp","security":"none"}}),
            )
        }
    }
}
pub fn loopback_freedom_socks(socks_port: u16) -> serde_json::Value {
    serde_json::json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks", "settings": {"udp": true}}],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}]
    })
}
pub fn tun_capability_config() -> Result<serde_json::Value, String> {
    serde_json::to_value(TunValidationConfig {
        inbounds: vec![TunInbound {
            port: 0,
            protocol: "tun",
            settings: TunInboundSettings {
                name: "VOID Capability Probe".into(),
                desc: "VOID Desktop".into(),
                mtu: 1500,
                gateway: vec!["172.30.0.1/30".into()],
                dns: vec!["1.1.1.1".into()],
                auto_system_routing_table: Vec::new(),
                auto_outbounds_interface: "auto".into(),
            },
        }],
        outbounds: vec![serde_json::json!({"protocol": "freedom"})],
    })
    .map_err(|_| "Не удалось сериализовать TUN capability config".into())
}
pub const SCOPED_SMOKE_ROUTE: &str = "1.1.1.1/32";
pub const FULL_IPV4_ROUTES: [&str; 2] = ["0.0.0.0/1", "128.0.0.0/1"];
pub const FULL_IPV4_TUN_DNS: [&str; 2] = ["1.1.1.1", "1.0.0.1"];

pub fn scoped_tun_smoke_config(adapter_name: &str) -> Result<serde_json::Value, String> {
    if adapter_name.len() > 96
        || adapter_name.is_empty()
        || !adapter_name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, ' ' | '-'))
    {
        return Err("Недопустимое имя VOID TUN adapter".into());
    }
    serde_json::to_value(TunValidationConfig {
        inbounds: vec![TunInbound {
            port: 0,
            protocol: "tun",
            settings: TunInboundSettings {
                name: adapter_name.into(),
                desc: "VOID Experimental TUN".into(),
                mtu: 1500,
                gateway: vec!["198.18.0.1/30".into()],
                dns: Vec::new(),
                auto_system_routing_table: vec![SCOPED_SMOKE_ROUTE.into()],
                auto_outbounds_interface: "auto".into(),
            },
        }],
        outbounds: vec![serde_json::json!({"tag":"direct","protocol":"freedom"})],
    })
    .map_err(|_| "Не удалось сериализовать scoped TUN config".into())
}

/// Development-only full IPv4 proof configuration. The two /1 routes retain
/// the physical /0 as Xray's underlying uplink and deliberately add no IPv6.
pub fn full_ipv4_freedom_config(adapter_name: &str) -> Result<serde_json::Value, String> {
    if adapter_name.len() > 96
        || adapter_name.is_empty()
        || !adapter_name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, ' ' | '-'))
    {
        return Err("Недопустимое имя VOID TUN adapter".into());
    }
    serde_json::to_value(TunValidationConfig {
        inbounds: vec![TunInbound {
            port: 0,
            protocol: "tun",
            settings: TunInboundSettings {
                name: adapter_name.into(),
                desc: "VOID Experimental Full IPv4 TUN".into(),
                mtu: 1500,
                gateway: vec!["198.18.0.1/30".into()],
                dns: FULL_IPV4_TUN_DNS
                    .iter()
                    .map(|value| (*value).into())
                    .collect(),
                auto_system_routing_table: FULL_IPV4_ROUTES
                    .iter()
                    .map(|value| (*value).into())
                    .collect(),
                auto_outbounds_interface: "auto".into(),
            },
        }],
        outbounds: vec![serde_json::json!({"tag":"direct","protocol":"freedom"})],
    })
    .map_err(|_| "Не удалось сериализовать full IPv4 TUN config".into())
}

pub fn full_ipv4_tun_config(
    adapter_name: &str,
    outbound: &CommonVlessOutbound,
) -> Result<serde_json::Value, String> {
    if adapter_name.len() > 96
        || adapter_name.is_empty()
        || !adapter_name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, ' ' | '-'))
    {
        return Err("Недопустимое имя VOID TUN adapter".into());
    }
    serde_json::to_value(TunValidationConfig {
        inbounds: vec![TunInbound {
            port: 0,
            protocol: "tun",
            settings: TunInboundSettings {
                name: adapter_name.into(),
                desc: "VOID Experimental System VPN IPv4".into(),
                mtu: 1500,
                gateway: vec!["198.18.0.1/30".into()],
                dns: FULL_IPV4_TUN_DNS
                    .iter()
                    .map(|value| (*value).into())
                    .collect(),
                auto_system_routing_table: FULL_IPV4_ROUTES
                    .iter()
                    .map(|value| (*value).into())
                    .collect(),
                auto_outbounds_interface: "auto".into(),
            },
        }],
        outbounds: vec![common_vless_outbound(outbound)?],
    })
    .map_err(|_| "Не удалось сериализовать System VPN TUN config".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn makes_loopback_reality_config() {
        let c = vless_reality_tcp(
            &VlessRealityOutbound {
                address: "edge.example".into(),
                port: 443,
                uuid: "11111111-1111-1111-1111-111111111111".into(),
                flow: Some("xtls-rprx-vision".into()),
                server_name: "www.example.com".into(),
                fingerprint: "chrome".into(),
                public_key: "public".into(),
                short_id: "aabb".into(),
            },
            32145,
        )
        .unwrap();
        assert_eq!(c["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(c["outbounds"][0]["streamSettings"]["security"], "reality");
    }
    #[test]
    fn uses_current_xray_tun_field_shapes() {
        let value = tun_capability_config().unwrap();
        assert!(value["inbounds"][0]["settings"]["autoSystemRoutingTable"].is_array());
        assert_eq!(
            value["inbounds"][0]["settings"]["autoOutboundsInterface"],
            "auto"
        );
    }
    #[test]
    fn scopes_experimental_tun_to_the_single_approved_route() {
        let value = scoped_tun_smoke_config("VOID Tunnel 1234").unwrap();
        let settings = &value["inbounds"][0]["settings"];
        assert_eq!(settings["dns"], serde_json::json!([]));
        assert_eq!(
            settings["autoSystemRoutingTable"],
            serde_json::json!([SCOPED_SMOKE_ROUTE])
        );
        assert_eq!(settings["autoOutboundsInterface"], "auto");
        assert_ne!(
            settings["autoSystemRoutingTable"],
            serde_json::json!(["0.0.0.0/0"])
        );
    }
    #[test]
    fn full_ipv4_policy_uses_only_the_two_fail_open_routes() {
        let value = full_ipv4_freedom_config("VOID Tunnel 1234").unwrap();
        let settings = &value["inbounds"][0]["settings"];
        assert_eq!(
            settings["autoSystemRoutingTable"],
            serde_json::json!(FULL_IPV4_ROUTES)
        );
        assert_eq!(settings["dns"], serde_json::json!(FULL_IPV4_TUN_DNS));
        assert_eq!(settings["autoOutboundsInterface"], "auto");
        assert_ne!(
            settings["autoSystemRoutingTable"],
            serde_json::json!(["0.0.0.0/0"])
        );
    }
    #[test]
    fn proxy_and_system_vpn_use_the_same_server_outbound() {
        let server = VlessRealityOutbound {
            address: "edge.example".into(),
            port: 443,
            uuid: "11111111-1111-1111-1111-111111111111".into(),
            flow: Some("xtls-rprx-vision".into()),
            server_name: "www.example.com".into(),
            fingerprint: "chrome".into(),
            public_key: "public".into(),
            short_id: "aabb".into(),
        };
        let proxy = vless_reality_tcp(&server, 32145).unwrap();
        let tun = full_ipv4_tun_config(
            "VOID Tunnel fixture",
            &CommonVlessOutbound::RealityTcp(server.clone()),
        )
        .unwrap();
        assert_eq!(
            proxy["outbounds"][0],
            vless_reality_outbound(&server).unwrap()
        );
        assert_eq!(tun["outbounds"][0], proxy["outbounds"][0]);
    }

    #[test]
    fn encrypted_vless_uses_protocol_encryption_not_transport_security() {
        let encryption = crate::domain::VlessEncryption::from_sharing_link(Some("mlkem768x25519plus.native.1rtt.100-111-1111.75-0-111.50-0-3333.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()));
        let outbound = VlessEncryptedTcpOutbound {
            address: "198.51.100.7".into(),
            port: 443,
            uuid: "11111111-1111-1111-1111-111111111111".into(),
            flow: None,
            encryption: encryption.enabled_config().unwrap().clone(),
        };
        let proxy = vless_encrypted_tcp(&outbound, 32145).unwrap();
        let tun = full_ipv4_tun_config(
            "VOID Tunnel fixture",
            &CommonVlessOutbound::EncryptedTcp(outbound),
        )
        .unwrap();
        assert_eq!(
            proxy["outbounds"][0]["settings"]["vnext"][0]["users"][0]["encryption"],
            serde_json::json!("mlkem768x25519plus.native.1rtt.100-111-1111.75-0-111.50-0-3333.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        );
        assert_eq!(proxy["outbounds"][0]["streamSettings"]["security"], "none");
        assert_eq!(tun["outbounds"][0], proxy["outbounds"][0]);
    }
}

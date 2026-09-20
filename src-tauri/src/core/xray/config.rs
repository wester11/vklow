use serde::Serialize;
#[derive(Serialize)]
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
#[derive(Serialize)]
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
#[derive(Serialize)]
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
pub fn vless_reality_tcp(
    input: &VlessRealityOutbound,
    socks_port: u16,
) -> Result<serde_json::Value, String> {
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
        serde_json::json!({"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":socks_port,"protocol":"socks","settings":{"udp":true}}],"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":input.address,"port":input.port,"users":[{"id":input.uuid,"encryption":"none","flow":input.flow}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":input.server_name,"fingerprint":input.fingerprint,"password":input.public_key,"shortId":input.short_id}}}]}),
    )
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
}

use serde::Serialize;
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
}

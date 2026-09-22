use crate::domain::{Protocol, Server, ServerHealth, ServerSummary};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use std::collections::HashMap;
use url::Url;
use uuid::Uuid;
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
    address: String,
    port: u16,
    transport: Option<String>,
    credential: String,
    security: Option<String>,
    sni: Option<String>,
    options: HashMap<String, String>,
}
fn base_server(input: ServerInput) -> Server {
    Server {
        summary: ServerSummary {
            id: Uuid::new_v4().to_string(),
            name: if input.name.trim().is_empty() {
                format!("{}:{}", input.address, input.port)
            } else {
                input.name
            },
            protocol: input.protocol,
            address: input.address,
            port: input.port,
            transport: input.transport,
            country: None,
            health: ServerHealth::Unknown,
            latency_ms: None,
        },
        credential: input.credential,
        security: input.security,
        sni: input.sni,
        options: input.options,
    }
}
fn parse_standard(input: &str, protocol: Protocol) -> Result<Server, String> {
    let url = Url::parse(input).map_err(|_| "Некорректный URI")?;
    let address = url.host_str().ok_or("В URI отсутствует сервер")?.to_owned();
    let port = url.port().unwrap_or(443);
    let credential = url.username();
    if credential.is_empty() {
        return Err("В URI отсутствуют учётные данные".into());
    }
    if matches!(protocol, Protocol::Vless) && Uuid::parse_str(credential).is_err() {
        return Err("VLESS URI содержит некорректный UUID".into());
    }
    let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
    let name = percent_decode_str(url.fragment().unwrap_or_default())
        .decode_utf8_lossy()
        .into_owned();
    Ok(base_server(ServerInput {
        protocol,
        name,
        address,
        port,
        transport: query.get("type").cloned(),
        credential: credential.to_owned(),
        security: query.get("security").cloned(),
        sni: query.get("sni").cloned(),
        options: query,
    }))
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
    let address = url.host_str().ok_or("В URI отсутствует сервер")?.to_owned();
    let port = url.port().ok_or("В URI отсутствует порт")?;
    let password = url.password().ok_or("В URI отсутствует пароль")?;
    Ok(base_server(ServerInput {
        protocol: Protocol::Shadowsocks,
        name: name.to_owned(),
        address,
        port,
        transport: None,
        credential: format!("{}:{}", url.username(), password),
        security: None,
        sni: None,
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
    Ok(base_server(ServerInput {
        protocol: Protocol::Vmess,
        name: item.name,
        address: item.address,
        port,
        transport: (!item.transport.is_empty()).then_some(item.transport),
        credential: item.id,
        security: (!item.tls.is_empty()).then_some(item.tls),
        sni: (!item.sni.is_empty()).then_some(item.sni),
        options: HashMap::new(),
    }))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_vless_reality() {
        let item = parse_uri("vless://11111111-1111-1111-1111-111111111111@node.example:443?security=reality&type=grpc&sni=site.example#NL%20Edge").unwrap();
        assert_eq!(item.summary.address, "node.example");
        assert_eq!(item.summary.port, 443);
        assert_eq!(item.summary.name, "NL Edge");
        assert!(matches!(item.summary.protocol, Protocol::Vless));
        assert_eq!(item.options["security"], "reality");
    }

    #[test]
    fn preserves_vless_tcp_reality_metadata_in_the_normalized_model() {
        let item = parse_uri("vless://11111111-1111-1111-1111-111111111111@198.51.100.7:8443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=cover.example&pbk=fake-public-key&sid=aabb&fp=chrome&spx=%2Ffake-spider#Synthetic").unwrap();
        assert_eq!(item.summary.address, "198.51.100.7");
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
    fn rejects_unknown_scheme() {
        assert!(parse_uri("file:///etc/passwd").is_err());
    }
    #[test]
    fn rejects_invalid_vless_uuid() {
        assert!(parse_uri("vless://not-a-uuid@node.example:443#bad").is_err());
    }
}

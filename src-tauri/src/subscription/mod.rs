pub mod parser;
use self::parser::{inspect_uri_authority, parse_uri, RawAuthorityObservation};
use crate::{
    core::secrets::{subscription_url_key, SecretStore},
    domain::{Server, Subscription},
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::{redirect::Policy, Client};
use url::Url;
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_SERVER_COUNT: usize = 500;

/// Shared production import transaction. Both the Tauri command and the
/// development-only stdin tool use this exact HTTPS fetch, parse and secure
/// storage path; the latter never gets a weaker parser or storage shortcut.
pub struct ImportedSubscription {
    pub subscription: Subscription,
    pub servers: Vec<Server>,
}

/// Development-only consumers use this value-free/raw-authority split to
/// trace a fetched VLESS entry without printing or persisting its URI.
pub struct VlessEndpointProvenanceEntry {
    pub raw: RawAuthorityObservation,
    pub parsed: Result<Server, String>,
}

pub async fn import_https_subscription(
    source: &str,
    secrets: &dyn SecretStore,
) -> Result<ImportedSubscription, String> {
    let url = Url::parse(source).map_err(|_| "Укажите корректный URL подписки")?;
    if url.scheme() != "https" {
        return Err("Подписка принимается только по HTTPS".into());
    }
    let name = url
        .host_str()
        .ok_or("В URL подписки отсутствует хост")?
        .to_owned();
    let servers = fetch_and_parse(source).await?;
    let id = uuid::Uuid::new_v4().to_string();
    secrets.set(&subscription_url_key(&id), source)?;
    Ok(ImportedSubscription {
        subscription: Subscription {
            id,
            name,
            updated_at: chrono::Utc::now().to_rfc3339(),
            server_count: servers.len(),
        },
        servers,
    })
}
pub async fn fetch_and_parse(source: &str) -> Result<Vec<Server>, String> {
    let url = Url::parse(source).map_err(|_| "Укажите корректный URL подписки")?;
    if url.scheme() != "https" {
        return Err("Подписка принимается только по HTTPS".into());
    }
    if url.host_str().is_none() {
        return Err("В URL подписки отсутствует хост".into());
    }
    let body = fetch_subscription_text(source).await?;
    parse_subscription_text(&body)
}

pub async fn fetch_subscription_text(source: &str) -> Result<String, String> {
    let url = Url::parse(source).map_err(|_| "Укажите корректный URL подписки")?;
    if url.scheme() != "https" {
        return Err("Подписка принимается только по HTTPS".into());
    }
    if url.host_str().is_none() {
        return Err("В URL подписки отсутствует хост".into());
    }
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .redirect(Policy::limited(3))
        .user_agent("VOID-Desktop/0.1")
        .build()
        .map_err(|e| e.to_string())?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|_| "Не удалось получить подписку: проверьте сеть и адрес")?
        .error_for_status()
        .map_err(|_| "Сервер подписки вернул ошибку")?;
    if response
        .content_length()
        .is_some_and(|size| size as usize > MAX_RESPONSE_BYTES)
    {
        return Err("Ответ подписки превышает допустимый размер".into());
    }
    let body = response
        .bytes()
        .await
        .map_err(|_| "Не удалось прочитать ответ подписки")?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err("Ответ подписки превышает допустимый размер".into());
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}
pub fn parse_subscription_text(body: &str) -> Result<Vec<Server>, String> {
    let content = decode_subscription(body).unwrap_or_else(|| body.trim().to_owned());
    let mut servers = Vec::new();
    for line in content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(MAX_SERVER_COUNT + 1)
    {
        match parse_uri(line) {
            Ok(server) => servers.push(server),
            Err(error)
                if line
                    .get(..8)
                    .is_some_and(|scheme| scheme.eq_ignore_ascii_case("vless://")) =>
            {
                return Err(error);
            }
            Err(_) => {}
        }
    }
    if servers.len() > MAX_SERVER_COUNT {
        return Err("Подписка содержит слишком много серверов".into());
    }
    if servers.is_empty() {
        return Err("В подписке не найдено поддерживаемых конфигураций".into());
    }
    Ok(servers)
}

pub fn inspect_vless_endpoint_provenance(body: &str) -> Vec<VlessEndpointProvenanceEntry> {
    let content = decode_subscription(body).unwrap_or_else(|| body.trim().to_owned());
    content
        .lines()
        .map(str::trim)
        .filter(|line| {
            line.get(..8)
                .is_some_and(|scheme| scheme.eq_ignore_ascii_case("vless://"))
        })
        .take(MAX_SERVER_COUNT)
        .map(|line| VlessEndpointProvenanceEntry {
            raw: inspect_uri_authority(line),
            parsed: parse_uri(line),
        })
        .collect()
}
fn decode_subscription(body: &str) -> Option<String> {
    let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains("://") {
        return None;
    }
    STANDARD
        .decode(compact)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .filter(|text| text.contains("://"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_vless_endpoint_aborts_import_without_a_connectable_server() {
        assert_eq!(
            parse_subscription_text(
                "vless://11111111-1111-1111-1111-111111111111@0.0.0.0:443?type=tcp"
            )
            .err()
            .as_deref(),
            Some("InvalidServerAddress")
        );
    }
}

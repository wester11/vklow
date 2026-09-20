use crate::{
    core::xray::manager::CoreStatus,
    domain::{ConnectionState, Protocol},
};
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsSnapshot {
    pub app_version: String,
    pub core: CoreStatus,
    pub connection: ConnectionState,
    pub process_state: String,
    pub socks_listen: Option<String>,
    pub selected_server_id: Option<String>,
    pub protocol: Option<Protocol>,
    pub transport: Option<String>,
    pub subscription_count: usize,
    pub last_subscription_status: String,
    pub internet_check: String,
    pub proxy_ip: Option<String>,
}
pub fn export(
    snapshot: &DiagnosticsSnapshot,
    directory: &Path,
    secrets: &[String],
) -> Result<PathBuf, String> {
    fs::create_dir_all(directory).map_err(|_| "Не удалось подготовить diagnostics directory")?;
    let raw = serde_json::to_string_pretty(snapshot)
        .map_err(|_| "Не удалось сериализовать diagnostics")?;
    let safe = crate::core::xray::redaction::redact(&raw, secrets);
    let path = directory.join(format!(
        "void-diagnostics-{}.json",
        chrono::Utc::now().format("%Y%m%d-%H%M%S")
    ));
    fs::write(&path, safe).map_err(|_| "Не удалось записать diagnostics export")?;
    Ok(path)
}
pub fn process_state(connection: &ConnectionState) -> String {
    match connection {
        ConnectionState::Idle => "not_running",
        ConnectionState::Preparing
        | ConnectionState::ValidatingConfig
        | ConnectionState::StartingCore
        | ConnectionState::WaitingForProxy => "starting",
        ConnectionState::ProxyReady { .. } => "running",
        ConnectionState::Stopping => "stopping",
        ConnectionState::Crashed { .. } => "crashed",
        ConnectionState::Error { .. } => "error",
    }
    .into()
}
pub fn socks_listen(connection: &ConnectionState) -> Option<String> {
    if let ConnectionState::ProxyReady { socks_port } = connection {
        Some(format!("127.0.0.1:{socks_port}"))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::xray::manager::CoreInstallState;
    #[test]
    fn export_redacts_adversarial_secrets() {
        let root = std::env::temp_dir().join(format!("void-diagnostics-{}", uuid::Uuid::new_v4()));
        let values = vec![
            "11111111-1111-1111-1111-111111111111",
            "Bearer fake-token",
            "hunter2",
            "vless://private",
            "trojan://private",
            "https://sub.test/?token=private",
            "Authorization: Basic fake",
        ];
        let snapshot = DiagnosticsSnapshot {
            app_version: values.join(" "),
            core: CoreStatus {
                install_state: CoreInstallState::Failed,
                active_version: None,
                previous_version: None,
                last_error: Some(values.join(" ")),
            },
            connection: ConnectionState::Error {
                message: values.join(" "),
            },
            process_state: "error".into(),
            socks_listen: None,
            selected_server_id: Some("opaque-id".into()),
            protocol: None,
            transport: None,
            subscription_count: 1,
            last_subscription_status: "failed".into(),
            internet_check: "unknown".into(),
            proxy_ip: None,
        };
        let path = export(
            &snapshot,
            &root,
            &values
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let output = fs::read_to_string(path).unwrap();
        for value in values {
            assert!(!output.contains(value), "secret leaked: {value}");
        }
    }
}

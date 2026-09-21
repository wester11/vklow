pub mod core;
pub mod domain;
mod subscription;
use chrono::Utc;
use core::xray::manager::{CoreStatus, TunCapabilityStatus, XrayCoreManager};
use core::{
    diagnostics::{
        export as export_diagnostics_file, process_state, socks_listen, DiagnosticsSnapshot,
    },
    secrets::{subscription_url_key, SecretStore, WindowsSecretStore},
};
use domain::{AppSnapshot, ConnectionState, Server, Subscription};
use std::sync::Mutex;
use tauri::{Manager, State};
use url::Url;
use uuid::Uuid;

struct RuntimeState {
    servers: Vec<Server>,
    subscriptions: Vec<Subscription>,
    selected_server_id: Option<String>,
    connection: ConnectionState,
}
impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            servers: vec![],
            subscriptions: vec![],
            selected_server_id: None,
            connection: ConnectionState::Idle,
        }
    }
}
struct AppState {
    runtime: Mutex<RuntimeState>,
    core: XrayCoreManager,
    secrets: Box<dyn SecretStore>,
}
fn snapshot(runtime: &RuntimeState) -> AppSnapshot {
    AppSnapshot {
        connection: runtime.connection.clone(),
        servers: runtime
            .servers
            .iter()
            .map(|server| server.summary.clone())
            .collect(),
        subscriptions: runtime.subscriptions.clone(),
        selected_server_id: runtime.selected_server_id.clone(),
    }
}
#[tauri::command]
fn get_snapshot(state: State<'_, AppState>) -> Result<AppSnapshot, String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "Внутренняя ошибка состояния")?;
    Ok(snapshot(&runtime))
}
#[tauri::command]
fn get_core_status(state: State<'_, AppState>) -> CoreStatus {
    state.core.status()
}
#[tauri::command]
fn get_connection_status(state: State<'_, AppState>) -> Result<ConnectionState, String> {
    state.core.connection_status()
}
#[tauri::command]
fn install_core(state: State<'_, AppState>) -> Result<CoreStatus, String> {
    state.core.install_latest_official()
}
#[tauri::command]
fn get_tun_capability(state: State<'_, AppState>) -> TunCapabilityStatus {
    state.core.validate_tun_capability()
}
#[tauri::command]
fn get_diagnostics(state: State<'_, AppState>) -> Result<DiagnosticsSnapshot, String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "Внутренняя ошибка состояния")?;
    let selected = runtime
        .selected_server_id
        .as_ref()
        .and_then(|id| {
            runtime
                .servers
                .iter()
                .find(|server| &server.summary.id == id)
        })
        .or_else(|| runtime.servers.first());
    Ok(DiagnosticsSnapshot {
        app_version: env!("CARGO_PKG_VERSION").into(),
        core: state.core.status(),
        process_state: process_state(&runtime.connection),
        socks_listen: socks_listen(&runtime.connection),
        connection: runtime.connection.clone(),
        selected_server_id: selected.map(|server| server.summary.id.clone()),
        protocol: selected.map(|server| server.summary.protocol),
        transport: selected.and_then(|server| server.summary.transport.clone()),
        subscription_count: runtime.subscriptions.len(),
        last_subscription_status: "last_known_good".into(),
        internet_check: "unknown".into(),
        proxy_ip: None,
    })
}
#[tauri::command]
fn export_diagnostics(state: State<'_, AppState>) -> Result<String, String> {
    let snapshot = get_diagnostics(state.clone())?;
    let path = state.core.diagnostics_directory().join("exports");
    let secrets = state
        .runtime
        .lock()
        .map_err(|_| "Внутренняя ошибка состояния")?
        .servers
        .iter()
        .flat_map(|server| {
            std::iter::once(server.credential.clone()).chain(server.options.values().cloned())
        })
        .collect::<Vec<_>>();
    let file = export_diagnostics_file(&snapshot, &path, &secrets)?;
    file.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| "Не удалось определить diagnostics export".to_owned())
}
#[tauri::command]
async fn add_subscription(url: String, state: State<'_, AppState>) -> Result<ImportResult, String> {
    let source = Url::parse(&url).map_err(|_| "Укажите корректный URL подписки")?;
    let name = source
        .host_str()
        .ok_or("В URL подписки отсутствует хост")?
        .to_owned();
    let servers = subscription::fetch_and_parse(&url).await?;
    let count = servers.len();
    let id = Uuid::new_v4().to_string();
    state.secrets.set(&subscription_url_key(&id), &url)?;
    let mut runtime = state
        .runtime
        .lock()
        .map_err(|_| "Внутренняя ошибка состояния")?;
    runtime.servers.extend(servers);
    runtime.subscriptions.push(Subscription {
        id,
        name,
        updated_at: Utc::now().to_rfc3339(),
        server_count: count,
    });
    Ok(ImportResult {
        server_count: count,
    })
}
#[tauri::command]
fn import_uri(uri: String, state: State<'_, AppState>) -> Result<ImportResult, String> {
    let server = subscription::parser::parse_uri(uri.trim())?;
    let mut runtime = state
        .runtime
        .lock()
        .map_err(|_| "Внутренняя ошибка состояния")?;
    runtime.servers.push(server);
    runtime.subscriptions.push(Subscription {
        id: Uuid::new_v4().to_string(),
        name: "Вручную добавленный URI".into(),
        updated_at: Utc::now().to_rfc3339(),
        server_count: 1,
    });
    Ok(ImportResult { server_count: 1 })
}
#[tauri::command]
fn select_server(server_id: Option<String>, state: State<'_, AppState>) -> Result<(), String> {
    let mut runtime = state
        .runtime
        .lock()
        .map_err(|_| "Внутренняя ошибка состояния")?;
    if let Some(id) = &server_id {
        if !runtime
            .servers
            .iter()
            .any(|server| server.summary.id == *id)
        {
            return Err("Выбранный сервер больше недоступен".into());
        }
    }
    runtime.selected_server_id = server_id;
    Ok(())
}
#[tauri::command]
fn connect(state: State<'_, AppState>) -> Result<(), String> {
    let server = {
        let runtime = state
            .runtime
            .lock()
            .map_err(|_| "Внутренняя ошибка состояния")?;
        let selected = runtime
            .selected_server_id
            .as_ref()
            .ok_or("NoServerSelected")?;
        runtime
            .servers
            .iter()
            .find(|item| &item.summary.id == selected)
            .cloned()
            .ok_or("SelectedServerUnavailable")?
    };
    let connection = state.core.connect(&server)?;
    let mut runtime = state
        .runtime
        .lock()
        .map_err(|_| "Внутренняя ошибка состояния")?;
    runtime.connection = connection;
    Ok(())
}
#[tauri::command]
fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    let connection = state.core.disconnect()?;
    let mut runtime = state
        .runtime
        .lock()
        .map_err(|_| "Внутренняя ошибка состояния")?;
    runtime.connection = connection;
    Ok(())
}
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportResult {
    server_count: usize,
}
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let data = app
                .path()
                .app_data_dir()
                .map_err(|_| "Не удалось определить application data directory")?;
            app.manage(AppState {
                runtime: Mutex::new(RuntimeState::default()),
                core: XrayCoreManager::load(data),
                secrets: Box::new(WindowsSecretStore::new()),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_snapshot,
            get_core_status,
            get_connection_status,
            get_diagnostics,
            export_diagnostics,
            install_core,
            get_tun_capability,
            add_subscription,
            import_uri,
            select_server,
            connect,
            disconnect
        ])
        .run(tauri::generate_context!())
        .expect("error while running VOID Desktop");
}

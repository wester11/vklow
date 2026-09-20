mod core;
mod domain;
mod subscription;
use chrono::Utc;
use domain::{AppSnapshot, ConnectionState, Server, Subscription};
use std::sync::Mutex;
use tauri::State;
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
struct AppState(Mutex<RuntimeState>);
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
    let runtime = state.0.lock().map_err(|_| "Внутренняя ошибка состояния")?;
    Ok(snapshot(&runtime))
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
    let mut runtime = state.0.lock().map_err(|_| "Внутренняя ошибка состояния")?;
    runtime.servers.extend(servers);
    runtime.subscriptions.push(Subscription {
        id: Uuid::new_v4().to_string(),
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
    let mut runtime = state.0.lock().map_err(|_| "Внутренняя ошибка состояния")?;
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
    let mut runtime = state.0.lock().map_err(|_| "Внутренняя ошибка состояния")?;
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
    let mut runtime = state.0.lock().map_err(|_| "Внутренняя ошибка состояния")?;
    if runtime.servers.is_empty() {
        return Err("Сначала добавьте подписку или URI сервера".into());
    }
    runtime.connection = ConnectionState::Preparing;
    runtime.connection = ConnectionState::Error {
        message: "Xray-core ещё не установлен в доверенное хранилище приложения".into(),
    };
    Err("Xray-core не установлен. Подключение не имитируется: добавьте проверенный core через менеджер обновлений.".into())
}
#[tauri::command]
fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    let mut runtime = state.0.lock().map_err(|_| "Внутренняя ошибка состояния")?;
    runtime.connection = ConnectionState::Idle;
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
        .manage(AppState(Mutex::new(RuntimeState::default())))
        .invoke_handler(tauri::generate_handler![
            get_snapshot,
            add_subscription,
            import_uri,
            select_server,
            connect,
            disconnect
        ])
        .run(tauri::generate_context!())
        .expect("error while running VOID Desktop");
}

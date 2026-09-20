use serde::Serialize;
use std::collections::HashMap;
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Vless,
    Vmess,
    Shadowsocks,
    Trojan,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ServerHealth {
    Unknown,
    Testing,
    Available,
    Degraded,
    Unavailable,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerSummary {
    pub id: String,
    pub name: String,
    pub protocol: Protocol,
    pub address: String,
    pub port: u16,
    pub transport: Option<String>,
    pub country: Option<String>,
    pub health: ServerHealth,
    pub latency_ms: Option<u32>,
}
#[derive(Clone, Debug)]
pub struct Server {
    pub summary: ServerSummary,
    pub credential: String,
    pub security: Option<String>,
    pub sni: Option<String>,
    /// Connection parameters are backend-only because they may contain credentials.
    pub options: HashMap<String, String>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub updated_at: String,
    pub server_count: usize,
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConnectionState {
    Idle,
    Preparing,
    ValidatingConfig,
    StartingCore,
    WaitingForProxy,
    #[serde(rename = "connected")]
    ProxyReady {
        socks_port: u16,
    },
    Stopping,
    Crashed {
        message: String,
    },
    Error {
        message: String,
    },
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSnapshot {
    pub connection: ConnectionState,
    pub servers: Vec<ServerSummary>,
    pub subscriptions: Vec<Subscription>,
    pub selected_server_id: Option<String>,
}

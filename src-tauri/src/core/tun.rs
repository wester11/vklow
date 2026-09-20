use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunSessionPhase {
    Prepared,
    Elevating,
    HelperReady,
    StartingTun,
    AdapterReady,
    ScopedRouteReady,
    TrafficVerified,
    Stopping,
    Recovered,
    Completed,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnedRoute {
    pub destination: String,
    pub interface_alias: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunSessionJournal {
    pub schema_version: u8,
    pub session_id: String,
    pub started_at: String,
    pub adapter_name: String,
    pub adapter_luid: Option<u64>,
    pub interface_index: Option<u32>,
    pub experimental_version: String,
    pub core_pid: Option<u32>,
    pub owned_routes: Vec<OwnedRoute>,
    pub phase: TunSessionPhase,
}
impl TunSessionJournal {
    pub fn new(session_id: String, adapter_name: String, experimental_version: String) -> Self {
        Self {
            schema_version: 2,
            session_id,
            started_at: chrono::Utc::now().to_rfc3339(),
            adapter_name,
            adapter_luid: None,
            interface_index: None,
            experimental_version,
            core_pid: None,
            owned_routes: Vec::new(),
            phase: TunSessionPhase::Prepared,
        }
    }
    pub fn save_atomic(&self, path: &Path) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|_| "Не удалось сериализовать TUN session journal")?;
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, bytes).map_err(|_| "Не удалось записать TUN session journal")?;
        fs::rename(temporary, path)
            .map_err(|_| "Не удалось активировать TUN session journal".into())
    }
    pub fn load(path: &Path) -> Result<Option<Self>, String> {
        if !path.is_file() {
            return Ok(None);
        }
        serde_json::from_slice(
            &fs::read(path).map_err(|_| "Не удалось прочитать TUN session journal")?,
        )
        .map(Some)
        .map_err(|_| "TUN session journal повреждён".into())
    }
    pub fn owns_route(&self, route: &OwnedRoute) -> bool {
        self.owned_routes.contains(route) && route.interface_alias == self.adapter_name
    }
    pub fn transition(&mut self, phase: TunSessionPhase) {
        self.phase = phase;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn journal_matches_only_its_own_route() {
        let mut journal = TunSessionJournal::new(
            "session".into(),
            "VOID Tunnel session".into(),
            "v26.9.8".into(),
        );
        journal.owned_routes.push(OwnedRoute {
            destination: "1.1.1.1/32".into(),
            interface_alias: "VOID Tunnel session".into(),
        });
        assert!(journal.owns_route(&journal.owned_routes[0]));
        assert!(!journal.owns_route(&OwnedRoute {
            destination: "1.1.1.1/32".into(),
            interface_alias: "Other VPN".into()
        }));
    }
    #[test]
    fn journal_records_owned_adapter_identity_and_phase() {
        let mut journal = TunSessionJournal::new(
            "session".into(),
            "VOID Tunnel session".into(),
            "v26.9.8".into(),
        );
        journal.adapter_luid = Some(42);
        journal.interface_index = Some(7);
        journal.transition(TunSessionPhase::ScopedRouteReady);
        assert_eq!(journal.phase, TunSessionPhase::ScopedRouteReady);
        assert_eq!(journal.adapter_luid, Some(42));
        assert_eq!(journal.interface_index, Some(7));
    }
}

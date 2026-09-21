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
    FullIpv4RoutesReady,
    TrafficVerified,
    Stopping,
    Recovered,
    Completed,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunSessionPolicy {
    ScopedSmoke,
    FullIpv4Experimental,
    SystemIpv4Experimental,
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
    #[serde(default = "default_policy")]
    pub policy: TunSessionPolicy,
    pub session_id: String,
    pub started_at: String,
    pub adapter_name: String,
    pub adapter_luid: Option<u64>,
    pub interface_index: Option<u32>,
    pub experimental_version: String,
    /// Safe server identity and digest only. Credentials never enter this file.
    #[serde(default)]
    pub selected_server_id: Option<String>,
    #[serde(default)]
    pub config_sha256: Option<String>,
    pub core_pid: Option<u32>,
    pub owned_routes: Vec<OwnedRoute>,
    #[serde(default)]
    pub tun_dns: Vec<String>,
    pub phase: TunSessionPhase,
}
impl TunSessionJournal {
    pub fn new(
        session_id: String,
        adapter_name: String,
        experimental_version: String,
        policy: TunSessionPolicy,
    ) -> Self {
        Self {
            schema_version: 4,
            policy,
            session_id,
            started_at: chrono::Utc::now().to_rfc3339(),
            adapter_name,
            adapter_luid: None,
            interface_index: None,
            experimental_version,
            selected_server_id: None,
            config_sha256: None,
            core_pid: None,
            owned_routes: Vec::new(),
            tun_dns: Vec::new(),
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

fn default_policy() -> TunSessionPolicy {
    TunSessionPolicy::ScopedSmoke
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
            TunSessionPolicy::ScopedSmoke,
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
            TunSessionPolicy::ScopedSmoke,
        );
        journal.adapter_luid = Some(42);
        journal.interface_index = Some(7);
        journal.transition(TunSessionPhase::ScopedRouteReady);
        assert_eq!(journal.phase, TunSessionPhase::ScopedRouteReady);
        assert_eq!(journal.adapter_luid, Some(42));
        assert_eq!(journal.interface_index, Some(7));
    }
    #[test]
    fn system_vpn_journal_has_no_credential_fields() {
        let mut journal = TunSessionJournal::new(
            "11111111-1111-1111-1111-111111111111".into(),
            "VOID Tunnel 11111111".into(),
            "v26.9.8".into(),
            TunSessionPolicy::SystemIpv4Experimental,
        );
        journal.selected_server_id = Some("22222222-2222-2222-2222-222222222222".into());
        journal.config_sha256 = Some("a".repeat(64));
        let value = serde_json::to_string(&journal).unwrap();
        for forbidden in ["credential", "password", "privateKey", "publicKey", "uuid"] {
            assert!(
                !value.contains(forbidden),
                "journal must not contain {forbidden}"
            );
        }
    }
}

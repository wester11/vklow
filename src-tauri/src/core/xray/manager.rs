use crate::core::xray::{paths::XrayPaths, state::InstalledState};
use serde::Serialize;
use std::sync::Mutex;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreInstallState {
    NotInstalled,
    Ready,
    Failed,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreStatus {
    pub install_state: CoreInstallState,
    pub active_version: Option<String>,
    pub previous_version: Option<String>,
    pub last_error: Option<String>,
}
pub struct XrayCoreManager {
    paths: XrayPaths,
    state: Mutex<InstalledState>,
    last_error: Mutex<Option<String>>,
}
impl XrayCoreManager {
    pub fn load(application_data: std::path::PathBuf) -> Self {
        let paths = XrayPaths::new(application_data);
        let mut error = paths.ensure().err();
        let state = match InstalledState::load(&paths.state()) {
            Ok(value) => value,
            Err(reason) => {
                error = Some(reason);
                InstalledState {
                    schema_version: 1,
                    ..Default::default()
                }
            }
        };
        Self {
            paths,
            state: Mutex::new(state),
            last_error: Mutex::new(error),
        }
    }
    pub fn status(&self) -> CoreStatus {
        let state = self.state.lock().expect("Xray state mutex poisoned");
        let active_valid = state.active_version.as_ref().is_some_and(|version| {
            self.paths
                .versions()
                .join(version)
                .join("xray.exe")
                .is_file()
        });
        let error = self
            .last_error
            .lock()
            .expect("Xray error mutex poisoned")
            .clone();
        CoreStatus {
            install_state: if active_valid {
                CoreInstallState::Ready
            } else if error.is_some() {
                CoreInstallState::Failed
            } else {
                CoreInstallState::NotInstalled
            },
            active_version: active_valid.then(|| state.active_version.clone()).flatten(),
            previous_version: state.previous_version.clone(),
            last_error: error,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn new_manager_reports_not_installed() {
        let root = std::env::temp_dir().join(format!("void-core-{}", uuid::Uuid::new_v4()));
        let manager = XrayCoreManager::load(root);
        assert!(matches!(
            manager.status().install_state,
            CoreInstallState::NotInstalled
        ));
    }
}

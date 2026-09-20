use crate::core::xray::version::XrayVersion;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledState {
    pub schema_version: u8,
    pub active_version: Option<String>,
    pub previous_version: Option<String>,
    pub installed_versions: Vec<String>,
    pub failed_versions: Vec<String>,
}
impl InstalledState {
    pub fn activate(&mut self, version: XrayVersion) {
        let value = version.to_string();
        if self.active_version.as_deref() != Some(&value) {
            self.previous_version = self.active_version.replace(value.clone());
        }
        if !self.installed_versions.contains(&value) {
            self.installed_versions.push(value);
        }
    }
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self {
                schema_version: 1,
                ..Self::default()
            });
        }
        serde_json::from_slice(&fs::read(path).map_err(|_| "Не удалось прочитать Xray state")?)
            .map_err(|_| "Xray state повреждён".to_owned())
    }
    pub fn save_atomic(&self, path: &Path) -> Result<(), String> {
        let bytes =
            serde_json::to_vec_pretty(self).map_err(|_| "Не удалось сериализовать Xray state")?;
        let temporary = path.with_extension("json.tmp");
        fs::write(&temporary, bytes).map_err(|_| "Не удалось записать Xray state")?;
        fs::rename(temporary, path).map_err(|_| "Не удалось активировать Xray state".to_owned())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retains_previous_version() {
        let mut state = InstalledState {
            schema_version: 1,
            ..Default::default()
        };
        state.activate("v26.3.27".parse().unwrap());
        state.activate("v26.4.1".parse().unwrap());
        assert_eq!(state.active_version.as_deref(), Some("v26.4.1"));
        assert_eq!(state.previous_version.as_deref(), Some("v26.3.27"));
    }
}

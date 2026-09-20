use crate::core::xray::version::XrayVersion;
use std::path::{Path, PathBuf};
#[derive(Clone, Debug)]
pub struct XrayPaths {
    root: PathBuf,
}
impl XrayPaths {
    pub fn new(app_data: impl Into<PathBuf>) -> Self {
        Self {
            root: app_data.into().join("xray"),
        }
    }
    pub fn versions(&self) -> PathBuf {
        self.root.join("versions")
    }
    pub fn staging(&self) -> PathBuf {
        self.root.join("staging")
    }
    pub fn state(&self) -> PathBuf {
        self.root.join("state.json")
    }
    pub fn version_dir(&self, version: &XrayVersion) -> PathBuf {
        self.versions().join(version.to_string())
    }
    pub fn binary(&self, version: &XrayVersion) -> PathBuf {
        self.version_dir(version).join("xray.exe")
    }
    pub fn runtime(&self) -> PathBuf {
        self.root.join("runtime")
    }
    pub fn ensure(&self) -> Result<(), String> {
        for path in [&self.versions(), &self.staging(), &self.runtime()] {
            std::fs::create_dir_all(path)
                .map_err(|_| "Не удалось подготовить private directory Xray")?;
        }
        Ok(())
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
}

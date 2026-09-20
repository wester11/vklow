use crate::core::xray::version::XrayVersion;
use reqwest::{
    blocking::{Client, Response},
    redirect::Policy,
};
use serde::Deserialize;
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use url::Url;

const API: &str = "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=20";
pub const ARCHIVE_NAME: &str = "Xray-windows-64.zip";
pub const DIGEST_NAME: &str = "Xray-windows-64.zip.dgst";
const MAX_ARCHIVE: u64 = 64 * 1024 * 1024;
const MAX_DIGEST: u64 = 64 * 1024;

#[derive(Clone, Debug)]
pub struct OfficialRelease {
    pub version: XrayVersion,
    pub archive: Url,
    pub digest: Url,
    pub asset_name: String,
}
#[derive(Clone, Deserialize)]
struct GithubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<GithubAsset>,
}
#[derive(Clone, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

pub fn resolve_windows_x64(client: &Client) -> Result<OfficialRelease, String> {
    if !cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        return Err("UnsupportedPlatform: требуется Windows x86_64".into());
    }
    let response = client
        .get(API)
        .header("User-Agent", "VOID-Desktop")
        .send()
        .map_err(|_| "Не удалось получить официальный Xray release")?;
    if !response.status().is_success() {
        return Err("Официальный Xray release недоступен".into());
    }
    let releases: Vec<GithubRelease> = response
        .json()
        .map_err(|_| "Некорректный ответ официального Xray release API")?;
    let release =
        select_stable_release(releases).ok_or("Официальный stable Xray release недоступен")?;
    let version = release.tag_name.parse()?;
    let asset = |name: &str| -> Result<Url, String> {
        let item = release
            .assets
            .iter()
            .find(|item| item.name == name)
            .ok_or("В официальном release отсутствует ожидаемый Windows x64 asset")?;
        trusted_url(&item.browser_download_url)
    };
    Ok(OfficialRelease {
        version,
        archive: asset(ARCHIVE_NAME)?,
        digest: asset(DIGEST_NAME)?,
        asset_name: ARCHIVE_NAME.into(),
    })
}

fn select_stable_release(releases: Vec<GithubRelease>) -> Option<GithubRelease> {
    releases
        .into_iter()
        .find(|release| !release.draft && !release.prerelease)
}
pub fn trusted_client() -> Result<Client, String> {
    Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(45))
        .redirect(Policy::custom(|attempt| {
            if attempt.previous().len() >= 3 || !trusted_host(attempt.url().host_str()) {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .build()
        .map_err(|_| "Не удалось подготовить secure Xray downloader".to_owned())
}
pub fn download_to(client: &Client, url: &Url, path: &Path, max: u64) -> Result<(), String> {
    trusted_url(url.as_str())?;
    let mut response = client
        .get(url.clone())
        .header("User-Agent", "VOID-Desktop")
        .send()
        .map_err(|_| "Не удалось скачать официальный Xray asset")?;
    if !response.status().is_success() {
        return Err("Официальный Xray asset недоступен".into());
    }
    if response.content_length().is_some_and(|size| size > max) {
        return Err("Официальный Xray asset превышает допустимый размер".into());
    }
    let partial = path.with_extension("partial");
    let result = stream(&mut response, &partial, max);
    if result.is_err() {
        let _ = std::fs::remove_file(&partial);
        return result;
    }
    std::fs::rename(partial, path)
        .map_err(|_| "Не удалось завершить загрузку Xray asset".to_owned())
}
pub fn acquire(release: &OfficialRelease, staging: &Path) -> Result<(PathBuf, String), String> {
    std::fs::create_dir_all(staging).map_err(|_| "Не удалось создать download staging")?;
    let client = trusted_client()?;
    let archive = staging.join(ARCHIVE_NAME);
    let digest = staging.join(DIGEST_NAME);
    download_to(&client, &release.archive, &archive, MAX_ARCHIVE)?;
    download_to(&client, &release.digest, &digest, MAX_DIGEST)?;
    let contents =
        std::fs::read_to_string(&digest).map_err(|_| "Не удалось прочитать официальный digest")?;
    Ok((archive, contents))
}
fn stream(response: &mut Response, path: &Path, max: u64) -> Result<(), String> {
    let mut out = File::create(path).map_err(|_| "Не удалось создать partial Xray artifact")?;
    let mut bytes = 0u64;
    let mut buffer = [0u8; 32 * 1024];
    loop {
        let read = response
            .read(&mut buffer)
            .map_err(|_| "Загрузка Xray asset была прервана")?;
        if read == 0 {
            break;
        }
        bytes += read as u64;
        if bytes > max {
            return Err("Официальный Xray asset превышает допустимый размер".into());
        }
        out.write_all(&buffer[..read])
            .map_err(|_| "Не удалось записать Xray artifact")?;
    }
    out.sync_all()
        .map_err(|_| "Не удалось синхронизировать Xray artifact".to_owned())
}
fn trusted_url(raw: &str) -> Result<Url, String> {
    let url = Url::parse(raw).map_err(|_| "Некорректный URL официального Xray asset")?;
    if url.scheme() != "https" || !trusted_host(url.host_str()) {
        return Err("Xray download host не входит в trusted allowlist".into());
    }
    Ok(url)
}
fn trusted_host(host: Option<&str>) -> bool {
    matches!(
        host,
        Some(
            "api.github.com"
                | "github.com"
                | "objects.githubusercontent.com"
                | "release-assets.githubusercontent.com"
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(tag_name: &str, draft: bool, prerelease: bool) -> GithubRelease {
        GithubRelease {
            tag_name: tag_name.into(),
            draft,
            prerelease,
            assets: vec![],
        }
    }

    #[test]
    fn selects_first_non_draft_non_prerelease() {
        let selected = select_stable_release(vec![
            release("v26.10.1", false, true),
            release("v26.10.0", true, false),
            release("v26.9.8", false, false),
        ])
        .expect("stable release");

        assert_eq!(selected.tag_name, "v26.9.8");
    }

    #[test]
    fn rejects_release_list_without_stable_entry() {
        assert!(select_stable_release(vec![
            release("v26.10.1", false, true),
            release("v26.10.0", true, false),
        ])
        .is_none());
    }
}

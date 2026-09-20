use std::{
    fs::{self, File},
    io,
    path::{Component, Path, PathBuf},
};
pub const MAX_FILES: usize = 32;
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
pub fn safe_relative_path(entry: &str) -> Result<PathBuf, String> {
    if entry.is_empty() || entry.starts_with('/') || entry.starts_with('\\') || entry.contains(':')
    {
        return Err("Недопустимый путь в Xray archive".into());
    }
    let path = Path::new(entry);
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) if part != ".." => clean.push(part),
            Component::CurDir => {}
            _ => return Err("Archive path выходит за staging directory".into()),
        }
    }
    if clean.as_os_str().is_empty() {
        return Err("Недопустимый путь в Xray archive".into());
    }
    Ok(clean)
}
pub fn extract_verified_zip(archive: &Path, destination: &Path) -> Result<PathBuf, String> {
    let file = File::open(archive).map_err(|_| "Не удалось открыть Xray archive")?;
    let mut zip = zip::ZipArchive::new(file).map_err(|_| "Xray archive повреждён")?;
    if zip.len() > MAX_FILES {
        return Err("Xray archive содержит слишком много файлов".into());
    }
    let mut total = 0u64;
    let mut binary = None;
    for index in 0..zip.len() {
        let mut entry = zip
            .by_index(index)
            .map_err(|_| "Не удалось прочитать entry Xray archive")?;
        let relative = safe_relative_path(entry.name())?;
        if entry.is_dir() {
            fs::create_dir_all(destination.join(relative))
                .map_err(|_| "Не удалось создать staging directory")?;
            continue;
        }
        if entry.size() > MAX_FILE_BYTES {
            return Err("Файл Xray archive превышает допустимый размер".into());
        }
        total = total
            .checked_add(entry.size())
            .ok_or("Недопустимый размер Xray archive")?;
        if total > MAX_TOTAL_BYTES {
            return Err("Распакованный Xray archive слишком большой".into());
        }
        let target = destination.join(&relative);
        if !target.starts_with(destination) {
            return Err("Archive path выходит за staging directory".into());
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|_| "Не удалось создать staging directory")?;
        }
        let mut output =
            File::create(&target).map_err(|_| "Не удалось записать Xray staging file")?;
        io::copy(&mut entry, &mut output).map_err(|_| "Не удалось распаковать Xray archive")?;
        if relative == Path::new("xray.exe") {
            if binary.replace(target).is_some() {
                return Err("Xray archive содержит несколько xray.exe".into());
            }
        }
    }
    binary.ok_or_else(|| "Xray archive не содержит ожидаемый xray.exe".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn blocks_traversal_paths() {
        for value in [
            "../../evil.exe",
            "..\\..\\evil.exe",
            "C:\\evil.exe",
            "\\\\server\\share\\evil.exe",
        ] {
            assert!(safe_relative_path(value).is_err(), "{value}");
        }
    }
    #[test]
    fn permits_nested_path() {
        assert_eq!(
            safe_relative_path("resources/geoip.dat").unwrap(),
            PathBuf::from("resources").join("geoip.dat")
        );
    }
}

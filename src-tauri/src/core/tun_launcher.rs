#![cfg(windows)]

use std::path::{Path, PathBuf};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, ERROR_CANCELLED, HANDLE},
    System::Threading::{GetProcessId, TerminateProcess},
    UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW},
};

#[derive(Debug)]
pub enum ElevationError {
    ElevationCancelled,
    SmokeInconclusiveNetworkChanged,
    PhysicalDnsMutated,
    LaunchFailed,
    InvalidHelperLayout,
}

pub struct ElevatedHelper {
    handle: HANDLE,
    pub pid: u32,
}

// The handle is only accessed through the owning controller's mutex and is
// closed exactly once in Drop.
unsafe impl Send for ElevatedHelper {}

impl ElevatedHelper {
    pub fn terminate_if_owned(&self) {
        unsafe { TerminateProcess(self.handle, 1) };
    }
}

impl Drop for ElevatedHelper {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle) };
    }
}

pub fn trusted_helper_path(current_exe: &Path) -> Result<PathBuf, ElevationError> {
    let parent = current_exe
        .parent()
        .ok_or(ElevationError::InvalidHelperLayout)?;
    let parent = parent
        .canonicalize()
        .map_err(|_| ElevationError::InvalidHelperLayout)?;
    let helper = parent.join("void-tun-helper.exe");
    let helper = helper
        .canonicalize()
        .map_err(|_| ElevationError::InvalidHelperLayout)?;
    if helper.file_name().and_then(|name| name.to_str()) != Some("void-tun-helper.exe")
        || !helper.starts_with(&parent)
    {
        return Err(ElevationError::InvalidHelperLayout);
    }
    Ok(helper)
}

pub fn launch_elevated_helper(
    current_exe: &Path,
    pipe_name: &str,
    session_id: &str,
    nonce: &str,
    controller_pid: u32,
) -> Result<ElevatedHelper, ElevationError> {
    let helper = trusted_helper_path(current_exe)?;
    let parameters = format!(
        "--pipe \"{pipe_name}\" --session \"{session_id}\" --nonce \"{nonce}\" --controller-pid {controller_pid}"
    );
    let verb = wide("runas");
    let file = wide_path(&helper);
    let parameters = wide(&parameters);
    let directory = wide_path(helper.parent().ok_or(ElevationError::InvalidHelperLayout)?);
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: verb.as_ptr(),
        lpFile: file.as_ptr(),
        lpParameters: parameters.as_ptr(),
        lpDirectory: directory.as_ptr(),
        ..Default::default()
    };
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        return Err(if unsafe { GetLastError() } == ERROR_CANCELLED {
            ElevationError::ElevationCancelled
        } else {
            ElevationError::LaunchFailed
        });
    }
    let pid = unsafe { GetProcessId(info.hProcess) };
    if pid == 0 {
        unsafe { CloseHandle(info.hProcess) };
        return Err(ElevationError::LaunchFailed);
    }
    Ok(ElevatedHelper {
        handle: info.hProcess,
        pid,
    })
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_path(value: &Path) -> Vec<u16> {
    wide(&value.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_path_rejects_missing_or_wrong_helper() {
        let root =
            std::env::temp_dir().join(format!("void-helper-layout-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        assert!(matches!(
            trusted_helper_path(&root.join("void-desktop.exe")),
            Err(ElevationError::InvalidHelperLayout)
        ));
    }
}

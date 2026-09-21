//! Owner-only directories for short-lived credential-bearing Xray configs.

use std::path::Path;
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::CreateDirectoryW,
};

pub fn create_owner_only_directory(path: &Path) -> Result<(), String> {
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let sddl = wide("D:P(A;;GA;;;OW)");
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err("UnableToCreatePrivateRuntimeAcl".into());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let wide_path = wide(&path.to_string_lossy());
    let created = unsafe { CreateDirectoryW(wide_path.as_ptr(), &attributes) };
    unsafe { LocalFree(descriptor) };
    if created == 0 {
        return Err("UnableToCreatePrivateRuntimeDirectory".into());
    }
    Ok(())
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

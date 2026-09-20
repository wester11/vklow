#![cfg(windows)]

use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
    System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    },
};

/// Owns only the Xray child spawned for one VOID session. Closing this handle
/// makes Windows terminate remaining job members, including after helper crash.
pub struct OwnedXrayJob {
    handle: HANDLE,
}

impl OwnedXrayJob {
    pub fn create() -> Result<Self, String> {
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err("Unable to create owned Xray job object".into());
        }
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            unsafe { CloseHandle(handle) };
            return Err("Unable to configure owned Xray job object".into());
        }
        Ok(Self { handle })
    }

    pub fn assign(&self, child: &std::process::Child) -> Result<(), String> {
        if unsafe { AssignProcessToJobObject(self.handle, child.as_raw_handle().cast()) } == 0 {
            return Err("Unable to assign owned Xray to job object".into());
        }
        Ok(())
    }
}

impl Drop for OwnedXrayJob {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle) };
    }
}

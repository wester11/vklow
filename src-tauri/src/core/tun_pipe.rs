#![cfg(windows)]

use std::{
    ffi::c_void,
    fs::File,
    io::{Read, Write},
    os::windows::io::FromRawHandle,
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE,
        INVALID_HANDLE_VALUE,
    },
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING, PIPE_ACCESS_DUPLEX},
    System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
        GetNamedPipeServerProcessId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_BYTE, PIPE_WAIT,
    },
};

use crate::core::tun_protocol::MAX_IPC_MESSAGE_BYTES;

const PIPE_BUFFER_BYTES: u32 = (MAX_IPC_MESSAGE_BYTES as u32) + 4;

pub struct TunPipeServer {
    handle: *mut c_void,
}

pub struct TunPipeConnection {
    file: File,
    peer_pid: u32,
}

impl TunPipeServer {
    pub fn create(name: &str) -> Result<Self, String> {
        if !name.starts_with(r"\\.\pipe\void-tun-") || name.len() > 160 {
            return Err("Invalid TUN pipe name".into());
        }
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let sddl = wide("D:P(A;;GA;;;OW)");
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if converted == 0 {
            return Err("Unable to create TUN pipe security descriptor".into());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let wide_name = wide(name);
        let handle = unsafe {
            CreateNamedPipeW(
                wide_name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                PIPE_BUFFER_BYTES,
                PIPE_BUFFER_BYTES,
                5_000,
                &attributes,
            )
        };
        unsafe { windows_sys::Win32::Foundation::LocalFree(descriptor) };
        if handle == INVALID_HANDLE_VALUE {
            return Err("Unable to create restricted TUN pipe".into());
        }
        Ok(Self { handle })
    }

    pub fn accept(self) -> Result<TunPipeConnection, String> {
        let connected = unsafe { ConnectNamedPipe(self.handle, std::ptr::null_mut()) };
        if connected == 0 && unsafe { GetLastError() } != ERROR_PIPE_CONNECTED {
            unsafe { CloseHandle(self.handle) };
            return Err("TUN helper did not connect to pipe".into());
        }
        let mut peer_pid = 0;
        if unsafe { GetNamedPipeClientProcessId(self.handle, &mut peer_pid) } == 0 || peer_pid == 0
        {
            return Err("Unable to verify TUN helper pipe process".into());
        }
        let file = unsafe { File::from_raw_handle(self.handle) };
        Ok(TunPipeConnection { file, peer_pid })
    }
}

impl TunPipeConnection {
    pub fn connect(name: &str) -> Result<Self, String> {
        let wide_name = wide(name);
        let handle = unsafe {
            CreateFileW(
                wide_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err("Unable to connect to restricted TUN pipe".into());
        }
        let mut peer_pid = 0;
        if unsafe { GetNamedPipeServerProcessId(handle, &mut peer_pid) } == 0 || peer_pid == 0 {
            unsafe { CloseHandle(handle) };
            return Err("Unable to verify TUN controller pipe process".into());
        }
        let file = unsafe { File::from_raw_handle(handle) };
        Ok(Self { file, peer_pid })
    }

    pub fn write_frame(&mut self, bytes: &[u8]) -> Result<(), String> {
        if bytes.len() > MAX_IPC_MESSAGE_BYTES {
            return Err("Tun IPC message exceeds limit".into());
        }
        self.file
            .write_all(&(bytes.len() as u32).to_le_bytes())
            .and_then(|_| self.file.write_all(bytes))
            .and_then(|_| self.file.flush())
            .map_err(|_| "Unable to write TUN IPC message".into())
    }

    pub fn read_frame(&mut self) -> Result<Vec<u8>, String> {
        let mut length = [0_u8; 4];
        self.file
            .read_exact(&mut length)
            .map_err(|_| "Unable to read TUN IPC message length")?;
        let length = u32::from_le_bytes(length) as usize;
        if length > MAX_IPC_MESSAGE_BYTES {
            return Err("Tun IPC message exceeds limit".into());
        }
        let mut bytes = vec![0; length];
        self.file
            .read_exact(&mut bytes)
            .map_err(|_| "Unable to read TUN IPC message")?;
        Ok(bytes)
    }

    pub fn into_file(self) -> File {
        self.file
    }
    pub fn peer_pid(&self) -> u32 {
        self.peer_pid
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_void_pipe_names() {
        assert!(TunPipeServer::create(r"\\.\pipe\other").is_err());
    }

    #[test]
    fn framed_pipe_round_trip_uses_local_restricted_endpoint() {
        let name = format!(r"\\.\pipe\void-tun-{}", uuid::Uuid::new_v4());
        let server = TunPipeServer::create(&name).unwrap();
        let client_name = name.clone();
        let client = std::thread::spawn(move || {
            let mut connection = TunPipeConnection::connect(&client_name).unwrap();
            assert_ne!(connection.peer_pid(), 0);
            connection.write_frame(b"request").unwrap();
            assert_eq!(connection.read_frame().unwrap(), b"response");
        });
        let mut connection = server.accept().unwrap();
        assert_ne!(connection.peer_pid(), 0);
        assert_eq!(connection.read_frame().unwrap(), b"request");
        connection.write_frame(b"response").unwrap();
        client.join().unwrap();
    }
}

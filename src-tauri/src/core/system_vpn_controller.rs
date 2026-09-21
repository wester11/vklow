//! Normal-process side of the one-shot elevated System VPN session.
//! It owns exactly one authenticated pipe and the handle returned by UAC; it
//! never exposes a generic privileged command channel.

use crate::core::{
    system_vpn::SystemVpnSessionSpec,
    tun_launcher::{launch_elevated_helper, ElevatedHelper, ElevationError},
    tun_pipe::{TunPipeConnection, TunPipeServer},
    tun_protocol::{TunOperation, TunRequest, TunResponse, IPC_PROTOCOL_VERSION},
};
use std::{process, sync::mpsc, thread, time::Duration};
use zeroize::Zeroize;

const HELPER_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

pub struct SystemVpnController {
    helper: ElevatedHelper,
    pipe: TunPipeConnection,
    session_id: String,
    nonce: String,
    controller_pid: u32,
    helper_pid: u32,
}

impl SystemVpnController {
    pub fn start(spec: SystemVpnSessionSpec) -> Result<Self, ElevationError> {
        spec.validate().map_err(|_| ElevationError::LaunchFailed)?;
        let controller_pid = process::id();
        let pipe_name = format!(r"\\.\pipe\void-tun-{}", spec.session_id);
        let nonce = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let server = TunPipeServer::create(&pipe_name).map_err(|_| ElevationError::LaunchFailed)?;
        let current_exe =
            std::env::current_exe().map_err(|_| ElevationError::InvalidHelperLayout)?;
        let helper = launch_elevated_helper(
            &current_exe,
            &pipe_name,
            &spec.session_id,
            &nonce,
            controller_pid,
        )?;
        let helper_pid = helper.pid;
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let _ = sender.send(server.accept());
        });
        let mut pipe = match receiver.recv_timeout(HELPER_CONNECT_TIMEOUT) {
            Ok(Ok(pipe)) if pipe.peer_pid() == helper_pid => pipe,
            _ => {
                helper.terminate_if_owned();
                return Err(ElevationError::LaunchFailed);
            }
        };
        let request = TunRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            session_id: spec.session_id.clone(),
            nonce: nonce.clone(),
            controller_pid,
            helper_pid,
            operation: TunOperation::StartSystemVpnSession,
            system_vpn: Some(spec),
        };
        let mut bytes = serde_json::to_vec(&request).map_err(|_| ElevationError::LaunchFailed)?;
        let write_result = pipe.write_frame(&bytes);
        bytes.zeroize();
        write_result.map_err(|_| ElevationError::LaunchFailed)?;
        let response: TunResponse = serde_json::from_slice(
            &pipe
                .read_frame()
                .map_err(|_| ElevationError::LaunchFailed)?,
        )
        .map_err(|_| ElevationError::LaunchFailed)?;
        if !response.ok
            || response.state != "system_ipv4_tun_running"
            || response.protocol_version != IPC_PROTOCOL_VERSION
            || response.session_id != request.session_id
            || response.controller_pid != controller_pid
            || response.helper_pid != helper_pid
        {
            helper.terminate_if_owned();
            return Err(ElevationError::LaunchFailed);
        }
        Ok(Self {
            helper,
            pipe,
            session_id: request.session_id,
            nonce,
            controller_pid,
            helper_pid,
        })
    }

    pub fn stop(&mut self) -> Result<(), ElevationError> {
        let request = TunRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            session_id: self.session_id.clone(),
            nonce: self.nonce.clone(),
            controller_pid: self.controller_pid,
            helper_pid: self.helper_pid,
            operation: TunOperation::StopTunSession,
            system_vpn: None,
        };
        self.pipe
            .write_frame(&serde_json::to_vec(&request).map_err(|_| ElevationError::LaunchFailed)?)
            .map_err(|_| ElevationError::LaunchFailed)?;
        let response: TunResponse = serde_json::from_slice(
            &self
                .pipe
                .read_frame()
                .map_err(|_| ElevationError::LaunchFailed)?,
        )
        .map_err(|_| ElevationError::LaunchFailed)?;
        if response.ok
            && response.state == "stopped"
            && response.session_id == self.session_id
            && response.controller_pid == self.controller_pid
            && response.helper_pid == self.helper_pid
        {
            Ok(())
        } else {
            Err(ElevationError::LaunchFailed)
        }
    }
}

impl Drop for SystemVpnController {
    fn drop(&mut self) {
        // Pipe loss causes the helper's bounded session loop to clean its own
        // job/routes. The handle is an owned fallback if it does not return.
        self.helper.terminate_if_owned();
    }
}

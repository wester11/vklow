use std::{env, process, sync::mpsc, thread, time::Duration};
use void_desktop_lib::core::{
    tun_launcher::{launch_elevated_helper, ElevationError},
    tun_pipe::TunPipeServer,
    tun_protocol::{TunOperation, TunRequest, TunResponse, IPC_PROTOCOL_VERSION},
};

const HELPER_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

fn main() {
    match run() {
        Ok(result) => println!("{result}"),
        Err(ElevationError::ElevationCancelled) => println!("ElevationCancelled"),
        Err(error) => {
            eprintln!("VOID TUN controller failed: {error:?}");
            process::exit(1);
        }
    }
}

fn run() -> Result<String, ElevationError> {
    let controller_pid = process::id();
    let session_id = uuid::Uuid::new_v4().to_string();
    let nonce = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let pipe_name = format!(r"\\.\pipe\void-tun-{session_id}");
    let server = TunPipeServer::create(&pipe_name).map_err(|_| ElevationError::LaunchFailed)?;
    let current_exe = env::current_exe().map_err(|_| ElevationError::InvalidHelperLayout)?;
    let helper = launch_elevated_helper(
        &current_exe,
        &pipe_name,
        &session_id,
        &nonce,
        controller_pid,
    )?;
    let helper_pid = helper.pid;
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let result = server.accept();
        let _ = sender.send(result);
    });
    let mut pipe = match receiver.recv_timeout(HELPER_CONNECT_TIMEOUT) {
        Ok(Ok(pipe)) => pipe,
        _ => {
            helper.terminate_if_owned();
            return Err(ElevationError::LaunchFailed);
        }
    };
    if pipe.peer_pid() != helper_pid {
        helper.terminate_if_owned();
        return Err(ElevationError::LaunchFailed);
    }
    let request = TunRequest {
        protocol_version: IPC_PROTOCOL_VERSION,
        session_id: session_id.clone(),
        nonce,
        controller_pid,
        helper_pid,
        operation: TunOperation::StartScopedTunSession,
    };
    pipe.write_frame(&serde_json::to_vec(&request).map_err(|_| ElevationError::LaunchFailed)?)
        .map_err(|_| ElevationError::LaunchFailed)?;
    let response: TunResponse = serde_json::from_slice(
        &pipe
            .read_frame()
            .map_err(|_| ElevationError::LaunchFailed)?,
    )
    .map_err(|_| ElevationError::LaunchFailed)?;
    if !response.ok
        || response.session_id != session_id
        || response.controller_pid != controller_pid
        || response.helper_pid != helper_pid
    {
        return Err(ElevationError::LaunchFailed);
    }
    Ok(format!(
        "UAC handshake verified: controller_pid={controller_pid} helper_pid={helper_pid} pipe_client_pid={} pipe_server_pid={controller_pid}",
        pipe.peer_pid()
    ))
}

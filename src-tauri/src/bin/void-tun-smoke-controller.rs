use std::{env, process, sync::mpsc, thread, time::Duration};
use void_desktop_lib::core::{
    network::{
        compare_physical_dns, has_default_route_on, interface_metadata, physical_dns_snapshot,
        scoped_smoke_route, PhysicalDnsComparison, PhysicalDnsSnapshot,
    },
    tun_launcher::{launch_elevated_helper, ElevationError},
    tun_pipe::{TunPipeConnection, TunPipeServer},
    tun_protocol::{TunOperation, TunRequest, TunResponse, IPC_PROTOCOL_VERSION},
    xray::manager::XrayCoreManager,
};

const HELPER_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

fn main() {
    match run() {
        Ok(result) => println!("{result}"),
        Err(ElevationError::ElevationCancelled) => println!("ElevationCancelled"),
        Err(ElevationError::SmokeInconclusiveNetworkChanged) => {
            println!("SmokeInconclusiveNetworkChanged")
        }
        Err(ElevationError::PhysicalDnsMutated) => println!("PHYSICAL_DNS_MUTATED"),
        Err(error) => {
            eprintln!("VOID TUN controller failed: {error:?}");
            process::exit(1);
        }
    }
}

fn run() -> Result<String, ElevationError> {
    let abort_after_route = cfg!(debug_assertions)
        && env::args()
            .skip(1)
            .any(|argument| argument == "--abort-after-route");
    let route_before = scoped_smoke_route().map_err(|_| ElevationError::LaunchFailed)?;
    let dns_before = physical_dns_snapshot().map_err(|_| ElevationError::LaunchFailed)?;
    let app_data = env::var_os("APPDATA")
        .map(std::path::PathBuf::from)
        .ok_or(ElevationError::LaunchFailed)?
        .join("com.void.desktop");
    let baseline = https_check().map_err(|_| ElevationError::LaunchFailed)?;
    let core = XrayCoreManager::load(app_data);
    core.install_pinned_experimental_tun()
        .map_err(|_| ElevationError::LaunchFailed)?;
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
    if response.state != "scoped_tun_running" {
        return Err(ElevationError::LaunchFailed);
    }
    let route_during = scoped_smoke_route()
        .map_err(|_| ElevationError::LaunchFailed)?
        .ok_or(ElevationError::LaunchFailed)?;
    if has_default_route_on(route_during.interface_index)
        .map_err(|_| ElevationError::LaunchFailed)?
    {
        return Err(ElevationError::LaunchFailed);
    }
    let interface_before = interface_metadata(route_during.interface_index)
        .map_err(|_| ElevationError::LaunchFailed)?;
    if !interface_before.alias.starts_with("VOID Tunnel ") {
        return Err(ElevationError::LaunchFailed);
    }
    let dns_during = physical_dns_snapshot().map_err(|_| ElevationError::LaunchFailed)?;
    if let Err(error) = dns_equality_result(&dns_before, &dns_during) {
        let _ = stop_session(&mut pipe, &request, &session_id, controller_pid, helper_pid);
        return Err(error);
    }
    if abort_after_route {
        drop(pipe);
        thread::sleep(Duration::from_secs(3));
        let route_after_abort = scoped_smoke_route().map_err(|_| ElevationError::LaunchFailed)?;
        if route_after_abort != route_before {
            return Err(ElevationError::LaunchFailed);
        }
        let dns_after_abort = physical_dns_snapshot().map_err(|_| ElevationError::LaunchFailed)?;
        dns_equality_result(&dns_before, &dns_after_abort)?;
        let after_abort = https_check().map_err(|_| ElevationError::LaunchFailed)?;
        return Ok(format!(
            "Controlled failure cleanup: controller_pid={controller_pid} helper_pid={helper_pid} route_after={route_after_abort:?} dns_before={} dns_during={} dns_after={} void_tun_dns_during={} https_after={after_abort}",
            format_dns(&dns_before),
            format_dns(&dns_during),
            format_dns(&dns_after_abort),
            format_dns_adapters(&dns_during.void_tun_dns),
        ));
    }
    let through_tun = https_check().map_err(|_| ElevationError::LaunchFailed)?;
    let interface_after = interface_metadata(route_during.interface_index)
        .map_err(|_| ElevationError::LaunchFailed)?;
    let stopped = stop_session(&mut pipe, &request, &session_id, controller_pid, helper_pid)?;
    if !stopped.ok || stopped.state != "stopped" || stopped.helper_pid != helper_pid {
        return Err(ElevationError::LaunchFailed);
    }
    let route_after = scoped_smoke_route().map_err(|_| ElevationError::LaunchFailed)?;
    if route_after != route_before {
        return Err(ElevationError::LaunchFailed);
    }
    let dns_after = physical_dns_snapshot().map_err(|_| ElevationError::LaunchFailed)?;
    dns_equality_result(&dns_before, &dns_after)?;
    let after = https_check().map_err(|_| ElevationError::LaunchFailed)?;
    Ok(format!(
        "Scoped TUN smoke: controller_pid={controller_pid} helper_pid={helper_pid} pipe_client_pid={} pipe_server_pid={controller_pid} adapter_alias={} adapter_index={} adapter_luid={} tun_delta_in={} tun_delta_out={} route_before={:?} route_during={:?} route_after={:?} dns_before={} dns_during={} dns_after={} void_tun_dns_during={} dns_equality=equal https_before={baseline} https_tun={through_tun} https_after={after}",
        pipe.peer_pid(),
        interface_before.alias,
        interface_before.index,
        interface_before.luid,
        interface_after.in_octets.saturating_sub(interface_before.in_octets),
        interface_after.out_octets.saturating_sub(interface_before.out_octets),
        route_before,
        route_during,
        route_after,
        format_dns(&dns_before),
        format_dns(&dns_during),
        format_dns(&dns_after),
        format_dns_adapters(&dns_during.void_tun_dns),
    ))
}

fn dns_equality_result(
    before: &PhysicalDnsSnapshot,
    observed: &PhysicalDnsSnapshot,
) -> Result<(), ElevationError> {
    match compare_physical_dns(before, observed) {
        PhysicalDnsComparison::Equal => Ok(()),
        PhysicalDnsComparison::SmokeInconclusiveNetworkChanged => {
            Err(ElevationError::SmokeInconclusiveNetworkChanged)
        }
        PhysicalDnsComparison::PhysicalDnsMutated => Err(ElevationError::PhysicalDnsMutated),
    }
}

fn stop_session(
    pipe: &mut TunPipeConnection,
    request: &TunRequest,
    session_id: &str,
    controller_pid: u32,
    helper_pid: u32,
) -> Result<TunResponse, ElevationError> {
    let stop = TunRequest {
        protocol_version: IPC_PROTOCOL_VERSION,
        session_id: session_id.to_owned(),
        nonce: request.nonce.clone(),
        controller_pid,
        helper_pid,
        operation: TunOperation::StopTunSession,
    };
    pipe.write_frame(&serde_json::to_vec(&stop).map_err(|_| ElevationError::LaunchFailed)?)
        .map_err(|_| ElevationError::LaunchFailed)?;
    serde_json::from_slice(
        &pipe
            .read_frame()
            .map_err(|_| ElevationError::LaunchFailed)?,
    )
    .map_err(|_| ElevationError::LaunchFailed)
}

fn format_dns(snapshot: &PhysicalDnsSnapshot) -> String {
    format_dns_adapters(&snapshot.adapters)
}

fn format_dns_adapters(
    adapters: &[void_desktop_lib::core::network::PhysicalAdapterDnsSnapshot],
) -> String {
    adapters
        .iter()
        .map(|adapter| {
            format!(
                "[luid={} if4={} if6={} type={} status={} hardware={} name={:?} dns={:?}]",
                adapter.luid,
                adapter.if_index_v4,
                adapter.if_index_v6,
                adapter.interface_type,
                adapter.operational_status,
                adapter.hardware_interface,
                adapter.friendly_name,
                adapter.dns_servers
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn https_check() -> Result<u16, String> {
    let response = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(12))
        .build()
        .map_err(|_| "Unable to prepare direct HTTPS client")?
        .get("https://1.1.1.1/help")
        .send()
        .map_err(|_| "SmokePreconditionFailed")?;
    let status = response.status().as_u16();
    if response
        .content_length()
        .is_some_and(|length| length > 64 * 1024)
    {
        return Err("HTTPS response exceeds smoke limit".into());
    }
    Ok(status)
}

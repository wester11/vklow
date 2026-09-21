use std::{env, net::ToSocketAddrs, process, sync::mpsc, thread, time::Duration};
use void_desktop_lib::core::{
    network::{
        compare_physical_dns, full_ipv4_routes, has_default_route_on, interface_metadata,
        physical_default_routes, physical_dns_snapshot, scoped_smoke_route, void_tun_adapters,
        PhysicalDnsComparison, PhysicalDnsSnapshot,
    },
    tun::TunSessionJournal,
    tun_launcher::{launch_elevated_helper, ElevationError},
    tun_pipe::{TunPipeConnection, TunPipeServer},
    tun_protocol::{TunOperation, TunRequest, TunResponse, IPC_PROTOCOL_VERSION},
    xray::manager::XrayCoreManager,
};

const HELPER_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

fn main() {
    if cfg!(debug_assertions) {
        let stress_cycles = if env::args()
            .skip(1)
            .any(|argument| argument == "--stress-full-ipv4")
        {
            Some(10)
        } else if env::args()
            .skip(1)
            .any(|argument| argument == "--stress-3-full-ipv4")
        {
            Some(3)
        } else {
            None
        };
        if let Some(cycles) = stress_cycles {
            match run_full_ipv4_stress(cycles) {
                Ok(result) => println!("{result}"),
                Err(error) => {
                    eprintln!("VOID full IPv4 stress failed: {error:?}");
                    process::exit(1);
                }
            }
            return;
        }
    }
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

/// Development-only reliability harness. Every iteration intentionally invokes
/// the same per-session controller/UAC/helper path as production; it does not
/// turn the helper into a service or accept any extra privileged operation.
fn run_full_ipv4_stress(cycles: u8) -> Result<String, ElevationError> {
    for cycle in 1..=cycles {
        wait_for_network_quiescence()?;
        run()?;
        let app_data = env::var_os("APPDATA")
            .map(std::path::PathBuf::from)
            .ok_or(ElevationError::LaunchFailed)?
            .join("com.void.desktop");
        if app_data.join("tun-session.json").exists()
            || full_ipv4_routes()
                .map_err(|_| ElevationError::LaunchFailed)?
                .iter()
                .any(Option::is_some)
        {
            return Err(ElevationError::LaunchFailed);
        }
        println!("full_ipv4_stress_cycle={cycle}/{cycles} clean");
    }
    Ok(format!("full_ipv4_stress={cycles}/{cycles} clean"))
}

/// Polls observable owned state rather than sleeping an arbitrary amount between
/// sessions. Wintun may retain an inert driver object, but an active adapter DNS
/// configuration, an owned route, or a journal is never acceptable here.
fn wait_for_network_quiescence() -> Result<(), ElevationError> {
    let app_data = env::var_os("APPDATA")
        .map(std::path::PathBuf::from)
        .ok_or(ElevationError::LaunchFailed)?
        .join("com.void.desktop");
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_secs(20) {
        let routes_clear = full_ipv4_routes()
            .map_err(|_| ElevationError::LaunchFailed)?
            .iter()
            .all(Option::is_none);
        let adapters = void_tun_adapters().map_err(|_| ElevationError::LaunchFailed)?;
        // A Wintun object may legitimately remain registered by its driver, but
        // it must not retain an active TUN DNS assignment between sessions.
        let adapter_dns_clear = adapters
            .iter()
            .all(|adapter| adapter.dns_servers.is_empty());
        let physical_default_ok = !physical_default_routes()
            .map_err(|_| ElevationError::LaunchFailed)?
            .is_empty();
        if routes_clear
            && adapter_dns_clear
            && physical_default_ok
            && !app_data.join("tun-session.json").exists()
            && https_check().is_ok()
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    eprintln!(
        "stress quiescence timeout after {}ms",
        started.elapsed().as_millis()
    );
    Err(ElevationError::LaunchFailed)
}

fn run() -> Result<String, ElevationError> {
    stress_phase("CycleStarted");
    let abort_after_route = cfg!(debug_assertions)
        && env::args()
            .skip(1)
            .any(|argument| argument == "--abort-after-route");
    let full_ipv4 = env::args()
        .skip(1)
        .any(|argument| argument == "--full-ipv4");
    let test_crash_core = cfg!(debug_assertions)
        && env::args()
            .skip(1)
            .any(|argument| argument == "--crash-xray-after-route");
    let test_crash_helper = cfg!(debug_assertions)
        && env::args()
            .skip(1)
            .any(|argument| argument == "--crash-helper-after-route");
    let route_before = scoped_smoke_route().map_err(|_| ElevationError::LaunchFailed)?;
    let full_routes_before = full_ipv4_routes().map_err(|_| ElevationError::LaunchFailed)?;
    if full_ipv4 && full_routes_before.iter().any(Option::is_some) {
        return Err(ElevationError::LaunchFailed);
    }
    let dns_before = physical_dns_snapshot().map_err(|_| ElevationError::LaunchFailed)?;
    stress_phase("BaselineSnapshotCaptured");
    let app_data = env::var_os("APPDATA")
        .map(std::path::PathBuf::from)
        .ok_or(ElevationError::LaunchFailed)?
        .join("com.void.desktop");
    let baseline = retry_transient("baseline IP HTTPS", https_check)?;
    let hostname_baseline = retry_transient("baseline hostname HTTPS", https_hostname_check)?;
    stress_phase("BaselineConnectivityPassed");
    let core = XrayCoreManager::load(app_data.clone());
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
    stress_phase("HelperLaunchRequested");
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
    stress_phase("PipeConnected");
    if pipe.peer_pid() != helper_pid {
        helper.terminate_if_owned();
        return Err(ElevationError::LaunchFailed);
    }
    stress_phase("PipeAuthenticated");
    let request = TunRequest {
        protocol_version: IPC_PROTOCOL_VERSION,
        session_id: session_id.clone(),
        nonce,
        controller_pid,
        helper_pid,
        operation: if full_ipv4 {
            TunOperation::StartFullIpv4Experimental
        } else {
            TunOperation::StartScopedTunSession
        },
        system_vpn: None,
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
        if let Some(message) = response.message {
            eprintln!("VOID TUN helper rejected typed session: {message}");
        }
        return Err(ElevationError::LaunchFailed);
    }
    if response.state
        != if full_ipv4 {
            "full_ipv4_tun_running"
        } else {
            "scoped_tun_running"
        }
    {
        return Err(ElevationError::LaunchFailed);
    }
    stress_phase("XrayAndTunReady");
    let route_during = if full_ipv4 {
        let [first, second] = full_ipv4_routes().map_err(|_| ElevationError::LaunchFailed)?;
        let first = first.ok_or(ElevationError::LaunchFailed)?;
        let second = second.ok_or(ElevationError::LaunchFailed)?;
        if first.interface_index != second.interface_index
            || physical_default_routes()
                .map_err(|_| ElevationError::LaunchFailed)?
                .iter()
                .all(|route| route.interface_index == first.interface_index)
        {
            return Err(ElevationError::LaunchFailed);
        }
        first
    } else {
        scoped_smoke_route()
            .map_err(|_| ElevationError::LaunchFailed)?
            .ok_or(ElevationError::LaunchFailed)?
    };
    stress_phase("BothRoutesObserved");
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
    stress_phase("PhysicalDnsVerified");
    if test_crash_helper {
        helper.terminate_if_owned();
        drop(pipe);
        thread::sleep(Duration::from_secs(3));
        recover_stale_owned_journal(&app_data)?;
        let full_after = full_ipv4_routes().map_err(|_| ElevationError::LaunchFailed)?;
        if (full_ipv4 && full_after != full_routes_before)
            || (!full_ipv4
                && scoped_smoke_route().map_err(|_| ElevationError::LaunchFailed)? != route_before)
        {
            return Err(ElevationError::LaunchFailed);
        }
        let dns_after = physical_dns_snapshot().map_err(|_| ElevationError::LaunchFailed)?;
        dns_equality_result(&dns_before, &dns_after)?;
        let ip = https_check().map_err(|_| ElevationError::LaunchFailed)?;
        return Ok(format!(
            "Helper Job Object crash cleanup: full_ipv4={full_ipv4} full_routes_after={full_after:?} dns_after={} https_ip_after={ip}",
            format_dns(&dns_after),
        ));
    }
    if test_crash_core {
        let crash = TunRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            session_id: session_id.clone(),
            nonce: request.nonce.clone(),
            controller_pid,
            helper_pid,
            operation: TunOperation::TestCrashOwnedCore,
            system_vpn: None,
        };
        pipe.write_frame(&serde_json::to_vec(&crash).map_err(|_| ElevationError::LaunchFailed)?)
            .map_err(|_| ElevationError::LaunchFailed)?;
        let crashed: TunResponse = serde_json::from_slice(
            &pipe
                .read_frame()
                .map_err(|_| ElevationError::LaunchFailed)?,
        )
        .map_err(|_| ElevationError::LaunchFailed)?;
        if !crashed.ok || crashed.state != "owned_core_crash_recovered" {
            return Err(ElevationError::LaunchFailed);
        }
        let full_after = full_ipv4_routes().map_err(|_| ElevationError::LaunchFailed)?;
        if (full_ipv4 && full_after != full_routes_before)
            || (!full_ipv4
                && scoped_smoke_route().map_err(|_| ElevationError::LaunchFailed)? != route_before)
        {
            return Err(ElevationError::LaunchFailed);
        }
        let dns_after = physical_dns_snapshot().map_err(|_| ElevationError::LaunchFailed)?;
        dns_equality_result(&dns_before, &dns_after)?;
        let ip = https_check().map_err(|_| ElevationError::LaunchFailed)?;
        let hostname = https_hostname_check().map_err(|_| ElevationError::LaunchFailed)?;
        return Ok(format!(
            "Owned Xray crash cleanup: mode={} full_routes_after={full_after:?} dns_before={} dns_during={} dns_after={} https_ip_after={ip} https_hostname_after={hostname}",
            if full_ipv4 { "full_ipv4" } else { "scoped" },
            format_dns(&dns_before),
            format_dns(&dns_during),
            format_dns(&dns_after),
        ));
    }
    if abort_after_route {
        drop(pipe);
        thread::sleep(Duration::from_secs(3));
        let route_after_abort = scoped_smoke_route().map_err(|_| ElevationError::LaunchFailed)?;
        let full_after_abort = full_ipv4_routes().map_err(|_| ElevationError::LaunchFailed)?;
        if (!full_ipv4 && route_after_abort != route_before)
            || (full_ipv4 && full_after_abort != full_routes_before)
        {
            return Err(ElevationError::LaunchFailed);
        }
        let dns_after_abort = physical_dns_snapshot().map_err(|_| ElevationError::LaunchFailed)?;
        dns_equality_result(&dns_before, &dns_after_abort)?;
        let after_abort = https_check().map_err(|_| ElevationError::LaunchFailed)?;
        let hostname_after_abort =
            https_hostname_check().map_err(|_| ElevationError::LaunchFailed)?;
        return Ok(format!(
            "Controlled failure cleanup: mode={} controller_pid={controller_pid} helper_pid={helper_pid} route_after={route_after_abort:?} full_routes_after={full_after_abort:?} dns_before={} dns_during={} dns_after={} void_tun_dns_during={} https_after={after_abort} hostname_https_after={hostname_after_abort}",
            if full_ipv4 { "full_ipv4" } else { "scoped" },
            format_dns(&dns_before),
            format_dns(&dns_during),
            format_dns(&dns_after_abort),
            format_dns_adapters(&dns_during.void_tun_dns),
        ));
    }
    let through_tun = retry_transient("TUN IP HTTPS", https_check)?;
    let hostname_through_tun = retry_transient("TUN hostname HTTPS", https_hostname_check)?;
    let udp_resolution = retry_transient("TUN system DNS", system_dns_udp_check)?;
    stress_phase("ConnectivityPassed");
    let interface_after = interface_metadata(route_during.interface_index)
        .map_err(|_| ElevationError::LaunchFailed)?;
    let stopped = stop_session(&mut pipe, &request, &session_id, controller_pid, helper_pid)?;
    if !stopped.ok || stopped.state != "stopped" || stopped.helper_pid != helper_pid {
        return Err(ElevationError::LaunchFailed);
    }
    stress_phase("StoppingCompleted");
    let route_after = scoped_smoke_route().map_err(|_| ElevationError::LaunchFailed)?;
    let full_routes_after = full_ipv4_routes().map_err(|_| ElevationError::LaunchFailed)?;
    if (!full_ipv4 && route_after != route_before)
        || (full_ipv4 && full_routes_after != full_routes_before)
    {
        return Err(ElevationError::LaunchFailed);
    }
    let dns_after = physical_dns_snapshot().map_err(|_| ElevationError::LaunchFailed)?;
    dns_equality_result(&dns_before, &dns_after)?;
    let after = retry_transient("post-cleanup IP HTTPS", https_check)?;
    let hostname_after = retry_transient("post-cleanup hostname HTTPS", https_hostname_check)?;
    stress_phase("CycleCompleted");
    Ok(format!(
        "TUN smoke: mode={} controller_pid={controller_pid} helper_pid={helper_pid} pipe_client_pid={} pipe_server_pid={controller_pid} adapter_alias={} adapter_index={} adapter_luid={} tun_delta_in={} tun_delta_out={} route_before={:?} route_during={:?} route_after={:?} full_routes_before={full_routes_before:?} full_routes_after={full_routes_after:?} dns_before={} dns_during={} dns_after={} void_tun_dns_during={} dns_equality=equal https_ip_before={baseline} https_ip_tun={through_tun} https_ip_after={after} https_hostname_before={hostname_baseline} https_hostname_tun={hostname_through_tun} https_hostname_after={hostname_after} udp_system_resolution={udp_resolution}",
        if full_ipv4 { "full_ipv4" } else { "scoped" },
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

fn stress_phase(phase: &str) {
    if env::args()
        .skip(1)
        .any(|argument| argument == "--stress-full-ipv4")
    {
        println!("stress_phase={phase}");
    }
}

fn retry_transient<T>(
    label: &str,
    check: impl Fn() -> Result<T, String>,
) -> Result<T, ElevationError> {
    let mut last_error = None;
    for attempt in 1..=3 {
        match check() {
            Ok(value) => return Ok(value),
            Err(error) => {
                last_error = Some(error);
                if attempt < 3 {
                    thread::sleep(Duration::from_millis(250 * attempt));
                }
            }
        }
    }
    eprintln!(
        "{label} failed after bounded retries: {}",
        last_error.unwrap_or_default()
    );
    Err(ElevationError::LaunchFailed)
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
        system_vpn: None,
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

fn recover_stale_owned_journal(app_data: &std::path::Path) -> Result<(), ElevationError> {
    let journal_path = app_data.join("tun-session.json");
    let Some(journal) =
        TunSessionJournal::load(&journal_path).map_err(|_| ElevationError::LaunchFailed)?
    else {
        return Ok(());
    };
    let adapter_exists = void_tun_adapters()
        .map_err(|_| ElevationError::LaunchFailed)?
        .into_iter()
        .any(|adapter| {
            adapter.friendly_name == journal.adapter_name
                && journal
                    .adapter_luid
                    .is_some_and(|luid| luid == adapter.luid)
        });
    let [first, second] = full_ipv4_routes().map_err(|_| ElevationError::LaunchFailed)?;
    if adapter_exists || first.is_some() || second.is_some() {
        return Err(ElevationError::LaunchFailed);
    }
    std::fs::remove_file(journal_path).map_err(|_| ElevationError::LaunchFailed)
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

fn https_hostname_check() -> Result<u16, String> {
    let response = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(12))
        .build()
        .map_err(|_| "Unable to prepare hostname HTTPS client")?
        .get("https://www.cloudflare.com/cdn-cgi/trace")
        .send()
        .map_err(|_| "HostnameHttpsFailed")?;
    Ok(response.status().as_u16())
}

/// Uses the regular Windows resolver, which may select UDP DNS internally. The
/// resolved endpoint is intentionally not queried through a custom DNS socket.
fn system_dns_udp_check() -> Result<usize, String> {
    ("www.cloudflare.com", 443)
        .to_socket_addrs()
        .map(|addresses| addresses.filter(|address| address.is_ipv4()).count())
        .map_err(|_| "SystemDnsResolutionFailed".into())
        .and_then(|count| {
            if count == 0 {
                Err("SystemDnsReturnedNoIpv4Address".into())
            } else {
                Ok(count)
            }
        })
}

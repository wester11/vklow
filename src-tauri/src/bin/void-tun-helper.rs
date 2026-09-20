use std::{
    env, fs,
    process::{self, Command, Stdio},
    thread,
    time::Duration,
};
use void_desktop_lib::core::{
    job::OwnedXrayJob,
    network::{
        full_ipv4_routes, has_default_route_on, interface_metadata, physical_default_routes,
        scoped_smoke_route, void_tun_adapters,
    },
    tun::{OwnedRoute, TunSessionJournal, TunSessionPhase, TunSessionPolicy},
    tun_pipe::TunPipeConnection,
    tun_protocol::{TunOperation, TunRequest, TunResponse},
    xray::{
        config::{
            full_ipv4_freedom_config, scoped_tun_smoke_config, FULL_IPV4_ROUTES, FULL_IPV4_TUN_DNS,
        },
        manager::XrayCoreManager,
    },
};
use windows_sys::Win32::{
    NetworkManagement::IpHelper::{
        CreateIpForwardEntry2, DeleteIpForwardEntry2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
    },
    Networking::WinSock::AF_INET,
};

struct Bootstrap {
    pipe: String,
    session_id: String,
    nonce: String,
    controller_pid: u32,
}

fn main() {
    let result = run();
    if let Err(message) = result {
        eprintln!("VOID TUN helper failed: {message}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let bootstrap = parse_bootstrap(env::args().skip(1).collect())?;
    let helper_pid = process::id();
    let mut pipe = TunPipeConnection::connect(&bootstrap.pipe)?;
    if pipe.peer_pid() != bootstrap.controller_pid {
        return Err("TUN controller PID mismatch".into());
    }
    let request = TunRequest::decode(&pipe.read_frame()?, &bootstrap.session_id, &bootstrap.nonce)?;
    if request.controller_pid != bootstrap.controller_pid || request.helper_pid != helper_pid {
        return Err("TUN IPC process identity mismatch".into());
    }
    if !matches!(
        request.operation,
        TunOperation::StartScopedTunSession | TunOperation::StartFullIpv4Experimental
    ) {
        let response = TunResponse::rejected(
            bootstrap.session_id.clone(),
            bootstrap.controller_pid,
            helper_pid,
            "First helper request must start a typed TUN policy",
        );
        pipe.write_frame(
            &serde_json::to_vec(&response).map_err(|_| "Unable to encode helper response")?,
        )?;
        return Err("Rejected TUN helper operation".into());
    }
    let full_ipv4 = request.operation == TunOperation::StartFullIpv4Experimental;
    let mut session = match start_tun(&bootstrap, full_ipv4) {
        Ok(session) => session,
        Err(error) => {
            let response = TunResponse::rejected(
                bootstrap.session_id.clone(),
                bootstrap.controller_pid,
                helper_pid,
                &error,
            );
            let _ = pipe.write_frame(
                &serde_json::to_vec(&response).map_err(|_| "Unable to encode helper response")?,
            );
            return Err(error);
        }
    };
    let response = TunResponse::accepted(
        bootstrap.session_id.clone(),
        bootstrap.controller_pid,
        helper_pid,
        if full_ipv4 {
            "full_ipv4_tun_running"
        } else {
            "scoped_tun_running"
        },
    );
    pipe.write_frame(
        &serde_json::to_vec(&response).map_err(|_| "Unable to encode helper response")?,
    )?;
    let stop = match pipe
        .read_frame()
        .and_then(|bytes| TunRequest::decode(&bytes, &bootstrap.session_id, &bootstrap.nonce))
    {
        Ok(request) => request,
        Err(error) => {
            let _ = session.stop();
            return Err(error);
        }
    };
    if stop.controller_pid != bootstrap.controller_pid
        || stop.helper_pid != helper_pid
        || !matches!(
            stop.operation,
            TunOperation::StopTunSession | TunOperation::TestCrashOwnedCore
        )
    {
        let _ = session.stop();
        return Err("Invalid TUN stop request".into());
    }
    let state = if stop.operation == TunOperation::TestCrashOwnedCore {
        if session
            .child
            .try_wait()
            .map_err(|_| "Unable to inspect owned Xray")?
            .is_none()
        {
            session
                .child
                .kill()
                .map_err(|_| "Unable to crash owned Xray")?;
            session
                .child
                .wait()
                .map_err(|_| "Unable to reap owned Xray")?;
        }
        session.stop()?;
        "owned_core_crash_recovered"
    } else {
        session.stop()?;
        "stopped"
    };
    let response = TunResponse::accepted(
        bootstrap.session_id,
        bootstrap.controller_pid,
        helper_pid,
        state,
    );
    pipe.write_frame(
        &serde_json::to_vec(&response).map_err(|_| "Unable to encode helper response")?,
    )
}

struct OwnedTunSession {
    child: std::process::Child,
    _job: OwnedXrayJob,
    config: std::path::PathBuf,
    journal_path: std::path::PathBuf,
    journal: TunSessionJournal,
    manual_routes: Vec<MIB_IPFORWARD_ROW2>,
}

impl OwnedTunSession {
    fn stop(&mut self) -> Result<(), String> {
        self.journal.transition(TunSessionPhase::Stopping);
        self.journal.save_atomic(&self.journal_path)?;
        for route in &self.manual_routes {
            let _ = unsafe { DeleteIpForwardEntry2(route) };
        }
        if self
            .child
            .try_wait()
            .map_err(|_| "Unable to inspect owned Xray")?
            .is_none()
        {
            self.child.kill().map_err(|_| "Unable to stop owned Xray")?;
            self.child.wait().map_err(|_| "Unable to reap owned Xray")?;
        }
        let _ = fs::remove_file(&self.config);
        self.journal.transition(TunSessionPhase::Completed);
        self.journal.save_atomic(&self.journal_path)?;
        fs::remove_file(&self.journal_path)
            .map_err(|_| "Unable to clear completed TUN journal".to_owned())
    }
}

fn start_tun(bootstrap: &Bootstrap, full_ipv4: bool) -> Result<OwnedTunSession, String> {
    let app_data = env::var_os("APPDATA")
        .map(std::path::PathBuf::from)
        .ok_or("Unable to resolve VOID app data")?
        .join("com.void.desktop");
    let core = XrayCoreManager::load(app_data);
    let binary = core.experimental_tun_binary()?;
    let version_dir = binary
        .parent()
        .ok_or("Invalid experimental Xray location")?
        .canonicalize()
        .map_err(|_| "Unable to resolve experimental Xray location")?;
    let binary = binary
        .canonicalize()
        .map_err(|_| "Unable to resolve experimental xray.exe")?;
    if !binary.starts_with(&version_dir) || !binary.with_file_name("wintun.dll").is_file() {
        return Err("Verified experimental Xray or Wintun is unavailable".into());
    }
    let adapter_name = format!("VOID Tunnel {}", &bootstrap.session_id[..8]);
    let mut journal = TunSessionJournal::new(
        bootstrap.session_id.clone(),
        adapter_name.clone(),
        "v26.9.8".into(),
        if full_ipv4 {
            TunSessionPolicy::FullIpv4Experimental
        } else {
            TunSessionPolicy::ScopedSmoke
        },
    );
    if full_ipv4 {
        journal.owned_routes = FULL_IPV4_ROUTES
            .iter()
            .map(|destination| OwnedRoute {
                destination: (*destination).into(),
                interface_alias: adapter_name.clone(),
            })
            .collect();
        journal.tun_dns = FULL_IPV4_TUN_DNS
            .iter()
            .map(|value| (*value).into())
            .collect();
        if physical_default_routes()?.is_empty() {
            return Err("Physical IPv4 default route is absent before full TUN start".into());
        }
    } else {
        journal.owned_routes = vec![OwnedRoute {
            destination: "1.1.1.1/32".into(),
            interface_alias: adapter_name.clone(),
        }];
    }
    journal.transition(TunSessionPhase::StartingTun);
    let journal_path = core.tun_journal_path();
    journal.save_atomic(&journal_path)?;
    let config = core
        .runtime_directory()
        .join(format!("tun-{}.json", bootstrap.session_id));
    fs::write(
        &config,
        serde_json::to_vec(&if full_ipv4 {
            full_ipv4_freedom_config(&adapter_name)?
        } else {
            scoped_tun_smoke_config(&adapter_name)?
        })
        .map_err(|_| "Unable to serialize TUN config")?,
    )
    .map_err(|_| "Unable to write private TUN runtime config")?;
    let validation = Command::new(&binary)
        .args(["run", "-test", "-c"])
        .arg(&config)
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "Unable to validate experimental TUN config")?;
    if !validation.status.success() {
        let _ = fs::remove_file(&config);
        let _ = fs::remove_file(&journal_path);
        return Err("Experimental Xray rejected scoped TUN config".into());
    }
    let mut child = Command::new(&binary)
        .args(["run", "-c"])
        .arg(&config)
        .current_dir(core.runtime_directory())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "Unable to launch verified experimental Xray")?;
    let job = OwnedXrayJob::create()?;
    if let Err(error) = job.assign(&child) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    journal.core_pid = Some(child.id());
    journal.save_atomic(&journal_path)?;
    thread::sleep(Duration::from_secs(3));
    if child
        .try_wait()
        .map_err(|_| "Unable to inspect owned Xray")?
        .is_some()
    {
        let _ = fs::remove_file(&config);
        let _ = fs::remove_file(&journal_path);
        return Err("Experimental Xray exited before TUN readiness".into());
    }
    let mut session = OwnedTunSession {
        child,
        _job: job,
        config,
        journal_path,
        journal,
        manual_routes: Vec::new(),
    };
    if full_ipv4 {
        let index = wait_for_owned_adapter(&session.journal.adapter_name)?;
        session.manual_routes = install_full_ipv4_routes(index)?;
    }
    if let Err(error) = if full_ipv4 {
        wait_for_full_ipv4_routes(&mut session)
    } else {
        wait_for_scoped_route(&mut session)
    } {
        let _ = session.stop();
        return Err(error);
    }
    Ok(session)
}

fn wait_for_owned_adapter(adapter_name: &str) -> Result<u32, String> {
    for _ in 0..40 {
        if let Some(adapter) = void_tun_adapters()?
            .into_iter()
            .find(|adapter| adapter.friendly_name == adapter_name)
        {
            return Ok(adapter.if_index_v4);
        }
        thread::sleep(Duration::from_millis(250));
    }
    Err("VOID adapter did not appear before full route installation".into())
}

fn install_full_ipv4_routes(index: u32) -> Result<Vec<MIB_IPFORWARD_ROW2>, String> {
    let mut created = Vec::new();
    for (destination, prefix_length) in [([0, 0, 0, 0], 1), ([128, 0, 0, 0], 1)] {
        let mut route = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut route) };
        route.InterfaceIndex = index;
        route.DestinationPrefix.PrefixLength = prefix_length;
        route.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
        route.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr = u32::from_be_bytes(destination);
        route.NextHop.Ipv4.sin_family = AF_INET;
        route.Metric = 1;
        let status = unsafe { CreateIpForwardEntry2(&route) };
        if status == 5010 {
            // Xray's typed autoSystemRoutingTable won the race. It owns this
            // route and will remove it with the owned core process.
            return Ok(Vec::new());
        }
        if status != 0 {
            for previous in &created {
                let _ = unsafe { DeleteIpForwardEntry2(previous) };
            }
            return Err(format!(
                "Unable to install owned full IPv4 route (Win32 {status})"
            ));
        }
        created.push(route);
    }
    Ok(created)
}

fn wait_for_scoped_route(session: &mut OwnedTunSession) -> Result<(), String> {
    for _ in 0..30 {
        if session
            .child
            .try_wait()
            .map_err(|_| "Unable to inspect owned Xray")?
            .is_some()
        {
            return Err("Experimental Xray exited before scoped route readiness".into());
        }
        if let Some(route) = scoped_smoke_route()? {
            if has_default_route_on(route.interface_index)? {
                return Err("Unexpected VOID default route detected".into());
            }
            let interface = interface_metadata(route.interface_index)?;
            if interface.alias != session.journal.adapter_name {
                return Err("Scoped route does not belong to the current VOID adapter".into());
            }
            session.journal.interface_index = Some(route.interface_index);
            session.journal.adapter_luid = Some(interface.luid);
            session.journal.transition(TunSessionPhase::AdapterReady);
            session.journal.save_atomic(&session.journal_path)?;
            session
                .journal
                .transition(TunSessionPhase::ScopedRouteReady);
            session.journal.save_atomic(&session.journal_path)?;
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    Err("Scoped 1.1.1.1/32 route did not appear".into())
}

fn wait_for_full_ipv4_routes(session: &mut OwnedTunSession) -> Result<(), String> {
    for _ in 0..40 {
        if session
            .child
            .try_wait()
            .map_err(|_| "Unable to inspect owned Xray")?
            .is_some()
        {
            return Err("Experimental Xray exited before full IPv4 route readiness".into());
        }
        let [first, second] = full_ipv4_routes()?;
        if let (Some(first), Some(second)) = (first, second) {
            if first.interface_index != second.interface_index {
                return Err("Full IPv4 routes do not share one VOID adapter".into());
            }
            if has_default_route_on(first.interface_index)? {
                return Err("Unexpected VOID default route detected".into());
            }
            if physical_default_routes()?
                .into_iter()
                .all(|route| route.interface_index == first.interface_index)
            {
                return Err("Physical IPv4 default route was not retained".into());
            }
            let interface = interface_metadata(first.interface_index)?;
            if interface.alias != session.journal.adapter_name {
                return Err("Full IPv4 routes do not belong to the current VOID adapter".into());
            }
            session.journal.interface_index = Some(first.interface_index);
            session.journal.adapter_luid = Some(interface.luid);
            session.journal.transition(TunSessionPhase::AdapterReady);
            session.journal.save_atomic(&session.journal_path)?;
            session
                .journal
                .transition(TunSessionPhase::FullIpv4RoutesReady);
            session.journal.save_atomic(&session.journal_path)?;
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    Err("Full IPv4 /1 routes did not appear".into())
}

fn parse_bootstrap(arguments: Vec<String>) -> Result<Bootstrap, String> {
    if arguments.len() != 8 {
        return Err("Invalid TUN helper bootstrap arguments".into());
    }
    let value = |flag: &str| -> Result<&str, String> {
        arguments
            .windows(2)
            .find(|pair| pair[0] == flag)
            .map(|pair| pair[1].as_str())
            .ok_or_else(|| "Invalid TUN helper bootstrap arguments".into())
    };
    let pipe = value("--pipe")?.to_owned();
    let session_id = value("--session")?.to_owned();
    let nonce = value("--nonce")?.to_owned();
    let controller_pid = value("--controller-pid")?
        .parse()
        .map_err(|_| "Invalid TUN controller PID")?;
    if !pipe.starts_with(r"\\.\pipe\void-tun-")
        || session_id.len() != 36
        || nonce.len() < 32
        || controller_pid == 0
    {
        return Err("Invalid TUN helper bootstrap values".into());
    }
    Ok(Bootstrap {
        pipe,
        session_id,
        nonce,
        controller_pid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_accepts_only_fixed_bootstrap_surface() {
        assert!(parse_bootstrap(vec![
            "--pipe".into(),
            r"\\.\pipe\void-tun-example".into(),
            "--session".into(),
            "2b7e4251-3328-4470-8708-e19084073cb3".into(),
            "--nonce".into(),
            "Kzf4TeYHAb29qVi1_6vm5VH9mqNUJM60BaVGFvYp9Hk".into(),
            "--controller-pid".into(),
            "42".into(),
        ])
        .is_ok());
        assert!(parse_bootstrap(vec!["--exec".into(), "evil.exe".into()]).is_err());
    }
}

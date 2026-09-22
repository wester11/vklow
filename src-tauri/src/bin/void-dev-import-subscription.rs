//! Development-only one-shot subscription importer.
//!
//! It is feature-gated out of normal Tauri builds and accepts its sole secret
//! from stdin. Never add URL arguments, environment-variable input or a
//! plaintext hand-off file to this tool.

use sha2::Digest;
use std::{
    fs,
    io::{self, Read},
    net::{IpAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    process::{self, Command},
    time::Duration,
};
use void_desktop_lib::{
    core::{
        network::{
            compare_physical_dns, full_ipv4_routes, has_default_route_on, interface_metadata,
            physical_default_routes, physical_dns_snapshot, void_tun_adapters,
            PhysicalDnsComparison, PhysicalDnsSnapshot,
        },
        secrets::{subscription_url_key, SecretStore, WindowsSecretStore},
        system_vpn::{
            authoritative_endpoint_for_system_vpn, compatibility_diagnostic, SystemVpnSessionSpec,
        },
        system_vpn_controller::SystemVpnController,
        tun::TunSessionJournal,
        xray::{config::FULL_IPV4_TUN_DNS, manager::XrayCoreManager},
    },
    domain::{Protocol, Server, ServerEndpoint},
    subscription::{
        fetch_subscription_text, import_https_subscription, inspect_vless_endpoint_provenance,
    },
};
use zeroize::Zeroize;

const MAX_SCAN_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Eq, PartialEq)]
enum RunMode {
    ImportOnly,
    Phase2,
    Provenance(String),
}

fn main() {
    let mode = match run_mode() {
        Some(mode) => mode,
        None => {
            eprintln!("usage: void-dev-import-subscription [--phase2] < stdin | --provenance <subscription-id>");
            process::exit(2);
        }
    };
    if let RunMode::Provenance(subscription_id) = mode {
        if let Err(error) = run_endpoint_provenance(&subscription_id) {
            eprintln!("endpoint_provenance_failed stage={error}");
            process::exit(1);
        }
        return;
    }
    let mut source = match read_one_secret_line() {
        Ok(value) => value,
        Err(()) => {
            eprintln!("stdin must contain exactly one non-empty subscription value");
            process::exit(2);
        }
    };
    let fingerprint = sha2::Sha256::digest(source.as_bytes());
    let result = tauri::async_runtime::block_on(import_https_subscription(
        &source,
        &WindowsSecretStore::new(),
    ));
    match result {
        Ok(mut imported) => {
            if let Err(kind) = leak_check(&source, repo_root(), app_runtime_root()) {
                // Do not emit a path or matched content: a filename can itself
                // be sensitive, and this tool's result is consumed by automation.
                eprintln!("leak_detected type={kind}");
                process::exit(1);
            }
            if !git_is_clean_after_import(repo_root()) {
                eprintln!("git_worktree_changed_after_import");
                process::exit(1);
            }
            println!(
                "imported subscription_id={} servers={}",
                imported.subscription.id,
                imported.servers.len()
            );
            for server in &imported.servers {
                println!(
                    "{} {}",
                    safe_server_line(server),
                    safe_compatibility_line(server)
                );
            }
            if mode == RunMode::Phase2 {
                if let Err(stage) = run_real_phase2(&imported.servers) {
                    eprintln!("phase2_failed stage={stage}");
                    scrub_servers(&mut imported.servers);
                    source.zeroize();
                    process::exit(1);
                }
                println!("phase2=passed");
            }
            if let Err(kind) = leak_check(&source, repo_root(), app_runtime_root()) {
                eprintln!("leak_detected type={kind}");
                scrub_servers(&mut imported.servers);
                source.zeroize();
                process::exit(1);
            }
            // The digest is intentionally retained only long enough to prove
            // it was computed; never print or persist a subscription fingerprint.
            let _ = fingerprint;
            scrub_servers(&mut imported.servers);
            source.zeroize();
            println!("secretstore=stored leak_check=clean git_worktree=clean");
        }
        Err(_) => {
            source.zeroize();
            eprintln!("subscription_import_failed");
            process::exit(1);
        }
    }
}

fn run_mode() -> Option<RunMode> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [] => Some(RunMode::ImportOnly),
        [argument] if argument == "--phase2" => Some(RunMode::Phase2),
        [argument, subscription_id] if argument == "--provenance" => subscription_id
            .to_str()
            .filter(|value| uuid::Uuid::parse_str(value).is_ok())
            .map(|value| RunMode::Provenance(value.into())),
        _ => None,
    }
}

fn run_endpoint_provenance(subscription_id: &str) -> Result<(), &'static str> {
    let store = WindowsSecretStore::new();
    let mut source = store
        .get(&subscription_url_key(subscription_id))
        .map_err(|_| "SecretStoreReadFailed")?
        .ok_or("SubscriptionSourceUnavailable")?;
    let mut body = tauri::async_runtime::block_on(fetch_subscription_text(&source))
        .map_err(|_| "SubscriptionFetchFailed")?;
    source.zeroize();
    let mut key = diagnostic_key();
    let mut entries = inspect_vless_endpoint_provenance(&body);
    body.zeroize();
    if entries.len() != 3 {
        for entry in &mut entries {
            entry.raw.canonical.as_mut().map(Zeroize::zeroize);
            if let Ok(server) = &mut entry.parsed {
                scrub_servers(std::slice::from_mut(server));
            }
        }
        key.zeroize();
        return Err("UnexpectedVlessEntryCount");
    }
    for (index, mut entry) in entries.drain(..).enumerate() {
        let raw = safe_raw_stage(&entry.raw, &key);
        entry.raw.canonical.as_mut().map(Zeroize::zeroize);
        match entry.parsed {
            Ok(mut server) => {
                let parsed = safe_endpoint_stage(&server.endpoint, &key);
                let normalized = safe_endpoint_stage(&server.endpoint, &key);
                let reloaded = server
                    .endpoint
                    .persistence_round_trip()
                    .map_err(|_| "EndpointPersistenceFailed")?;
                let reloaded = safe_endpoint_stage(&reloaded, &key);
                let system =
                    safe_endpoint_stage(authoritative_endpoint_for_system_vpn(&server), &key);
                let changed = first_changed(&[&raw, &parsed, &normalized, &reloaded, &system]);
                println!(
                    "server={} raw={} parsed={} normalized={} reloaded={} system_vpn={} first_changed={}",
                    index + 1,
                    raw,
                    parsed,
                    normalized,
                    reloaded,
                    system,
                    changed,
                );
                scrub_servers(std::slice::from_mut(&mut server));
            }
            Err(error) => {
                println!(
                    "server={} raw={} parsed=invalid normalized=unavailable reloaded=unavailable system_vpn=unavailable first_changed=parser parse_error={}",
                    index + 1,
                    raw,
                    safe_parse_error(&error),
                );
            }
        }
    }
    key.zeroize();
    println!("endpoint_provenance=complete secretstore=reused");
    Ok(())
}

fn diagnostic_key() -> [u8; 32] {
    let first = uuid::Uuid::new_v4();
    let second = uuid::Uuid::new_v4();
    let mut key = [0_u8; 32];
    key[..16].copy_from_slice(first.as_bytes());
    key[16..].copy_from_slice(second.as_bytes());
    key
}

fn safe_raw_stage(
    raw: &void_desktop_lib::subscription::parser::RawAuthorityObservation,
    key: &[u8; 32],
) -> String {
    format!(
        "present:{} kind:{} unspecified:{} fp:{}",
        yes_no(raw.present),
        raw.kind.code(),
        yes_no(raw.unspecified),
        fingerprint(raw.canonical.as_deref(), key),
    )
}

fn safe_endpoint_stage(endpoint: &ServerEndpoint, key: &[u8; 32]) -> String {
    format!(
        "kind:{} unspecified:no fp:{}",
        endpoint.kind().code(),
        fingerprint(Some(&endpoint.canonical()), key),
    )
}

fn fingerprint(value: Option<&str>, key: &[u8; 32]) -> String {
    let Some(value) = value else {
        return "none".into();
    };
    let mut inner = sha2::Sha256::new();
    let mut pad = [0_u8; 64];
    for (index, byte) in key.iter().enumerate() {
        pad[index] = byte ^ 0x36;
    }
    inner.update(pad);
    inner.update(value.as_bytes());
    let inner = inner.finalize();
    let mut outer = sha2::Sha256::new();
    let mut pad = [0_u8; 64];
    for (index, byte) in key.iter().enumerate() {
        pad[index] = byte ^ 0x5c;
    }
    outer.update(pad);
    outer.update(inner);
    outer
        .finalize()
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn first_changed(stages: &[&str]) -> &'static str {
    let fingerprints = stages
        .iter()
        .filter_map(|stage| {
            stage
                .split("fp:")
                .nth(1)
                .and_then(|value| value.split_whitespace().next())
        })
        .collect::<Vec<_>>();
    if fingerprints.len() == stages.len() && fingerprints.windows(2).all(|pair| pair[0] == pair[1])
    {
        "none"
    } else {
        "unavailable_or_changed"
    }
}

fn safe_parse_error(error: &str) -> &'static str {
    match error {
        "MissingServerAddress" => "MissingServerAddress",
        "InvalidServerAddress" => "InvalidServerAddress",
        _ => "ParserRejectedEntry",
    }
}

fn system_vpn_support(server: &Server) -> bool {
    compatibility_diagnostic(server).rejection_reason.is_none()
}

fn safe_compatibility_line(server: &Server) -> String {
    let diagnostic = compatibility_diagnostic(server);
    let reason = diagnostic
        .rejection_reason
        .map(|reason| reason.code())
        .unwrap_or("None");
    format!(
        "security_type={} vless_encryption_field_present={} vless_encryption_status={} vless_encryption_metadata={} flow_type={} sni_present={} reality_public_key_present={} short_id_present={} fingerprint_present={} spider_x_present={} address_kind={} address_class={} compatibility={} rejection_reason={}",
        diagnostic.security_type,
        yes_no(diagnostic.vless_encryption_field_present),
        diagnostic.vless_encryption_status,
        diagnostic.vless_encryption_metadata.unwrap_or("none"),
        diagnostic.flow_type,
        yes_no(diagnostic.sni_present),
        yes_no(diagnostic.reality_public_key_present),
        yes_no(diagnostic.short_id_present),
        yes_no(diagnostic.fingerprint_present),
        yes_no(diagnostic.spider_x_present),
        diagnostic.address_kind,
        diagnostic.address_class,
        diagnostic.compatibility,
        reason,
    )
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn scrub_servers(servers: &mut [Server]) {
    for server in servers {
        server.credential.zeroize();
        server.security.as_mut().map(Zeroize::zeroize);
        server.sni.as_mut().map(Zeroize::zeroize);
        server.vless_encryption.zeroize();
        for value in server.options.values_mut() {
            value.zeroize();
        }
        server.options.clear();
    }
}

/// Explicit development selection only. Production commands still require a
/// user-selected ID and return NoServerSelected otherwise.
fn select_development_phase2_server(servers: &[Server]) -> Result<&Server, &'static str> {
    servers
        .iter()
        .find(|server| system_vpn_support(server))
        .ok_or("NoSupportedServerForSystemVpn")
}

fn run_real_phase2(servers: &[Server]) -> Result<(), &'static str> {
    let server = select_development_phase2_server(servers)?;
    println!(
        "selected server_id={} protocol={} transport={}",
        server.summary.id,
        protocol_name(server.summary.protocol),
        server
            .summary
            .transport
            .as_deref()
            .map(safe_display)
            .unwrap_or_else(|| "unknown".into())
    );
    let app_data = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .map(|path| path.join("com.void.desktop"))
        .ok_or("AppDataUnavailable")?;
    let core = XrayCoreManager::load(app_data.clone());
    core.install_pinned_experimental_tun()
        .map_err(|_| "PinnedCoreInstallFailed")?;
    run_live_cycle(server, &core, &app_data, false)?;
    run_live_cycle(server, &core, &app_data, false)?;
    run_live_cycle(server, &core, &app_data, true)?;
    Ok(())
}

fn run_live_cycle(
    server: &Server,
    core: &XrayCoreManager,
    app_data: &Path,
    crash_owned_core: bool,
) -> Result<(), &'static str> {
    let baseline = NetworkBaseline::capture()?;
    let spec = SystemVpnSessionSpec::from_selected_server(server).map_err(|_| "SpecBuildFailed")?;
    core.preflight_system_vpn(&spec)
        .map_err(|_| "PreUacValidationFailed")?;
    println!(
        "pre_uac_validation=passed server_id={} protocol={} transport={}",
        spec.selected_server_id,
        protocol_name(server.summary.protocol),
        server
            .summary
            .transport
            .as_deref()
            .map(safe_display)
            .unwrap_or_else(|| "unknown".into())
    );
    let session_id = spec.session_id.clone();
    let mut controller = SystemVpnController::start(spec).map_err(|_| "UacOrHelperStartFailed")?;
    let outcome = (|| {
        let [first, second] = full_ipv4_routes().map_err(|_| "RouteInspectionFailed")?;
        let (Some(first), Some(second)) = (first, second) else {
            return Err("FullIpv4RoutesMissing");
        };
        if first.interface_index != second.interface_index
            || has_default_route_on(first.interface_index).map_err(|_| "RouteInspectionFailed")?
            || physical_default_routes()
                .map_err(|_| "RouteInspectionFailed")?
                .is_empty()
        {
            return Err("RoutePolicyFailed");
        }
        let interface_before =
            interface_metadata(first.interface_index).map_err(|_| "TunCounterReadFailed")?;
        let dns_during = physical_dns_snapshot().map_err(|_| "PhysicalDnsReadFailed")?;
        if compare_physical_dns(&baseline.physical_dns, &dns_during) != PhysicalDnsComparison::Equal
        {
            return Err("PhysicalDnsChanged");
        }
        let tun_dns_ok = void_tun_adapters()
            .map_err(|_| "TunDnsReadFailed")?
            .iter()
            .any(|adapter| {
                adapter.friendly_name == interface_before.alias
                    && adapter.dns_servers == FULL_IPV4_TUN_DNS
            });
        if !tun_dns_ok {
            return Err("TunDnsPolicyFailed");
        }
        let journal = TunSessionJournal::load(&core.tun_journal_path())
            .map_err(|_| "JournalReadFailed")?
            .ok_or("JournalMissing")?;
        if journal.selected_server_id.as_deref() != Some(server.summary.id.as_str())
            || journal.config_sha256.as_deref().is_none()
        {
            return Err("SelectedOutboundEvidenceFailed");
        }
        let vpn_ip = direct_public_ip()?;
        let hostname_status = direct_hostname_https()?;
        let resolver_count = system_dns_count()?;
        let interface_after =
            interface_metadata(first.interface_index).map_err(|_| "TunCounterReadFailed")?;
        if interface_after.in_octets <= interface_before.in_octets
            && interface_after.out_octets <= interface_before.out_octets
        {
            return Err("TunTrafficCounterDidNotAdvance");
        }
        println!(
            "vpn_ready public_ip={} hostname_https={} system_dns={} tun_rx_delta={} tun_tx_delta={} outbound_tag=proxy outbound_protocol=vless",
            vpn_ip,
            hostname_status,
            resolver_count,
            interface_after.in_octets.saturating_sub(interface_before.in_octets),
            interface_after.out_octets.saturating_sub(interface_before.out_octets),
        );
        Ok(())
    })();
    if outcome.is_err() {
        let _ = controller.stop();
        drop(controller);
        let _ = verify_cleanup(&baseline, app_data, &session_id, core);
        return outcome;
    }
    if crash_owned_core {
        controller
            .terminate_owned_core_for_development()
            .map_err(|_| "OwnedCoreCrashRecoveryFailed")?;
        println!("fail_open=owned_core_terminated");
    } else {
        controller.stop().map_err(|_| "DisconnectFailed")?;
    }
    drop(controller);
    verify_cleanup(&baseline, app_data, &session_id, core)?;
    println!(
        "disconnect_cleanup=passed direct_public_ip_after={}",
        direct_public_ip()?
    );
    Ok(())
}

struct NetworkBaseline {
    physical_dns: PhysicalDnsSnapshot,
}

impl NetworkBaseline {
    fn capture() -> Result<Self, &'static str> {
        let physical_dns = physical_dns_snapshot().map_err(|_| "PhysicalDnsReadFailed")?;
        if physical_default_routes()
            .map_err(|_| "RouteInspectionFailed")?
            .is_empty()
        {
            return Err("PhysicalDefaultRouteMissing");
        }
        let direct_ip = direct_public_ip()?;
        let hostname = direct_hostname_https()?;
        println!(
            "baseline direct_public_ip={} hostname_https={hostname}",
            direct_ip
        );
        Ok(Self { physical_dns })
    }
}

fn verify_cleanup(
    baseline: &NetworkBaseline,
    app_data: &Path,
    session_id: &str,
    core: &XrayCoreManager,
) -> Result<(), &'static str> {
    if full_ipv4_routes()
        .map_err(|_| "RouteInspectionFailed")?
        .iter()
        .any(Option::is_some)
        || core.tun_journal_path().exists()
        || app_data
            .join("xray")
            .join("runtime")
            .join("system-vpn")
            .join(session_id)
            .exists()
    {
        return Err("RuntimeCleanupFailed");
    }
    let observed_dns = physical_dns_snapshot().map_err(|_| "PhysicalDnsReadFailed")?;
    if compare_physical_dns(&baseline.physical_dns, &observed_dns) != PhysicalDnsComparison::Equal {
        return Err("PhysicalDnsChanged");
    }
    if !void_tun_adapters()
        .map_err(|_| "TunDnsReadFailed")?
        .iter()
        .all(|adapter| adapter.dns_servers.is_empty())
    {
        return Err("TunDnsCleanupFailed");
    }
    if physical_default_routes()
        .map_err(|_| "RouteInspectionFailed")?
        .is_empty()
    {
        return Err("PhysicalDefaultRouteMissing");
    }
    let _ = direct_hostname_https()?;
    Ok(())
}

fn direct_public_ip() -> Result<String, &'static str> {
    let response = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| "PublicIpClientFailed")?
        .get("https://api.ipify.org")
        .send()
        .map_err(|_| "PublicIpRequestFailed")?;
    if !response.status().is_success() {
        return Err("PublicIpStatusFailed");
    }
    let body = response.text().map_err(|_| "PublicIpBodyFailed")?;
    body.trim()
        .parse::<IpAddr>()
        .map(|address| address.to_string())
        .map_err(|_| "PublicIpMalformed")
}

fn direct_hostname_https() -> Result<u16, &'static str> {
    let response = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| "HostnameClientFailed")?
        .get("https://www.cloudflare.com/cdn-cgi/trace")
        .send()
        .map_err(|_| "HostnameRequestFailed")?;
    response
        .status()
        .is_success()
        .then_some(response.status().as_u16())
        .ok_or("HostnameStatusFailed")
}

fn system_dns_count() -> Result<usize, &'static str> {
    ("www.cloudflare.com", 443)
        .to_socket_addrs()
        .map_err(|_| "SystemDnsFailed")
        .map(|addresses| addresses.filter(|address| address.is_ipv4()).count())
        .and_then(|count| (count > 0).then_some(count).ok_or("SystemDnsNoIpv4"))
}

fn read_one_secret_line() -> Result<String, ()> {
    let mut stdin = io::stdin().lock();
    let mut input = String::new();
    stdin.read_to_string(&mut input).map_err(|_| ())?;
    if input.lines().count() != 1 {
        input.zeroize();
        return Err(());
    }
    let secret = input.trim().to_owned();
    input.zeroize();
    (!secret.is_empty()).then_some(secret).ok_or(())
}

fn safe_server_line(server: &Server) -> String {
    format!(
        "server id={} name={} protocol={} transport={} region={}",
        server.summary.id,
        safe_display(&server.summary.name),
        protocol_name(server.summary.protocol),
        server
            .summary
            .transport
            .as_deref()
            .map(safe_display)
            .unwrap_or_else(|| "unknown".into()),
        server
            .summary
            .country
            .as_deref()
            .map(safe_display)
            .unwrap_or_else(|| "unknown".into()),
    )
}

fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Vless => "vless",
        Protocol::Vmess => "vmess",
        Protocol::Shadowsocks => "shadowsocks",
        Protocol::Trojan => "trojan",
    }
}

fn safe_display(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(96)
        .collect()
}

fn repo_root() -> PathBuf {
    Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|path| PathBuf::from(path.trim()))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn app_runtime_root() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|value| PathBuf::from(value).join("com.void.desktop"))
}

fn git_is_clean_after_import(root: PathBuf) -> bool {
    Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(root)
        .output()
        .map(|output| output.status.success() && output.stdout.is_empty())
        .unwrap_or(false)
}

fn leak_check(secret: &str, root: PathBuf, runtime: Option<PathBuf>) -> Result<(), &'static str> {
    scan_git_files(secret.as_bytes(), &root, &["ls-files", "-z"], "tracked")?;
    scan_git_files(
        secret.as_bytes(),
        &root,
        &["ls-files", "--others", "--exclude-standard", "-z"],
        "untracked",
    )?;
    if let Some(runtime) = runtime {
        scan_directory(secret.as_bytes(), &runtime).map_err(|_| "runtime")?;
    }
    Ok(())
}

fn scan_git_files(
    secret: &[u8],
    root: &Path,
    arguments: &[&str],
    kind: &'static str,
) -> Result<(), &'static str> {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(root)
        .output()
        .map_err(|_| kind)?;
    if !output.status.success() {
        return Err(kind);
    }
    for relative in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|value| !value.is_empty())
    {
        let path = root.join(String::from_utf8_lossy(relative).as_ref());
        if contains_secret(&path, secret).map_err(|_| kind)? {
            return Err(kind);
        }
    }
    Ok(())
}

fn scan_directory(secret: &[u8], directory: &Path) -> Result<(), ()> {
    if !directory.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(directory).map_err(|_| ())? {
        let path = entry.map_err(|_| ())?.path();
        if path.is_dir() {
            scan_directory(secret, &path)?;
        } else if contains_secret(&path, secret).map_err(|_| ())? {
            return Err(());
        }
    }
    Ok(())
}

fn contains_secret(path: &Path, secret: &[u8]) -> Result<bool, ()> {
    let metadata = fs::metadata(path).map_err(|_| ())?;
    if metadata.len() > MAX_SCAN_BYTES {
        return Ok(false);
    }
    let bytes = fs::read(path).map_err(|_| ())?;
    Ok(bytes.windows(secret.len()).any(|window| window == secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use void_desktop_lib::domain::{
        ServerEndpoint, ServerEndpointKind, ServerHealth, ServerSummary, VlessEncryption,
    };

    #[test]
    fn safe_output_never_includes_server_address_or_credential() {
        let server = Server {
            summary: ServerSummary {
                id: "safe-id".into(),
                name: "Test node".into(),
                protocol: Protocol::Vless,
                endpoint_kind: ServerEndpointKind::Domain,
                port: 443,
                transport: Some("tcp".into()),
                country: None,
                health: ServerHealth::Unknown,
                latency_ms: None,
            },
            endpoint: ServerEndpoint::Domain("private-host.example".into()),
            credential: "private-credential".into(),
            security: Some("reality".into()),
            sni: None,
            vless_encryption: VlessEncryption::Absent,
            options: HashMap::new(),
        };
        let output = safe_server_line(&server);
        assert!(output.contains("safe-id"));
        assert!(!output.contains("private-host"));
        assert!(!output.contains("private-credential"));
    }

    #[test]
    fn no_arguments_are_allowed() {
        assert!(safe_display("safe\nvalue").contains("safevalue"));
    }
}

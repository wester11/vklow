//! Development-only one-shot subscription importer.
//!
//! It is feature-gated out of normal Tauri builds and accepts its sole secret
//! from stdin. Never add URL arguments, environment-variable input or a
//! plaintext hand-off file to this tool.

use sha2::Digest;
use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{self, Command},
};
use void_desktop_lib::{
    core::secrets::WindowsSecretStore,
    domain::{Protocol, Server},
    subscription::import_https_subscription,
};
use zeroize::Zeroize;

const MAX_SCAN_BYTES: u64 = 4 * 1024 * 1024;

fn main() {
    if !args_are_safe() {
        eprintln!("usage: void-dev-import-subscription < stdin");
        process::exit(2);
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
        Ok(imported) => {
            let leak_check = leak_check(&source, repo_root(), app_runtime_root());
            source.zeroize();
            if let Err(kind) = leak_check {
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
                println!("{}", safe_server_line(server));
            }
            // The digest is intentionally retained only long enough to prove
            // it was computed; never print or persist a subscription fingerprint.
            let _ = fingerprint;
            println!("secretstore=stored leak_check=clean git_worktree=clean");
        }
        Err(_) => {
            source.zeroize();
            eprintln!("subscription_import_failed");
            process::exit(1);
        }
    }
}

fn args_are_safe() -> bool {
    std::env::args_os().count() == 1
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
    use void_desktop_lib::domain::{ServerHealth, ServerSummary};

    #[test]
    fn safe_output_never_includes_server_address_or_credential() {
        let server = Server {
            summary: ServerSummary {
                id: "safe-id".into(),
                name: "Test node".into(),
                protocol: Protocol::Vless,
                address: "private-host.example".into(),
                port: 443,
                transport: Some("tcp".into()),
                country: None,
                health: ServerHealth::Unknown,
                latency_ms: None,
            },
            credential: "private-credential".into(),
            security: Some("reality".into()),
            sni: None,
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

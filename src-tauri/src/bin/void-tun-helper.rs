use std::{
    env, fs,
    process::{self, Command, Stdio},
    thread,
    time::Duration,
};
use void_desktop_lib::core::{
    tun::{TunSessionJournal, TunSessionPhase},
    tun_pipe::TunPipeConnection,
    tun_protocol::{TunOperation, TunRequest, TunResponse},
    xray::{config::scoped_tun_smoke_config, manager::XrayCoreManager},
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
    if request.operation != TunOperation::StartScopedTunSession {
        let response = TunResponse::rejected(
            bootstrap.session_id.clone(),
            bootstrap.controller_pid,
            helper_pid,
            "First helper request must start scoped TUN",
        );
        pipe.write_frame(
            &serde_json::to_vec(&response).map_err(|_| "Unable to encode helper response")?,
        )?;
        return Err("Rejected TUN helper operation".into());
    }
    let mut session = start_tun(&bootstrap)?;
    let response = TunResponse::accepted(
        bootstrap.session_id.clone(),
        bootstrap.controller_pid,
        helper_pid,
        "scoped_tun_running",
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
        || stop.operation != TunOperation::StopTunSession
    {
        let _ = session.stop();
        return Err("Invalid TUN stop request".into());
    }
    session.stop()?;
    let response = TunResponse::accepted(
        bootstrap.session_id,
        bootstrap.controller_pid,
        helper_pid,
        "stopped",
    );
    pipe.write_frame(
        &serde_json::to_vec(&response).map_err(|_| "Unable to encode helper response")?,
    )
}

struct OwnedTunSession {
    child: std::process::Child,
    config: std::path::PathBuf,
    journal_path: std::path::PathBuf,
    journal: TunSessionJournal,
}

impl OwnedTunSession {
    fn stop(&mut self) -> Result<(), String> {
        self.journal.transition(TunSessionPhase::Stopping);
        self.journal.save_atomic(&self.journal_path)?;
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

fn start_tun(bootstrap: &Bootstrap) -> Result<OwnedTunSession, String> {
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
    );
    journal.transition(TunSessionPhase::StartingTun);
    let journal_path = core.tun_journal_path();
    journal.save_atomic(&journal_path)?;
    let config = core
        .runtime_directory()
        .join(format!("tun-{}.json", bootstrap.session_id));
    fs::write(
        &config,
        serde_json::to_vec(&scoped_tun_smoke_config(&adapter_name)?)
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
    Ok(OwnedTunSession {
        child,
        config,
        journal_path,
        journal,
    })
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

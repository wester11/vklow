use std::{env, process};
use void_desktop_lib::core::{
    tun_pipe::TunPipeConnection,
    tun_protocol::{TunRequest, TunResponse},
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
    let response = match request.operation {
        void_desktop_lib::core::tun_protocol::TunOperation::StartScopedTunSession => {
            TunResponse::accepted(
                bootstrap.session_id.clone(),
                bootstrap.controller_pid,
                helper_pid,
                "helper_ready",
            )
        }
        _ => TunResponse::rejected(
            bootstrap.session_id.clone(),
            bootstrap.controller_pid,
            helper_pid,
            "First helper request must start scoped TUN",
        ),
    };
    pipe.write_frame(
        &serde_json::to_vec(&response).map_err(|_| "Unable to encode helper response")?,
    )?;
    if !response.ok {
        return Err("Rejected TUN helper operation".into());
    }
    Ok(())
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

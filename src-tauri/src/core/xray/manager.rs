use crate::{
    core::xray::{
        archive::extract_verified_zip,
        config::{vless_reality_tcp, VlessRealityOutbound},
        integrity::{parse_dgst_for_asset, verify_sha256},
        paths::XrayPaths,
        redaction::redact,
        state::InstalledState,
        version::XrayVersion,
    },
    domain::{ConnectionState, Protocol, Server},
};
use serde::Serialize;
use std::{
    collections::VecDeque,
    fs,
    io::{BufRead, BufReader},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

const TAIL_LINES: usize = 160;
const TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreInstallState {
    NotInstalled,
    Ready,
    Failed,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreStatus {
    pub install_state: CoreInstallState,
    pub active_version: Option<String>,
    pub previous_version: Option<String>,
    pub last_error: Option<String>,
}
struct ManagedProcess {
    child: Arc<Mutex<Child>>,
    config: PathBuf,
    tail: Arc<Mutex<VecDeque<String>>>,
}
struct Runtime {
    connection: ConnectionState,
    process: Option<ManagedProcess>,
    generation: u64,
}
impl Default for Runtime {
    fn default() -> Self {
        Self {
            connection: ConnectionState::Idle,
            process: None,
            generation: 0,
        }
    }
}
pub struct XrayCoreManager {
    paths: XrayPaths,
    state: Mutex<InstalledState>,
    runtime: Arc<Mutex<Runtime>>,
    last_error: Arc<Mutex<Option<String>>>,
}

impl XrayCoreManager {
    pub fn load(data: PathBuf) -> Self {
        let paths = XrayPaths::new(data);
        let mut error = paths.ensure().err();
        let state = InstalledState::load(&paths.state()).unwrap_or_else(|reason| {
            error = Some(reason);
            InstalledState {
                schema_version: 1,
                ..Default::default()
            }
        });
        let _ = Self::cleanup_stale_runtime(&paths);
        Self {
            paths,
            state: Mutex::new(state),
            runtime: Arc::new(Mutex::new(Runtime::default())),
            last_error: Arc::new(Mutex::new(error)),
        }
    }
    pub fn status(&self) -> CoreStatus {
        let state = self.state.lock().expect("Xray state mutex poisoned");
        let valid = state
            .active_version
            .as_ref()
            .is_some_and(|v| self.paths.versions().join(v).join("xray.exe").is_file());
        CoreStatus {
            install_state: if valid {
                CoreInstallState::Ready
            } else if self
                .last_error
                .lock()
                .expect("Xray error mutex poisoned")
                .is_some()
            {
                CoreInstallState::Failed
            } else {
                CoreInstallState::NotInstalled
            },
            active_version: valid.then(|| state.active_version.clone()).flatten(),
            previous_version: state.previous_version.clone(),
            last_error: self
                .last_error
                .lock()
                .expect("Xray error mutex poisoned")
                .clone(),
        }
    }
    pub fn connection_status(&self) -> Result<ConnectionState, String> {
        Ok(self
            .runtime
            .lock()
            .map_err(|_| "Внутренняя ошибка Xray runtime")?
            .connection
            .clone())
    }
    pub fn install_verified_core(
        &self,
        artifact: &Path,
        dgst: &str,
        version: XrayVersion,
    ) -> Result<CoreStatus, String> {
        let expected = parse_dgst_for_asset(dgst, "Xray-windows-64.zip")?;
        let bytes = fs::read(artifact).map_err(|_| "Не удалось прочитать Xray artifact")?;
        verify_sha256(&bytes, &expected)?;
        self.paths.ensure()?;
        let staging = self
            .paths
            .staging()
            .join(format!("install-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&staging).map_err(|_| "Не удалось создать Xray staging directory")?;
        let result = (|| {
            let binary = extract_verified_zip(artifact, &staging)?;
            if Self::run_version(&binary)? != version {
                return Err("Версия Xray в archive не совпадает с ожидаемой".into());
            }
            let target = self.paths.version_dir(&version);
            if target.exists() {
                fs::remove_dir_all(&staging)
                    .map_err(|_| "Не удалось очистить Xray staging directory")?;
            } else {
                fs::rename(&staging, &target).map_err(|_| "Не удалось атомарно установить Xray")?;
            }
            let mut state = self
                .state
                .lock()
                .map_err(|_| "Внутренняя ошибка Xray state")?;
            state.activate(version);
            state.save_atomic(&self.paths.state())
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&staging);
        }
        result?;
        Ok(self.status())
    }
    pub fn connect(&self, server: &Server) -> Result<ConnectionState, String> {
        let gen = {
            let mut runtime = self
                .runtime
                .lock()
                .map_err(|_| "Внутренняя ошибка Xray runtime")?;
            if !matches!(
                runtime.connection,
                ConnectionState::Idle
                    | ConnectionState::Error { .. }
                    | ConnectionState::Crashed { .. }
            ) {
                return Err("Подключение уже выполняется или proxy уже запущен".into());
            }
            runtime.generation += 1;
            runtime.connection = ConnectionState::Preparing;
            runtime.generation
        };
        let result = self.start(server, gen);
        if let Err(error) = &result {
            self.fail(gen, error);
        }
        result
    }
    fn start(&self, server: &Server, gen: u64) -> Result<ConnectionState, String> {
        let binary = self.active_binary()?;
        let port = Self::allocate_port()?;
        let config = self.config_for(server, port)?;
        let path = self.paths.runtime().join(format!("xray-{gen}.json"));
        fs::write(
            &path,
            serde_json::to_vec(&config).map_err(|_| "Не удалось сериализовать Xray config")?,
        )
        .map_err(|_| "Не удалось записать runtime config")?;
        self.set_state(gen, ConnectionState::ValidatingConfig)?;
        let secrets = Self::secrets(server);
        Self::validate(&binary, &path, &secrets)?;
        self.set_state(gen, ConnectionState::StartingCore)?;
        let mut child = Command::new(&binary)
            .args(["run", "-c"])
            .arg(&path)
            .current_dir(self.paths.runtime())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "Не удалось запустить установленный Xray")?;
        let tail = Arc::new(Mutex::new(VecDeque::new()));
        Self::drain(child.stdout.take(), Arc::clone(&tail), secrets.clone());
        Self::drain(child.stderr.take(), Arc::clone(&tail), secrets);
        {
            let mut runtime = self
                .runtime
                .lock()
                .map_err(|_| "Внутренняя ошибка Xray runtime")?;
            if runtime.generation != gen {
                return Err("Подключение было отменено".into());
            }
            runtime.process = Some(ManagedProcess {
                child: Arc::new(Mutex::new(child)),
                config: path,
                tail,
            });
            runtime.connection = ConnectionState::WaitingForProxy;
        }
        self.wait_ready(gen, port)?;
        self.set_state(gen, ConnectionState::ProxyReady { socks_port: port })?;
        self.watch(gen);
        self.connection_status()
    }
    pub fn disconnect(&self) -> Result<ConnectionState, String> {
        let process = {
            let mut runtime = self
                .runtime
                .lock()
                .map_err(|_| "Внутренняя ошибка Xray runtime")?;
            runtime.connection = ConnectionState::Stopping;
            runtime.process.take()
        };
        if let Some(process) = process {
            let mut child = process
                .child
                .lock()
                .map_err(|_| "Внутренняя ошибка owned Xray process")?;
            if child
                .try_wait()
                .map_err(|_| "Не удалось проверить Xray process")?
                .is_none()
            {
                child
                    .kill()
                    .map_err(|_| "Не удалось остановить owned Xray process")?;
                child
                    .wait()
                    .map_err(|_| "Не удалось дождаться Xray process")?;
            }
            let _ = fs::remove_file(process.config);
        }
        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| "Внутренняя ошибка Xray runtime")?;
        runtime.connection = ConnectionState::Idle;
        Ok(ConnectionState::Idle)
    }
    fn active_binary(&self) -> Result<PathBuf, String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "Внутренняя ошибка Xray state")?;
        let version: XrayVersion = state
            .active_version
            .as_deref()
            .ok_or("Xray не установлен")?
            .parse()?;
        let binary = self.paths.binary(&version);
        binary
            .is_file()
            .then_some(binary)
            .ok_or_else(|| "Активный Xray binary отсутствует; требуется переустановка".into())
    }
    fn config_for(&self, s: &Server, port: u16) -> Result<serde_json::Value, String> {
        if !matches!(s.summary.protocol, Protocol::Vless)
            || s.security.as_deref() != Some("reality")
        {
            return Err("В этом этапе runtime поддерживает только VLESS Reality TCP".into());
        }
        let option = |key| s.options.get(key).cloned().unwrap_or_default();
        vless_reality_tcp(
            &VlessRealityOutbound {
                address: s.summary.address.clone(),
                port: s.summary.port,
                uuid: s.credential.clone(),
                flow: s.options.get("flow").cloned(),
                server_name: s.sni.clone().unwrap_or_else(|| option("sni")),
                fingerprint: option("fp"),
                public_key: option("pbk"),
                short_id: option("sid"),
            },
            port,
        )
    }
    fn validate(binary: &Path, config: &Path, secrets: &[String]) -> Result<(), String> {
        let mut child = Command::new(binary)
            .args(["run", "-test", "-c"])
            .arg(config)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "Не удалось запустить проверку Xray config")?;
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if child
                .try_wait()
                .map_err(|_| "Не удалось проверить Xray config")?
                .is_some()
            {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Проверка Xray config превысила timeout".into());
            }
            thread::sleep(Duration::from_millis(50));
        }
        let output = child
            .wait_with_output()
            .map_err(|_| "Не удалось получить результат проверки Xray config")?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "Xray отклонил runtime config: {}",
                redact(&String::from_utf8_lossy(&output.stderr), secrets)
                    .trim()
                    .chars()
                    .take(500)
                    .collect::<String>()
            ))
        }
    }
    fn wait_ready(&self, gen: u64, port: u16) -> Result<(), String> {
        let deadline = Instant::now() + TIMEOUT;
        let address = format!("127.0.0.1:{port}")
            .parse()
            .map_err(|_| "Некорректный loopback port")?;
        loop {
            let runtime = self
                .runtime
                .lock()
                .map_err(|_| "Внутренняя ошибка Xray runtime")?;
            if runtime.generation != gen {
                return Err("Подключение было отменено".into());
            }
            let process = runtime
                .process
                .as_ref()
                .ok_or("Xray process потерян до readiness")?;
            let exited = process
                .child
                .lock()
                .map_err(|_| "Внутренняя ошибка owned Xray process")?
                .try_wait()
                .map_err(|_| "Не удалось проверить Xray process")?;
            drop(runtime);
            if let Some(status) = exited {
                return Err(format!("Xray завершился до readiness: {status}"));
            }
            if TcpStream::connect_timeout(&address, Duration::from_millis(150)).is_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("Xray SOCKS не начал принимать loopback соединения вовремя".into());
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
    fn watch(&self, gen: u64) {
        let runtime = Arc::clone(&self.runtime);
        let errors = Arc::clone(&self.last_error);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_millis(250));
            let mut state = match runtime.lock() {
                Ok(value) => value,
                Err(_) => return,
            };
            if state.generation != gen {
                return;
            }
            let Some(process) = state.process.as_ref() else {
                return;
            };
            let exit = process
                .child
                .lock()
                .ok()
                .and_then(|mut child| child.try_wait().ok().flatten());
            if let Some(status) = exit {
                let detail = process
                    .tail
                    .lock()
                    .ok()
                    .and_then(|tail| tail.back().cloned())
                    .unwrap_or_else(|| format!("Xray завершился: {status}"));
                let _ = fs::remove_file(&process.config);
                state.process = None;
                state.connection = ConnectionState::Crashed {
                    message: detail.clone(),
                };
                if let Ok(mut error) = errors.lock() {
                    *error = Some(detail);
                }
                return;
            }
        });
    }
    fn drain(
        pipe: Option<impl std::io::Read + Send + 'static>,
        tail: Arc<Mutex<VecDeque<String>>>,
        secrets: Vec<String>,
    ) {
        if let Some(pipe) = pipe {
            thread::spawn(move || {
                for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                    if let Ok(mut tail) = tail.lock() {
                        tail.push_back(redact(&line, &secrets));
                        if tail.len() > TAIL_LINES {
                            tail.pop_front();
                        }
                    }
                }
            });
        }
    }
    fn allocate_port() -> Result<u16, String> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .map_err(|_| "Не удалось выделить loopback SOCKS port")?;
        listener
            .local_addr()
            .map(|a| a.port())
            .map_err(|_| "Не удалось определить loopback SOCKS port".into())
    }
    fn set_state(&self, gen: u64, connection: ConnectionState) -> Result<(), String> {
        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| "Внутренняя ошибка Xray runtime")?;
        if runtime.generation != gen {
            return Err("Подключение было отменено".into());
        }
        runtime.connection = connection;
        Ok(())
    }
    fn fail(&self, gen: u64, error: &str) {
        let _ = self.disconnect();
        if let Ok(mut runtime) = self.runtime.lock() {
            if runtime.generation == gen {
                runtime.connection = ConnectionState::Error {
                    message: error.into(),
                };
            }
        }
        if let Ok(mut last) = self.last_error.lock() {
            *last = Some(error.into());
        }
    }
    fn secrets(s: &Server) -> Vec<String> {
        let mut values = vec![s.credential.clone()];
        values.extend(s.options.values().cloned());
        values
    }
    fn run_version(binary: &Path) -> Result<XrayVersion, String> {
        let output = Command::new(binary)
            .arg("version")
            .stdin(Stdio::null())
            .output()
            .map_err(|_| "Не удалось проверить Xray version")?;
        String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .find_map(|word| word.parse().ok())
            .ok_or_else(|| "Xray version не распознана".into())
    }
    fn cleanup_stale_runtime(paths: &XrayPaths) -> Result<(), String> {
        for entry in
            fs::read_dir(paths.runtime()).map_err(|_| "Не удалось прочитать Xray runtime")?
        {
            let path = entry
                .map_err(|_| "Не удалось прочитать Xray runtime")?
                .path();
            if path.extension().is_some_and(|ext| ext == "json") {
                fs::remove_file(path).map_err(|_| "Не удалось очистить stale runtime config")?;
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn new_manager_reports_not_installed() {
        let root = std::env::temp_dir().join(format!("void-core-{}", uuid::Uuid::new_v4()));
        let manager = XrayCoreManager::load(root);
        assert!(matches!(
            manager.status().install_state,
            CoreInstallState::NotInstalled
        ));
    }
}

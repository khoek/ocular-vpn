use std::fs::{self, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use indicatif::{ProgressBar, ProgressStyle};
use openconnect_core::config::{ConfigBuilder, EntrypointBuilder, LogLevel as CoreLogLevel};
use openconnect_core::events::EventHandlers;
use openconnect_core::protocols::get_anyconnect_protocol;
use openconnect_core::result::OpenconnectError;
use openconnect_core::{Connectable, Status, VpnClient};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
#[cfg(not(target_os = "windows"))]
use which::which;

use crate::anyconnect::AuthComplete;
use crate::cli::LogLevel;
use crate::error::AppError;
use crate::shell;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OpenConnectResult {
    pub exit_code: i32,
    pub auth_failed: bool,
    pub expires_at_epoch: Option<i64>,
    pub expires_at_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PrivilegedConnectPayload {
    host_url: String,
    session_token: String,
    server_cert_hash: String,
    proxy: Option<String>,
    version: String,
    args: Vec<String>,
    #[serde(default)]
    interactive: bool,
    result_path: PathBuf,
}

pub fn run_openconnect(
    host_url: &str,
    auth: &AuthComplete,
    proxy: Option<&str>,
    version: &str,
    args: &[String],
    on_disconnect: Option<&str>,
    interactive: bool,
    log_level: LogLevel,
) -> Result<OpenConnectResult, AppError> {
    #[cfg(unix)]
    {
        if unsafe { libc::geteuid() } != 0 {
            return run_openconnect_via_elevated_child(
                host_url,
                auth,
                proxy,
                version,
                args,
                on_disconnect,
                interactive,
                log_level,
            );
        }
    }

    run_openconnect_local(
        host_url,
        auth,
        proxy,
        version,
        args,
        on_disconnect,
        interactive,
        log_level,
    )
}

pub fn run_privileged_payload(payload_path: &Path, log_level: LogLevel) -> Result<i32, AppError> {
    let payload = read_json_file::<PrivilegedConnectPayload>(payload_path)?.ok_or_else(|| {
        AppError::Config("privileged connection payload file was empty".to_string())
    })?;
    cleanup_temp_file(payload_path);

    let auth = AuthComplete {
        auth_id: "cached".to_string(),
        auth_message: String::new(),
        session_token: payload.session_token,
        server_cert_hash: payload.server_cert_hash,
    };

    let result = run_openconnect_local(
        &payload.host_url,
        &auth,
        payload.proxy.as_deref(),
        &payload.version,
        &payload.args,
        None,
        payload.interactive,
        log_level,
    )?;

    if let Err(err) = write_json_file(&payload.result_path, &result, 0o666) {
        tracing::warn!(
            file = %payload.result_path.display(),
            %err,
            "Failed to write privileged connect result; falling back to child exit code only"
        );
        return Ok(result.exit_code);
    }

    Ok(result.exit_code)
}

pub fn preauthorize_privileged_runner() -> Result<(), AppError> {
    #[cfg(unix)]
    {
        if unsafe { libc::geteuid() } == 0 {
            return Ok(());
        }

        let (program, prefix_args) = privileged_command_prefix()?;
        let status = match program.as_str() {
            "sudo" => {
                let mut cmd = Command::new("sudo");
                cmd.args(&prefix_args);
                cmd.arg("-v");
                cmd.status()?
            }
            "doas" => {
                let mut cmd = Command::new("doas");
                cmd.args(&prefix_args);
                cmd.arg("true");
                cmd.status()?
            }
            _ => return Ok(()),
        };

        if !status.success() {
            return Err(AppError::NeedRoot);
        }
    }

    Ok(())
}

fn run_openconnect_local(
    host_url: &str,
    auth: &AuthComplete,
    proxy: Option<&str>,
    _version: &str,
    args: &[String],
    on_disconnect: Option<&str>,
    interactive: bool,
    log_level: LogLevel,
) -> Result<OpenConnectResult, AppError> {
    if !args.is_empty() {
        tracing::warn!(
            "--openconnect-args passthrough is not supported with libopenconnect; ignoring: {:?}",
            args
        );
    }

    tracing::info!(host = host_url, "OpenConnect connecting...");

    let mut builder = ConfigBuilder::default();
    builder.loglevel(to_core_log_level(log_level));
    if let Some(proxy) = proxy {
        builder.http_proxy(proxy);
    }
    let _vpnc_capture = configure_vpnc_script(&mut builder);

    let config = builder
        .build()
        .map_err(|e| AppError::OpenConnectCore(e.to_string()))?;

    let expected_hashes = parse_expected_hashes(&auth.server_cert_hash);
    let lifecycle = Arc::new(Mutex::new(Lifecycle::new(interactive)));
    let client_slot: Arc<Mutex<Option<Arc<VpnClient>>>> = Arc::new(Mutex::new(None));

    let event_handlers = {
        let lifecycle_for_status = Arc::clone(&lifecycle);
        let expected_hashes_for_cert = expected_hashes.clone();
        let client_slot_for_cert = Arc::clone(&client_slot);
        EventHandlers::default()
            .with_handle_connection_state_change(move |status| {
                handle_status_event(&lifecycle_for_status, status)
            })
            .with_handle_peer_cert_invalid(move |actual_hash| {
                handle_invalid_cert(
                    &expected_hashes_for_cert,
                    &client_slot_for_cert,
                    actual_hash,
                )
            })
    };

    let client = VpnClient::new(config, event_handlers)
        .map_err(|e| AppError::OpenConnectCore(e.to_string()))?;
    if let Ok(mut slot) = client_slot.lock() {
        *slot = Some(Arc::clone(&client));
    }

    let mut entry = EntrypointBuilder::new();
    let entrypoint = entry
        .server(host_url)
        .protocol(get_anyconnect_protocol())
        .cookie(&auth.session_token)
        .enable_udp(true)
        .accept_insecure_cert(false)
        .build()
        .map_err(|e| AppError::OpenConnectCore(e.to_string()))?;

    if let Err(err) = client.init_connection(entrypoint) {
        let auth_failed = is_probably_auth_failure(&err);
        tracing::warn!(error = %err, "OpenConnect failed to initialize connection");
        if let Some(cmd) = on_disconnect.filter(|s| !s.trim().is_empty()) {
            handle_disconnect(cmd);
        }
        return Ok(OpenConnectResult {
            exit_code: 1,
            auth_failed,
            ..OpenConnectResult::default()
        });
    }

    if !expected_hashes.is_empty() && !cert_hash_matches_any(&client, &expected_hashes) {
        let actual_hash = client.get_peer_cert_hash();
        tracing::warn!(
            expected = ?expected_hashes,
            actual = actual_hash,
            "Connected certificate does not match pinned hash; disconnecting"
        );
        client.disconnect();
        if let Some(cmd) = on_disconnect.filter(|s| !s.trim().is_empty()) {
            handle_disconnect(cmd);
        }
        return Ok(OpenConnectResult {
            exit_code: 1,
            auth_failed: true,
            ..OpenConnectResult::default()
        });
    }

    let mut result = OpenConnectResult::default();
    if let Err(err) = client.run_loop() {
        tracing::warn!(error = %err, "OpenConnect main loop exited with error");
        result.exit_code = 1;
        result.auth_failed = is_probably_auth_failure(&err);
    }

    if let Ok(state) = lifecycle.lock()
        && result.exit_code == 0
    {
        if let Some(err) = state.last_error.as_ref() {
            result.exit_code = 1;
            result.auth_failed |= is_probably_auth_failure(err);
        } else if !state.connected_once {
            result.exit_code = 1;
        }
    }

    if let Some(cmd) = on_disconnect.filter(|s| !s.trim().is_empty()) {
        handle_disconnect(cmd);
    }

    Ok(result)
}

#[cfg(unix)]
fn run_openconnect_via_elevated_child(
    host_url: &str,
    auth: &AuthComplete,
    proxy: Option<&str>,
    version: &str,
    args: &[String],
    on_disconnect: Option<&str>,
    interactive: bool,
    log_level: LogLevel,
) -> Result<OpenConnectResult, AppError> {
    let (program, prefix_args) = privileged_command_prefix()?;
    let payload_path = create_secure_temp_file("payload", "json", 0o600)?;
    let result_path = create_secure_temp_file("result", "json", 0o666)?;

    let payload = PrivilegedConnectPayload {
        host_url: host_url.to_string(),
        session_token: auth.session_token.clone(),
        server_cert_hash: auth.server_cert_hash.clone(),
        proxy: proxy.map(|s| s.to_string()),
        version: version.to_string(),
        args: args.to_vec(),
        interactive,
        result_path: result_path.clone(),
    };
    write_json_file(&payload_path, &payload, 0o600)?;

    let exe = std::env::current_exe()?;
    tracing::info!(runner = %program, "Delegating VPN connect to privileged helper");

    let mut cmd = Command::new(&program);
    cmd.args(&prefix_args);
    cmd.arg(exe);
    cmd.arg("--internal-openconnect-payload");
    cmd.arg(&payload_path);
    cmd.arg("--log-level");
    cmd.arg(log_level_as_cli_arg(log_level));
    if let Ok(rust_log) = std::env::var("RUST_LOG") {
        cmd.env("RUST_LOG", rust_log);
    }

    let status = cmd.status()?;

    let mut result = match read_json_file::<OpenConnectResult>(&result_path) {
        Ok(Some(result)) => result,
        Ok(None) => OpenConnectResult {
            exit_code: exit_code(status),
            auth_failed: !status.success(),
            ..OpenConnectResult::default()
        },
        Err(err) => {
            tracing::warn!(
                file = %result_path.display(),
                %err,
                "Failed to read privileged connect result; using child exit code fallback"
            );
            OpenConnectResult {
                exit_code: exit_code(status),
                auth_failed: !status.success(),
                ..OpenConnectResult::default()
            }
        }
    };

    if result.exit_code == 0 && !status.success() {
        result.exit_code = exit_code(status);
    }

    cleanup_temp_file(&payload_path);
    cleanup_temp_file(&result_path);

    if let Some(cmd) = on_disconnect.filter(|s| !s.trim().is_empty()) {
        handle_disconnect(cmd);
    }

    Ok(result)
}

#[cfg(unix)]
fn privileged_command_prefix() -> Result<(String, Vec<String>), AppError> {
    if which("doas").is_ok() {
        return Ok(("doas".to_string(), Vec::new()));
    }
    if which("sudo").is_ok() {
        return Ok(("sudo".to_string(), Vec::new()));
    }
    Err(AppError::NeedRoot)
}

fn log_level_as_cli_arg(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Error => "error",
        LogLevel::Warn => "warn",
        LogLevel::Info => "info",
        LogLevel::Debug => "debug",
        LogLevel::Trace => "trace",
    }
}

fn exit_code(status: std::process::ExitStatus) -> i32 {
    match status.code() {
        Some(code) => code,
        None => {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                status.signal().map(|s| 128 + s).unwrap_or(1)
            }
            #[cfg(not(unix))]
            {
                1
            }
        }
    }
}

fn create_secure_temp_file(prefix: &str, extension: &str, mode: u32) -> Result<PathBuf, AppError> {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    for attempt in 0..256_u32 {
        let path = dir.join(format!("ocular-{prefix}-{pid}-{now}-{attempt}.{extension}"));
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            opts.mode(mode);
        }

        match opts.open(&path) {
            Ok(_) => {
                #[cfg(unix)]
                fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
                return Ok(path);
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(AppError::Io(err)),
        }
    }

    Err(AppError::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "failed to create temporary payload file",
    )))
}

fn write_json_file<T: Serialize>(path: &Path, value: &T, mode: u32) -> Result<(), AppError> {
    let raw = serde_json::to_vec(value)?;

    let mut opts = OpenOptions::new();
    opts.write(true).truncate(true);
    #[cfg(unix)]
    {
        opts.mode(mode);
    }

    let mut file = opts.open(path)?;
    file.write_all(&raw)?;
    file.flush()?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn read_json_file<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, AppError> {
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read(path)?;
    if raw.is_empty() {
        return Ok(None);
    }

    let value = serde_json::from_slice(&raw)?;
    Ok(Some(value))
}

fn cleanup_temp_file(path: &Path) {
    if let Err(err) = fs::remove_file(path)
        && err.kind() != io::ErrorKind::NotFound
    {
        tracing::debug!(file = %path.display(), %err, "Failed to remove temporary file");
    }
}

fn to_core_log_level(level: LogLevel) -> CoreLogLevel {
    match level {
        LogLevel::Error | LogLevel::Warn | LogLevel::Info => CoreLogLevel::Err,
        LogLevel::Debug => CoreLogLevel::Debug,
        LogLevel::Trace => CoreLogLevel::Trace,
    }
}

#[cfg(not(target_os = "windows"))]
#[derive(Debug)]
struct VpncScriptCapture {
    wrapper_path: PathBuf,
    log_path: PathBuf,
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
struct VpncScriptCapture;

#[cfg(not(target_os = "windows"))]
impl VpncScriptCapture {
    fn new(vpnc_script: &str) -> Result<Self, AppError> {
        let wrapper_path = create_secure_temp_file("vpnc-wrapper", "sh", 0o700)?;
        let log_path = create_secure_temp_file("vpnc-script", "log", 0o600)?;

        let log_path_str = log_path.to_string_lossy().to_string();
        let script_body = format!(
            "#!/bin/sh\nexec {} \"$@\" >>{} 2>&1\n",
            shell::sh_quote(vpnc_script),
            shell::sh_quote(&log_path_str),
        );
        fs::write(&wrapper_path, script_body)?;
        #[cfg(unix)]
        fs::set_permissions(&wrapper_path, fs::Permissions::from_mode(0o700))?;

        Ok(Self {
            wrapper_path,
            log_path,
        })
    }

    fn wrapper_path_str(&self) -> String {
        self.wrapper_path.to_string_lossy().to_string()
    }

    fn emit_debug_logs(&self) {
        if !tracing::enabled!(tracing::Level::DEBUG) {
            return;
        }

        let raw = match fs::read_to_string(&self.log_path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return,
            Err(err) => {
                tracing::debug!(
                    file = %self.log_path.display(),
                    %err,
                    "Failed to read vpnc-script log capture"
                );
                return;
            }
        };

        for line in raw.lines().map(str::trim).filter(|line| !line.is_empty()) {
            tracing::debug!(vpnc_script = %line);
        }
    }
}

#[cfg(not(target_os = "windows"))]
impl Drop for VpncScriptCapture {
    fn drop(&mut self) {
        self.emit_debug_logs();
        cleanup_temp_file(&self.wrapper_path);
        cleanup_temp_file(&self.log_path);
    }
}

#[cfg(not(target_os = "windows"))]
fn configure_vpnc_script(builder: &mut ConfigBuilder) -> Option<VpncScriptCapture> {
    if let Some(vpnc_script) = discover_vpnc_script() {
        match VpncScriptCapture::new(&vpnc_script) {
            Ok(capture) => {
                tracing::debug!(script = %vpnc_script, "Using vpnc-script wrapper");
                let wrapper = capture.wrapper_path_str();
                builder.vpncscript(&wrapper);
                Some(capture)
            }
            Err(err) => {
                tracing::warn!(
                    %err,
                    script = %vpnc_script,
                    "Failed to prepare vpnc-script wrapper; using script directly"
                );
                builder.vpncscript(&vpnc_script);
                None
            }
        }
    } else {
        tracing::warn!(
            "vpnc-script was not found in PATH/common locations; set OCULAR_VPNC_SCRIPT to avoid './vpnc-script' failures"
        );
        None
    }
}

#[cfg(target_os = "windows")]
fn configure_vpnc_script(_builder: &mut ConfigBuilder) -> Option<VpncScriptCapture> {
    None
}

#[cfg(not(target_os = "windows"))]
fn discover_vpnc_script() -> Option<String> {
    if let Ok(path) = std::env::var("OCULAR_VPNC_SCRIPT") {
        let trimmed = path.trim();
        if !trimmed.is_empty() && Path::new(trimmed).is_file() {
            return Some(trimmed.to_string());
        }
    }

    if let Ok(path) = which("vpnc-script") {
        return Some(path.to_string_lossy().to_string());
    }

    let candidates = [
        "/etc/vpnc/vpnc-script",
        "/usr/share/vpnc-scripts/vpnc-script",
        "/usr/local/etc/vpnc/vpnc-script",
        "/opt/homebrew/etc/vpnc/vpnc-script",
    ];

    candidates.iter().find_map(|candidate| {
        Path::new(candidate)
            .is_file()
            .then(|| (*candidate).to_string())
    })
}

fn handle_disconnect(command: &str) {
    tracing::info!(command, "Running command on disconnect");
    #[cfg(unix)]
    let status = Command::new("sh").arg("-c").arg(command).status();
    #[cfg(windows)]
    let status = Command::new("cmd").arg("/C").arg(command).status();
    match status {
        Ok(st) => tracing::debug!(code = ?st.code(), "Disconnect command exited"),
        Err(err) => tracing::warn!(%err, "Disconnect command failed"),
    }
}

#[derive(Debug)]
struct LiveConnectionLine {
    pb: ProgressBar,
}

impl LiveConnectionLine {
    fn new() -> Self {
        let pb = ProgressBar::new_spinner();
        let style = ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner());
        pb.set_style(style);
        pb.enable_steady_tick(Duration::from_millis(120));
        pb.set_message("connecting...".to_string());
        Self { pb }
    }

    fn set_connecting(&self) {
        self.pb.set_message("connecting...".to_string());
    }

    fn set_connected(&self) {
        self.pb.set_message("\x1b[32mconnected\x1b[0m".to_string());
    }

    fn set_reconnecting(&self) {
        self.pb
            .set_message("disconnected, reconnecting...".to_string());
    }

    fn set_disconnecting(&self) {
        self.pb.set_message("disconnecting...".to_string());
    }

    fn finish(&self) {
        self.pb.finish_and_clear();
    }
}

#[derive(Debug)]
struct Lifecycle {
    connected_once: bool,
    connecting_announced: bool,
    last_error: Option<OpenconnectError>,
    live_line: Option<LiveConnectionLine>,
}

impl Lifecycle {
    fn new(interactive: bool) -> Self {
        Self {
            connected_once: false,
            connecting_announced: false,
            last_error: None,
            live_line: interactive.then(LiveConnectionLine::new),
        }
    }

    fn finish_live_line(&self) {
        if let Some(line) = self.live_line.as_ref() {
            line.finish();
        }
    }
}

impl Drop for Lifecycle {
    fn drop(&mut self) {
        self.finish_live_line();
    }
}

fn handle_status_event(state: &Arc<Mutex<Lifecycle>>, status: Status) {
    let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
    match status {
        Status::Initialized => {}
        Status::Connecting(stage) => {
            if !state.connecting_announced {
                tracing::info!("OpenConnect connecting...");
                state.connecting_announced = true;
            }
            if let Some(line) = state.live_line.as_ref() {
                line.set_connecting();
            }
            tracing::debug!(stage = %stage, "OpenConnect stage");
        }
        Status::Connected => {
            if state.connected_once {
                tracing::info!("OpenConnect reconnected");
            } else {
                tracing::info!("OpenConnect connected!");
                state.connected_once = true;
            }
            if let Some(line) = state.live_line.as_ref() {
                line.set_connected();
            }
            state.connecting_announced = false;
            state.last_error = None;
        }
        Status::Disconnecting => {
            if let Some(line) = state.live_line.as_ref() {
                line.set_disconnecting();
            }
            tracing::info!("OpenConnect disconnecting...");
        }
        Status::Disconnected => {
            if let Some(line) = state.live_line.as_ref() {
                line.set_reconnecting();
            }
            tracing::warn!("OpenConnect disconnected");
            state.connecting_announced = false;
        }
        Status::Error(err) => {
            state.last_error = Some(err.clone());
            tracing::warn!(error = %err, "OpenConnect error");
        }
    }
}

fn parse_expected_hashes(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(normalize_hash)
        .collect()
}

fn normalize_hash(hash: &str) -> String {
    hash.trim().to_ascii_lowercase()
}

fn handle_invalid_cert(
    expected_hashes: &[String],
    client_slot: &Arc<Mutex<Option<Arc<VpnClient>>>>,
    actual_hash: &str,
) -> bool {
    if expected_hashes.is_empty() {
        tracing::warn!("No pinned hash available; rejecting untrusted certificate");
        return false;
    }

    if let Ok(slot) = client_slot.lock()
        && let Some(client) = slot.as_ref()
        && cert_hash_matches_any(client, expected_hashes)
    {
        tracing::info!(
            hash = actual_hash,
            "Accepted VPN server certificate by pinned hash"
        );
        true
    } else {
        tracing::warn!(
            expected = ?expected_hashes,
            actual = actual_hash,
            "Rejected VPN server certificate (hash mismatch)"
        );
        false
    }
}

fn cert_hash_matches_any(client: &VpnClient, expected_hashes: &[String]) -> bool {
    expected_hashes.iter().any(|expected| {
        client
            .check_peer_cert_hash(expected)
            .map(|matched| matched)
            .unwrap_or(false)
    })
}

fn is_probably_auth_failure(err: &OpenconnectError) -> bool {
    matches!(
        err,
        OpenconnectError::SetCookieError(_)
            | OpenconnectError::ObtainCookieError(_)
            | OpenconnectError::MakeCstpError(_)
            | OpenconnectError::MainLoopError(_)
    )
}

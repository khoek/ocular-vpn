use std::process::Command;
use std::sync::{Arc, Mutex};

use openconnect_core::config::{ConfigBuilder, EntrypointBuilder, LogLevel as CoreLogLevel};
use openconnect_core::events::EventHandlers;
use openconnect_core::protocols::get_anyconnect_protocol;
use openconnect_core::result::OpenconnectError;
use openconnect_core::{Connectable, Status, VpnClient};

use crate::anyconnect::AuthComplete;
use crate::cli::LogLevel;
use crate::error::AppError;

#[derive(Debug, Clone, Default)]
pub struct OpenConnectResult {
    pub exit_code: i32,
    pub auth_failed: bool,
    pub expires_at_epoch: Option<i64>,
    pub expires_at_text: Option<String>,
}

pub fn run_openconnect(
    host_url: &str,
    auth: &AuthComplete,
    proxy: Option<&str>,
    _version: &str,
    args: &[String],
    on_disconnect: Option<&str>,
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
    let config = builder
        .build()
        .map_err(|e| AppError::OpenConnectCore(e.to_string()))?;

    let expected_hashes = parse_expected_hashes(&auth.server_cert_hash);
    let lifecycle = Arc::new(Mutex::new(Lifecycle::default()));
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

    if let Some(cmd) = on_disconnect.filter(|s| !s.trim().is_empty()) {
        handle_disconnect(cmd);
    }

    Ok(result)
}

pub fn preauthorize_privileged_runner() -> Result<(), AppError> {
    Ok(())
}

fn to_core_log_level(level: LogLevel) -> CoreLogLevel {
    match level {
        LogLevel::Error | LogLevel::Warn | LogLevel::Info => CoreLogLevel::Err,
        LogLevel::Debug => CoreLogLevel::Debug,
        LogLevel::Trace => CoreLogLevel::Trace,
    }
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

#[derive(Debug, Default)]
struct Lifecycle {
    connected_once: bool,
    connecting_announced: bool,
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
            tracing::debug!(stage = %stage, "OpenConnect stage");
        }
        Status::Connected => {
            if state.connected_once {
                tracing::info!("OpenConnect reconnected");
            } else {
                tracing::info!("OpenConnect connected!");
                state.connected_once = true;
            }
            state.connecting_announced = false;
        }
        Status::Disconnecting => {
            tracing::info!("OpenConnect disconnecting...");
        }
        Status::Disconnected => {
            tracing::warn!("OpenConnect disconnected");
            state.connecting_announced = false;
        }
        Status::Error(err) => {
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

mod anyconnect;
mod browser;
mod cli;
mod config;
mod error;
mod openconnect;
mod shell;
mod ui;

use clap::Parser;
use tracing::level_filters::LevelFilter;

use crate::cli::{Args, AuthenticateOutputFormat, LogLevel};
use crate::config::{CachedAuth, ConfigStore, LastConnect, StoredLogLevel};
use crate::error::AppError;

fn main() {
    let args = Args::parse();

    match run(args) {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    }
}

fn init_tracing(level: LogLevel) {
    let level = match level {
        LogLevel::Error => LevelFilter::ERROR,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Trace => LevelFilter::TRACE,
    };

    let crate_target = env!("CARGO_PKG_NAME").replace('-', "_");
    let default_filter = format!("warn,{crate_target}={level}");
    let filter = std::env::var("RUST_LOG").unwrap_or(default_filter);
    let filter = tracing_subscriber::EnvFilter::try_new(filter)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

fn run(args: Args) -> Result<i32, AppError> {
    let mut args = args;

    if let Some(payload_path) = args.internal_openconnect_payload.clone() {
        init_tracing(args.log_level);
        return openconnect::run_privileged_payload(&payload_path, args.log_level);
    }

    let mut config_store = ConfigStore::load()?;
    let interactive = args.interactive || args.server.is_none();
    if interactive {
        ui::interactive::run(&mut args, config_store.cfg())?;
    }

    init_tracing(args.log_level);

    let server = args.server.clone().ok_or_else(|| {
        AppError::InvalidServer("missing --server (or run with --interactive)".to_string())
    })?;

    let openconnect_args: Vec<String> = args
        .openconnect_args
        .iter()
        .filter(|s| s.as_str() != "--")
        .cloned()
        .collect();

    let ui_status = ui::status::UiStatus::new(interactive);

    let mut host =
        anyconnect::HostProfile::new(server, args.usergroup.clone(), args.authgroup.clone())?;
    let mut host_url = host.vpn_url();
    let mut config_key = anyconnect::canonicalize_remote_key(&host_url);

    if let Some(remote) = config_store.cfg().remote(&config_key) {
        if args.proxy.is_none() {
            args.proxy = remote.proxy.clone();
        }
        if host.user_group.is_empty() && !remote.usergroup.is_empty() {
            host.user_group = remote.usergroup.clone();
        }
        if host.auth_group.is_empty() && !remote.authgroup.is_empty() {
            host.auth_group = remote.authgroup.clone();
        }
        host_url = host.vpn_url();
        config_key = anyconnect::canonicalize_remote_key(&host_url);
    }

    let now = config::now_epoch();
    let cached = config_store
        .cfg()
        .remote(&config_key)
        .and_then(|r| r.cached_auth.clone())
        .filter(|c| !c.is_expired(now));

    if args.authenticate.is_none() {
        openconnect::preauthorize_privileged_runner()?;
    }

    if let Some(fmt) = args.authenticate
        && let Some(cached) = cached.clone()
    {
        let details = cli::AuthDetails {
            host: host_url.clone(),
            cookie: cached.session_token,
            fingerprint: cached.server_cert_hash,
        };
        match fmt {
            AuthenticateOutputFormat::Json => {
                println!("{}", serde_json::to_string_pretty(&details)?);
            }
            AuthenticateOutputFormat::Shell => {
                println!("HOST={}", shell::sh_quote(&details.host));
                println!("COOKIE={}", shell::sh_quote(&details.cookie));
                println!("FINGERPRINT={}", shell::sh_quote(&details.fingerprint));
            }
        }
        if let Some(remote) = config_store.cfg_mut().remote_mut(&config_key) {
            remote.proxy = args.proxy.clone();
            remote.usergroup = host.user_group.clone();
            remote.authgroup = host.auth_group.clone();
            remote.last_used_epoch = Some(now);
            let _ = config_store.save();
        }
        return Ok(0);
    }

    if args.authenticate.is_none()
        && let Some(cached) = cached.clone()
    {
        ui_status.info("Using cached session (no browser re-auth).");
        let auth = anyconnect::AuthComplete {
            auth_id: "cached".to_string(),
            auth_message: String::new(),
            session_token: cached.session_token,
            server_cert_hash: cached.server_cert_hash,
        };
        persist_last_connect(
            &mut config_store,
            &host_url,
            &host,
            &args,
            &openconnect_args,
        );
        let res = openconnect::run_openconnect(
            &host_url,
            &auth,
            args.proxy.as_deref(),
            &args.ac_version,
            &openconnect_args,
            (!args.on_disconnect.trim().is_empty()).then_some(args.on_disconnect.as_str()),
            interactive,
            args.log_level,
        )?;

        if res.auth_failed {
            tracing::warn!("Cached session was rejected; re-authenticating in browser");
            if let Some(remote) = config_store.cfg_mut().remote_mut(&config_key) {
                remote.proxy = args.proxy.clone();
                remote.usergroup = host.user_group.clone();
                remote.authgroup = host.auth_group.clone();
                remote.cached_auth = None;
                remote.last_used_epoch = Some(now);
            }
            let _ = config_store.save();
        } else {
            if let Some(remote) = config_store.cfg_mut().remote_mut(&config_key) {
                remote.proxy = args.proxy.clone();
                remote.usergroup = host.user_group.clone();
                remote.authgroup = host.auth_group.clone();
                if let Some(cache) = remote.cached_auth.as_mut() {
                    if res.expires_at_text.is_some() {
                        cache.expires_at_text = res.expires_at_text.clone();
                    }
                    if res.expires_at_epoch.is_some() {
                        cache.expires_at_epoch = res.expires_at_epoch;
                    }
                }
                remote.last_used_epoch = Some(now);
            }
            let _ = config_store.save();
            return Ok(res.exit_code);
        }
    }

    let http = anyconnect::Authenticator::new(args.proxy.as_deref(), &args.ac_version)?;

    let step = ui_status.step("Contacting VPN endpoint…");
    http.detect_authentication_target_url(&mut host)?;
    host_url = host.vpn_url();
    step.ok();

    let step = ui_status.step("Starting authentication…");
    let auth_request = http.start_authentication(&host)?;
    step.ok();
    if !auth_request.auth_error.is_empty() {
        return Err(AppError::AuthenticationFailed(auth_request.auth_error));
    }
    tracing::info!(
        id = %auth_request.auth_id,
        title = %auth_request.auth_title,
        message = %auth_request.auth_message,
        "Auth request received"
    );

    let browser_cfg = browser::BrowserConfig {
        chrome_path: args.chrome_path.clone(),
        proxy: args.proxy.clone(),
        timeout: args.browser_timeout,
        cookie_host: anyconnect::host_from_url(&host_url),
    };

    ui_status.info("Browser opened. Complete login in the window, then return here.");
    let step = ui_status.step("Waiting for browser login…");
    let sso_token = browser::authenticate_in_browser(&auth_request, &browser_cfg)?;
    step.ok();

    let step = ui_status.step("Finishing authentication…");
    let auth_complete = http.complete_authentication(&host, &auth_request, &sso_token)?;
    step.ok();
    tracing::info!(
        id = %auth_complete.auth_id,
        message = %auth_complete.auth_message,
        "Authentication completed"
    );

    host_url = host.vpn_url();

    {
        let remote = config_store.cfg_mut().ensure_remote(&config_key);
        remote.proxy = args.proxy.clone();
        remote.usergroup = host.user_group.clone();
        remote.authgroup = host.auth_group.clone();
        remote.last_used_epoch = Some(now);
        remote.cached_auth = Some(CachedAuth {
            session_token: auth_complete.session_token.clone(),
            server_cert_hash: auth_complete.server_cert_hash.clone(),
            cached_at_epoch: now,
            expires_at_epoch: None,
            expires_at_text: None,
        });
        config_store.save()?;
    }

    if let Some(fmt) = args.authenticate {
        let details = cli::AuthDetails {
            host: host_url,
            cookie: auth_complete.session_token,
            fingerprint: auth_complete.server_cert_hash,
        };
        match fmt {
            AuthenticateOutputFormat::Json => {
                println!("{}", serde_json::to_string_pretty(&details)?);
            }
            AuthenticateOutputFormat::Shell => {
                println!("HOST={}", shell::sh_quote(&details.host));
                println!("COOKIE={}", shell::sh_quote(&details.cookie));
                println!("FINGERPRINT={}", shell::sh_quote(&details.fingerprint));
            }
        }
        return Ok(0);
    }

    persist_last_connect(
        &mut config_store,
        &host_url,
        &host,
        &args,
        &openconnect_args,
    );
    let res = openconnect::run_openconnect(
        &host_url,
        &auth_complete,
        args.proxy.as_deref(),
        &args.ac_version,
        &openconnect_args,
        (!args.on_disconnect.trim().is_empty()).then_some(args.on_disconnect.as_str()),
        interactive,
        args.log_level,
    )?;

    if let Some(remote) = config_store.cfg_mut().remote_mut(&config_key) {
        if let Some(cache) = remote.cached_auth.as_mut() {
            if res.expires_at_text.is_some() {
                cache.expires_at_text = res.expires_at_text.clone();
            }
            if res.expires_at_epoch.is_some() {
                cache.expires_at_epoch = res.expires_at_epoch;
            }
        }
        remote.last_used_epoch = Some(config::now_epoch());
        let _ = config_store.save();
    }

    Ok(res.exit_code)
}

fn persist_last_connect(
    config_store: &mut ConfigStore,
    host_url: &str,
    host: &anyconnect::HostProfile,
    args: &Args,
    openconnect_args: &[String],
) {
    config_store.cfg_mut().last_connect = Some(LastConnect {
        remote_url: anyconnect::canonicalize_remote_key(host_url),
        proxy: args.proxy.clone(),
        usergroup: host.user_group.clone(),
        authgroup: host.auth_group.clone(),
        browser_timeout_secs: args.browser_timeout.as_secs().max(1),
        on_disconnect: args.on_disconnect.clone(),
        log_level: to_stored_log_level(args.log_level),
        openconnect_args: openconnect_args.to_vec(),
    });
    if let Err(err) = config_store.save() {
        tracing::warn!(%err, "Failed to persist quick-connect settings");
    }
}

fn to_stored_log_level(level: LogLevel) -> StoredLogLevel {
    match level {
        LogLevel::Error => StoredLogLevel::Error,
        LogLevel::Warn => StoredLogLevel::Warn,
        LogLevel::Info => StoredLogLevel::Info,
        LogLevel::Debug => StoredLogLevel::Debug,
        LogLevel::Trace => StoredLogLevel::Trace,
    }
}

use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use headless_chrome::protocol::cdp::Network;
use headless_chrome::{Browser, LaunchOptionsBuilder};
use which::which;

use crate::anyconnect::{self, AuthRequest};
use crate::config;
use crate::error::AppError;

pub struct BrowserConfig {
    pub chrome_path: Option<PathBuf>,
    pub proxy: Option<String>,
    pub timeout: Duration,
    pub cookie_host: Option<String>,
}

pub fn authenticate_in_browser(
    auth_info: &AuthRequest,
    cfg: &BrowserConfig,
) -> Result<String, AppError> {
    let chrome = resolve_chrome_path(cfg.chrome_path.as_ref())?;
    let profile_dir = resolve_profile_dir(auth_info, cfg)?;

    let options = LaunchOptionsBuilder::default()
        .path(Some(chrome))
        .user_data_dir(Some(profile_dir))
        .headless(false)
        .sandbox(!running_as_root())
        .ignore_certificate_errors(false)
        .idle_browser_timeout(cfg.timeout + Duration::from_secs(30))
        .proxy_server(cfg.proxy.as_deref())
        .args(vec![
            OsStr::new("--no-first-run"),
            OsStr::new("--no-default-browser-check"),
        ])
        .build()
        .map_err(|e| AppError::Browser(format!("invalid browser config: {e}")))?;

    let browser = Browser::new(options).map_err(|e| AppError::Browser(e.to_string()))?;
    let tab = browser
        .new_tab()
        .map_err(|e| AppError::Browser(e.to_string()))?;

    tracing::info!(url = %auth_info.login_url, "Opening browser for SSO login");
    tab.navigate_to(&auth_info.login_url)
        .map_err(|e| AppError::Browser(e.to_string()))?;

    let deadline = Instant::now() + cfg.timeout;
    loop {
        let cookies = tab
            .call_method(Network::GetAllCookies(None))
            .map_err(|e| AppError::Browser(e.to_string()))?
            .cookies;

        if let Some(token) = find_auth_cookie_value(
            cookies,
            &auth_info.token_cookie_name,
            cfg.cookie_host.as_deref(),
        ) {
            return Ok(token);
        }

        if Instant::now() > deadline {
            return Err(AppError::BrowserTimeout);
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn find_auth_cookie_value(
    cookies: Vec<Network::Cookie>,
    cookie_name: &str,
    expected_host: Option<&str>,
) -> Option<String> {
    let candidates: Vec<Network::Cookie> = cookies
        .into_iter()
        .filter(|cookie| cookie.name == cookie_name && !cookie.value.is_empty())
        .collect();
    if candidates.is_empty() {
        return None;
    }

    if let Some(host) = expected_host {
        if let Some(cookie) = candidates
            .iter()
            .find(|cookie| cookie_domain_matches(&cookie.domain, host))
        {
            return Some(cookie.value.clone());
        }
        if candidates.len() > 1 {
            return None;
        }
    }

    candidates.into_iter().next().map(|cookie| cookie.value)
}

fn cookie_domain_matches(cookie_domain: &str, host: &str) -> bool {
    let cookie = cookie_domain
        .trim()
        .trim_start_matches('.')
        .to_ascii_lowercase();
    let host = host.trim().trim_start_matches('.').to_ascii_lowercase();
    if cookie.is_empty() || host.is_empty() {
        return false;
    }
    host == cookie || host.ends_with(&format!(".{cookie}"))
}

fn resolve_profile_dir(auth_info: &AuthRequest, cfg: &BrowserConfig) -> Result<PathBuf, AppError> {
    let root = config::app_dir()?.join("browser-profiles");
    fs::create_dir_all(&root)?;
    tighten_dir_permissions(&root);

    let host = cfg
        .cookie_host
        .clone()
        .or_else(|| anyconnect::host_from_url(&auth_info.login_url))
        .unwrap_or_else(|| "default".to_string());
    let profile = root.join(sanitize_component(&host));
    fs::create_dir_all(&profile)?;
    tighten_dir_permissions(&profile);
    Ok(profile)
}

fn sanitize_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        return "default".to_string();
    }
    out
}

#[cfg(unix)]
fn tighten_dir_permissions(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o700);
    let _ = fs::set_permissions(dir, perms);
}

#[cfg(not(unix))]
fn tighten_dir_permissions(_dir: &Path) {}

fn resolve_chrome_path(explicit: Option<&PathBuf>) -> Result<PathBuf, AppError> {
    if let Some(p) = explicit {
        return Ok(p.clone());
    }

    for name in [
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
        "brave-browser",
        "microsoft-edge",
        "msedge",
        "chrome",
    ] {
        if let Ok(path) = which(name) {
            return Ok(path);
        }
    }

    Err(AppError::Browser(
        "could not find a Chrome/Chromium executable in PATH (use --chrome-path)".to_string(),
    ))
}

#[cfg(unix)]
fn running_as_root() -> bool {
    (unsafe { libc::geteuid() }) == 0
}

#[cfg(not(unix))]
fn running_as_root() -> bool {
    false
}

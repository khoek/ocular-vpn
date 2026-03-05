use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(
    name = "ocular",
    version,
    about = "SSO helper for OpenConnect (AnyConnect)"
)]
pub struct Args {
    #[arg(long, help = "VPN server address (e.g. vpn.example.com/group)")]
    pub server: Option<String>,

    #[arg(long, help = "Force interactive prompts", default_value_t = false)]
    pub interactive: bool,

    #[arg(
        long,
        help = "Proxy server (http:// or socks5://) used for auth and OpenConnect"
    )]
    pub proxy: Option<String>,

    #[arg(
        long,
        default_value = "",
        help = "Override usergroup (path) from --server"
    )]
    pub usergroup: String,

    #[arg(long, default_value = "", help = "Authentication group selection")]
    pub authgroup: String,

    #[arg(
        long,
        value_enum,
        num_args = 0..=1,
        default_missing_value = "shell",
        help = "Authenticate only and print connection details"
    )]
    pub authenticate: Option<AuthenticateOutputFormat>,

    #[arg(
        long,
        default_value = "4.7.00136",
        help = "AnyConnect version used during authentication and passed to openconnect"
    )]
    pub ac_version: String,

    #[arg(long, value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,

    #[arg(long, help = "Path to a Chrome/Chromium executable")]
    pub chrome_path: Option<PathBuf>,

    #[arg(
        long,
        value_parser = parse_timeout_seconds,
        default_value = "600",
        help = "Browser auth timeout (seconds)"
    )]
    pub browser_timeout: Duration,

    #[arg(long, default_value = "", help = "Command to run after disconnecting")]
    pub on_disconnect: String,

    #[arg(
        trailing_var_arg = true,
        help = "Arguments passed to openconnect (after --)"
    )]
    pub openconnect_args: Vec<String>,

    #[arg(long, hide = true)]
    pub internal_openconnect_payload: Option<PathBuf>,
}

fn parse_timeout_seconds(s: &str) -> Result<Duration, String> {
    let secs: u64 = s
        .parse()
        .map_err(|_| "timeout must be an integer number of seconds".to_string())?;
    Ok(Duration::from_secs(secs))
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum AuthenticateOutputFormat {
    Shell,
    Json,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Serialize)]
pub struct AuthDetails {
    pub host: String,
    pub cookie: String,
    pub fingerprint: String,
}

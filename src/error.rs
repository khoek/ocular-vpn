use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("invalid VPN server: {0}")]
    InvalidServer(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("XML error: {0}")]
    Xml(#[from] quick_xml::Error),

    #[error("XML attribute error: {0}")]
    XmlAttr(#[from] quick_xml::events::attributes::AttrError),

    #[error("XML escape error: {0}")]
    XmlEscape(#[from] quick_xml::escape::EscapeError),

    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("unknown XML entity: {0}")]
    UnknownEntity(String),

    #[error("interactive mode requires a TTY")]
    InteractiveRequiresTty,

    #[error("UI error: {0}")]
    Ui(#[from] dialoguer::Error),

    #[error("missing required field in VPN response: {0}")]
    MissingField(&'static str),

    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("browser error: {0}")]
    Browser(String),

    #[error("timed out waiting for browser login to complete")]
    BrowserTimeout,

    #[error(
        "this operation requires root privileges (run with sudo/doas, or ensure elevation succeeds)"
    )]
    NeedRoot,

    #[error("openconnect core error: {0}")]
    OpenConnectCore(String),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("could not determine home directory ($HOME)")]
    HomeNotFound,

    #[error("config error: {0}")]
    Config(String),
}

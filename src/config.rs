use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::anyconnect;
use crate::error::AppError;

const CONFIG_DIR: &str = ".ocular";
const CONFIG_FILE: &str = "config.toml";

#[derive(Debug, Clone)]
pub struct ConfigStore {
    path: PathBuf,
    cfg: Config,
}

impl ConfigStore {
    pub fn load() -> Result<Self, AppError> {
        let path = config_path()?;
        let mut cfg = if path.exists() {
            let raw = fs::read_to_string(&path)?;
            toml::from_str(&raw).map_err(|e| AppError::Config(e.to_string()))?
        } else {
            Config::default()
        };
        cfg.sort_remotes();
        Ok(Self { path, cfg })
    }

    pub fn cfg(&self) -> &Config {
        &self.cfg
    }

    pub fn cfg_mut(&mut self) -> &mut Config {
        &mut self.cfg
    }

    pub fn save(&mut self) -> Result<(), AppError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
            tighten_dir_permissions(parent)?;
        }

        self.cfg.sort_remotes();

        let content =
            toml::to_string_pretty(&self.cfg).map_err(|e| AppError::Config(e.to_string()))?;
        atomic_write(&self.path, content.as_bytes())?;
        tighten_file_permissions(&self.path)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_version")]
    pub version: u32,

    #[serde(default)]
    pub remotes: Vec<Remote>,

    #[serde(default)]
    pub last_connect: Option<LastConnect>,
}

fn default_version() -> u32 {
    1
}

fn default_browser_timeout_secs() -> u64 {
    600
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: default_version(),
            remotes: Vec::new(),
            last_connect: None,
        }
    }
}

impl Config {
    pub fn remote(&self, url: &str) -> Option<&Remote> {
        let key = anyconnect::canonicalize_remote_key(url);
        self.remotes
            .iter()
            .find(|remote| anyconnect::canonicalize_remote_key(&remote.url) == key)
    }

    pub fn remote_mut(&mut self, url: &str) -> Option<&mut Remote> {
        let key = anyconnect::canonicalize_remote_key(url);
        self.remotes
            .iter_mut()
            .find(|remote| anyconnect::canonicalize_remote_key(&remote.url) == key)
    }

    pub fn ensure_remote(&mut self, url: &str) -> &mut Remote {
        let key = anyconnect::canonicalize_remote_key(url);
        if let Some(idx) = self
            .remotes
            .iter()
            .position(|remote| anyconnect::canonicalize_remote_key(&remote.url) == key)
        {
            if self.remotes[idx].url != key {
                self.remotes[idx].url = key.clone();
            }
            return &mut self.remotes[idx];
        }
        self.remotes.push(Remote::new(key));
        self.remotes.last_mut().expect("just pushed remote")
    }

    pub fn sort_remotes(&mut self) {
        self.remotes
            .sort_by_key(|remote| std::cmp::Reverse(remote.last_used()));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remote {
    pub url: String,

    #[serde(default)]
    pub proxy: Option<String>,

    #[serde(default)]
    pub usergroup: String,

    #[serde(default)]
    pub authgroup: String,

    #[serde(default)]
    pub cached_auth: Option<CachedAuth>,

    #[serde(default)]
    pub last_used_epoch: Option<i64>,
}

impl Remote {
    pub fn new(url: String) -> Self {
        Self {
            url,
            proxy: None,
            usergroup: String::new(),
            authgroup: String::new(),
            cached_auth: None,
            last_used_epoch: None,
        }
    }

    pub fn last_used(&self) -> i64 {
        self.last_used_epoch.unwrap_or(0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedAuth {
    pub session_token: String,
    pub server_cert_hash: String,

    #[serde(default)]
    pub cached_at_epoch: i64,

    #[serde(default)]
    pub expires_at_epoch: Option<i64>,

    #[serde(default)]
    pub expires_at_text: Option<String>,
}

impl CachedAuth {
    pub fn is_expired(&self, now_epoch: i64) -> bool {
        self.expires_at_epoch
            .map(|expires| now_epoch >= expires)
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastConnect {
    pub remote_url: String,

    #[serde(default)]
    pub proxy: Option<String>,

    #[serde(default)]
    pub usergroup: String,

    #[serde(default)]
    pub authgroup: String,

    #[serde(default = "default_browser_timeout_secs")]
    pub browser_timeout_secs: u64,

    #[serde(default)]
    pub on_disconnect: String,

    #[serde(default)]
    pub log_level: StoredLogLevel,

    #[serde(default)]
    pub openconnect_args: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum StoredLogLevel {
    Error,
    Info,
    #[default]
    Warn,
    Debug,
    Trace,
}

pub fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn app_dir() -> Result<PathBuf, AppError> {
    let home = home_dir()?;
    Ok(home.join(CONFIG_DIR))
}

fn home_dir() -> Result<PathBuf, AppError> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or(AppError::HomeNotFound)?;
    Ok(PathBuf::from(home))
}

fn config_path() -> Result<PathBuf, AppError> {
    Ok(app_dir()?.join(CONFIG_FILE))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), AppError> {
    let tmp = path.with_extension("toml.new");
    write_file(&tmp, bytes)?;
    #[cfg(windows)]
    {
        if path.exists() {
            fs::remove_file(path)?;
        }
    }
    fs::rename(tmp, path)?;
    Ok(())
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), AppError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
        file.flush()?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        fs::write(path, bytes)?;
        Ok(())
    }
}

fn tighten_dir_permissions(dir: &Path) -> Result<(), AppError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o700);
        let _ = fs::set_permissions(dir, perms);
    }
    let _ = dir;
    Ok(())
}

fn tighten_file_permissions(path: &Path) -> Result<(), AppError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        let _ = fs::set_permissions(path, perms);
    }
    let _ = path;
    Ok(())
}

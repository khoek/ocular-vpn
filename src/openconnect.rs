use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

use which::which;

use crate::anyconnect::AuthComplete;
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
    version: &str,
    args: &[String],
    on_disconnect: Option<&str>,
) -> Result<OpenConnectResult, AppError> {
    let openconnect_path = which("openconnect").map_err(|_| AppError::OpenConnectNotFound)?;

    let (program, mut argv) = command_prefix(openconnect_path.to_string_lossy().as_ref())?;

    argv.push("--useragent".to_string());
    argv.push(format!("AnyConnect Linux_64 {version}"));
    argv.push("--version-string".to_string());
    argv.push(version.to_string());
    argv.push("--cookie-on-stdin".to_string());
    argv.push("--servercert".to_string());
    argv.push(auth.server_cert_hash.clone());
    argv.extend(args.iter().cloned());
    argv.push(host_url.to_string());
    if let Some(proxy) = proxy {
        argv.push("--proxy".to_string());
        argv.push(proxy.to_string());
    }

    tracing::debug!(?program, ?argv, "Starting OpenConnect");

    let mut child = Command::new(&program)
        .args(&argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(auth.session_token.as_bytes())?;
        stdin.write_all(b"\n")?;
    }

    let state = Arc::new(Mutex::new(ParserState::default()));

    let stdout = child.stdout.take().ok_or_else(|| {
        AppError::Io(std::io::Error::other(
            "failed to capture openconnect stdout",
        ))
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        AppError::Io(std::io::Error::other(
            "failed to capture openconnect stderr",
        ))
    })?;

    let state_out = Arc::clone(&state);
    let t_out = thread::spawn(move || forward_and_parse(stdout, std::io::stdout(), state_out));

    let state_err = Arc::clone(&state);
    let t_err = thread::spawn(move || forward_and_parse(stderr, std::io::stderr(), state_err));

    let status = child.wait()?;

    let _ = t_out.join();
    let _ = t_err.join();

    if let Some(cmd) = on_disconnect.filter(|s| !s.trim().is_empty()) {
        handle_disconnect(cmd);
    }

    let mut result = state.lock().unwrap_or_else(|e| e.into_inner()).to_result();
    result.exit_code = exit_code(status);
    Ok(result)
}

pub fn preauthorize_privileged_runner() -> Result<(), AppError> {
    let openconnect_path = which("openconnect").map_err(|_| AppError::OpenConnectNotFound)?;

    #[cfg(unix)]
    {
        let openconnect = openconnect_path.to_string_lossy();
        let (program, _) = command_prefix(openconnect.as_ref())?;
        let status = match program.as_str() {
            "sudo" => Command::new("sudo").arg("-v").status()?,
            "doas" => Command::new("doas").arg("true").status()?,
            _ => return Ok(()),
        };
        if !status.success() {
            return Err(AppError::NeedRoot);
        }
    }

    Ok(())
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

fn command_prefix(openconnect: &str) -> Result<(String, Vec<String>), AppError> {
    #[cfg(unix)]
    {
        if unsafe { libc::geteuid() } == 0 {
            return Ok((openconnect.to_string(), Vec::new()));
        }

        if which("doas").is_ok() {
            return Ok(("doas".to_string(), vec![openconnect.to_string()]));
        }
        if which("sudo").is_ok() {
            return Ok(("sudo".to_string(), vec![openconnect.to_string()]));
        }

        Err(AppError::NeedRoot)
    }

    #[cfg(not(unix))]
    {
        Ok((openconnect.to_string(), Vec::new()))
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
struct ParserState {
    auth_failed: bool,
    expires_at_epoch: Option<i64>,
    expires_at_text: Option<String>,
}

impl ParserState {
    fn observe_line(&mut self, line: &str) {
        if self.expires_at_text.is_none() {
            let needle = "Session authentication will expire at ";
            if let Some(pos) = line.find(needle) {
                let text = line[pos + needle.len()..].trim().to_string();
                if !text.is_empty() {
                    self.expires_at_epoch = parse_openconnect_expiry_epoch(&text);
                    self.expires_at_text = Some(text);
                }
            }
        }

        if self.auth_failed {
            return;
        }

        let lower = line.to_ascii_lowercase();
        let auth_markers = [
            "401",
            "unauthorized",
            "cookie was rejected",
            "cookie rejected",
            "invalid cookie",
            "bad cookie",
            "authentication failed",
            "failed to obtain webvpn cookie",
        ];
        if auth_markers.iter().any(|m| lower.contains(m))
            || (lower.contains("server certificate") && lower.contains("does not match"))
            || (lower.contains("fingerprint") && lower.contains("does not match"))
            || (lower.contains("fingerprint") && lower.contains("mismatch"))
        {
            self.auth_failed = true;
        }
    }

    fn to_result(&self) -> OpenConnectResult {
        OpenConnectResult {
            exit_code: 1,
            auth_failed: self.auth_failed,
            expires_at_epoch: self.expires_at_epoch,
            expires_at_text: self.expires_at_text.clone(),
        }
    }
}

fn forward_and_parse<R: std::io::Read, W: std::io::Write>(
    mut reader: R,
    mut writer: W,
    state: Arc<Mutex<ParserState>>,
) -> std::io::Result<()> {
    let mut buf = [0_u8; 8192];
    let mut line_buf: Vec<u8> = Vec::with_capacity(256);
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n])?;
        let _ = writer.flush();

        let mut start = 0;
        while start < n {
            let rel = buf[start..n].iter().position(|b| *b == b'\n');
            if let Some(rel) = rel {
                let end = start + rel + 1;
                line_buf.extend_from_slice(&buf[start..end]);
                let line = String::from_utf8_lossy(&line_buf);
                if let Ok(mut st) = state.lock() {
                    st.observe_line(&line);
                }
                line_buf.clear();
                start = end;
            } else {
                line_buf.extend_from_slice(&buf[start..n]);
                break;
            }
        }
    }

    if !line_buf.is_empty() {
        let line = String::from_utf8_lossy(&line_buf);
        if let Ok(mut st) = state.lock() {
            st.observe_line(&line);
        }
    }
    Ok(())
}

fn parse_openconnect_expiry_epoch(text: &str) -> Option<i64> {
    // Example: "Fri Feb 20 13:06:16 2026"
    let mut it = text.split_whitespace();
    let _weekday = it.next()?;
    let month = it.next()?;
    let day = it.next()?.parse::<i32>().ok()?;
    let time = it.next()?;
    let year = it.next()?.parse::<i32>().ok()?;

    let (hour, min, sec) = parse_hms(time)?;
    let month_idx = month_to_index(month)?;

    #[cfg(unix)]
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        tm.tm_sec = sec;
        tm.tm_min = min;
        tm.tm_hour = hour;
        tm.tm_mday = day;
        tm.tm_mon = month_idx;
        tm.tm_year = year - 1900;
        tm.tm_isdst = -1;
        let t = libc::mktime(&mut tm);
        if t < 0 { None } else { Some(t as i64) }
    }

    #[cfg(not(unix))]
    {
        let _ = (hour, min, sec, month_idx);
        None
    }
}

fn parse_hms(s: &str) -> Option<(i32, i32, i32)> {
    let (h, rest) = s.split_once(':')?;
    let (m, sec) = rest.split_once(':')?;
    Some((
        h.parse::<i32>().ok()?,
        m.parse::<i32>().ok()?,
        sec.parse::<i32>().ok()?,
    ))
}

fn month_to_index(month: &str) -> Option<i32> {
    Some(match month {
        "Jan" => 0,
        "Feb" => 1,
        "Mar" => 2,
        "Apr" => 3,
        "May" => 4,
        "Jun" => 5,
        "Jul" => 6,
        "Aug" => 7,
        "Sep" => 8,
        "Oct" => 9,
        "Nov" => 10,
        "Dec" => 11,
        _ => return None,
    })
}

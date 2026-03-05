pub mod interactive {
    use std::io::IsTerminal;
    use std::time::Duration;

    use dialoguer::{Confirm, Input, Select, theme::ColorfulTheme};

    use crate::cli::{Args, AuthenticateOutputFormat, LogLevel};
    use crate::config;
    use crate::error::AppError;

    pub fn run(args: &mut Args, cfg: &config::Config) -> Result<(), AppError> {
        if !std::io::stdin().is_terminal() {
            return Err(AppError::InteractiveRequiresTty);
        }

        let theme = ColorfulTheme::default();

        eprintln!("ocular\n");

        if args.server.is_none()
            && args.authenticate.is_none()
            && let Some(last) = cfg.last_connect.as_ref()
            && !last.remote_url.trim().is_empty()
        {
            let quick = Confirm::with_theme(&theme)
                .with_prompt(format!(
                    "Quick connect to {}?",
                    quick_connect_target(&last.remote_url)
                ))
                .default(true)
                .interact()?;
            if quick {
                args.server = Some(last.remote_url.clone());
                args.proxy = last.proxy.clone();
                args.usergroup = last.usergroup.clone();
                args.authgroup = last.authgroup.clone();
                args.browser_timeout = Duration::from_secs(last.browser_timeout_secs.max(1));
                args.on_disconnect = last.on_disconnect.clone();
                args.log_level = stored_to_cli_log_level(last.log_level);
                if args.openconnect_args.is_empty() {
                    args.openconnect_args = last.openconnect_args.clone();
                }
                return Ok(());
            }
        }

        let now = config::now_epoch();
        let mut labels: Vec<String> = Vec::new();
        let mut urls: Vec<String> = Vec::new();
        for remote in &cfg.remotes {
            let mut label = remote.url.clone();
            if let Some(cache) = &remote.cached_auth {
                if cache.is_expired(now) {
                    label.push_str(" (expired)");
                } else if let Some(text) = cache.expires_at_text.as_deref() {
                    label.push_str(" (cached; expires ");
                    label.push_str(text.trim());
                    label.push(')');
                } else {
                    label.push_str(" (cached)");
                }
            }
            labels.push(label);
            urls.push(remote.url.clone());
        }
        labels.push("<new>".to_string());

        let mut default_idx = labels.len().saturating_sub(1);
        if let Some(current) = args.server.as_deref() {
            if let Some(idx) = urls.iter().position(|u| u == current) {
                default_idx = idx;
            }
        } else if let Some((idx, _)) = cfg
            .remotes
            .iter()
            .enumerate()
            .max_by_key(|(_, r)| r.last_used_epoch.unwrap_or(0))
        {
            default_idx = idx;
        }

        let selection = if cfg.remotes.is_empty() {
            labels.len().saturating_sub(1)
        } else {
            Select::with_theme(&theme)
                .with_prompt("Remote")
                .items(&labels)
                .default(default_idx)
                .interact()?
        };

        if selection == labels.len() - 1 {
            let server_initial = args.server.clone().unwrap_or_default();
            let server: String = Input::with_theme(&theme)
                .with_prompt("VPN server (host[/group] or https://…)")
                .with_initial_text(server_initial)
                .validate_with(|input: &String| {
                    if input.trim().is_empty() {
                        Err("required")
                    } else {
                        Ok(())
                    }
                })
                .interact_text()?;
            args.server = Some(server.trim().to_string());
        } else {
            let remote = &cfg.remotes[selection];
            args.server = Some(urls[selection].clone());
            if args.proxy.is_none() {
                args.proxy = remote.proxy.clone();
            }
            if args.usergroup.is_empty() {
                args.usergroup = remote.usergroup.clone();
            }
            if args.authgroup.is_empty() {
                args.authgroup = remote.authgroup.clone();
            }
        }

        let action_items = [
            "Connect (run openconnect)",
            "Authenticate only (shell vars)",
            "Authenticate only (JSON)",
        ];
        let action_default = match args.authenticate {
            None => 0,
            Some(AuthenticateOutputFormat::Shell) => 1,
            Some(AuthenticateOutputFormat::Json) => 2,
        };
        let action_idx = Select::with_theme(&theme)
            .with_prompt("Action")
            .items(&action_items)
            .default(action_default)
            .interact()?;
        args.authenticate = match action_idx {
            0 => None,
            1 => Some(AuthenticateOutputFormat::Shell),
            2 => Some(AuthenticateOutputFormat::Json),
            _ => unreachable!(),
        };

        let advanced = Confirm::with_theme(&theme)
            .with_prompt("Advanced options?")
            .default(false)
            .interact()?;

        if advanced {
            let proxy_initial = args.proxy.clone().unwrap_or_default();
            let proxy: String = Input::with_theme(&theme)
                .with_prompt("Proxy (optional, http:// or socks5://)")
                .with_initial_text(proxy_initial)
                .allow_empty(true)
                .interact_text()?;
            args.proxy = match proxy.trim() {
                "" => None,
                v => Some(v.to_string()),
            };

            let usergroup: String = Input::with_theme(&theme)
                .with_prompt("User group override (optional)")
                .with_initial_text(args.usergroup.clone())
                .allow_empty(true)
                .interact_text()?;
            args.usergroup = usergroup.trim().to_string();

            let authgroup: String = Input::with_theme(&theme)
                .with_prompt("Auth group (optional)")
                .with_initial_text(args.authgroup.clone())
                .allow_empty(true)
                .interact_text()?;
            args.authgroup = authgroup.trim().to_string();

            let timeout_initial = args.browser_timeout.as_secs().to_string();
            let timeout_secs: u64 = Input::with_theme(&theme)
                .with_prompt("Browser timeout (seconds)")
                .with_initial_text(timeout_initial)
                .validate_with(|input: &String| {
                    input
                        .parse::<u64>()
                        .map(|_| ())
                        .map_err(|_| "must be an integer number of seconds")
                })
                .interact_text()?
                .parse()
                .unwrap_or(args.browser_timeout.as_secs());
            args.browser_timeout = std::time::Duration::from_secs(timeout_secs);

            let on_disconnect: String = Input::with_theme(&theme)
                .with_prompt("On disconnect command (optional)")
                .with_initial_text(args.on_disconnect.clone())
                .allow_empty(true)
                .interact_text()?;
            args.on_disconnect = on_disconnect.trim().to_string();

            let log_levels = [
                (LogLevel::Error, "error"),
                (LogLevel::Warn, "warn"),
                (LogLevel::Info, "info"),
                (LogLevel::Debug, "debug"),
                (LogLevel::Trace, "trace"),
            ];
            let log_level_labels: Vec<&str> = log_levels.iter().map(|(_, s)| *s).collect();
            let current = log_levels
                .iter()
                .position(|(lvl, _)| *lvl == args.log_level)
                .unwrap_or(1);
            let idx = Select::with_theme(&theme)
                .with_prompt("Log level")
                .items(&log_level_labels)
                .default(current)
                .interact()?;
            args.log_level = log_levels[idx].0;
        }

        Ok(())
    }

    fn quick_connect_target(url: &str) -> String {
        let trimmed = url.trim().trim_end_matches('/');
        let no_scheme = trimmed
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(trimmed);
        no_scheme.to_string()
    }

    fn stored_to_cli_log_level(level: config::StoredLogLevel) -> LogLevel {
        match level {
            config::StoredLogLevel::Error => LogLevel::Error,
            config::StoredLogLevel::Warn => LogLevel::Warn,
            config::StoredLogLevel::Info => LogLevel::Info,
            config::StoredLogLevel::Debug => LogLevel::Debug,
            config::StoredLogLevel::Trace => LogLevel::Trace,
        }
    }
}

pub mod status {
    use std::time::Duration;

    use indicatif::{ProgressBar, ProgressStyle};

    pub struct UiStatus {
        enabled: bool,
        spinner_style: ProgressStyle,
    }

    impl UiStatus {
        pub fn new(enabled: bool) -> Self {
            let spinner_style = ProgressStyle::with_template("{spinner:.cyan} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_spinner());
            Self {
                enabled,
                spinner_style,
            }
        }

        pub fn info(&self, msg: &str) {
            if self.enabled {
                eprintln!("{msg}");
            }
        }

        pub fn step(&self, msg: &str) -> Step {
            if !self.enabled {
                return Step {
                    pb: None,
                    msg: msg.to_string(),
                    finished: true,
                };
            }

            let pb = ProgressBar::new_spinner();
            pb.set_style(self.spinner_style.clone());
            pb.set_message(msg.to_string());
            pb.enable_steady_tick(Duration::from_millis(90));
            Step {
                pb: Some(pb),
                msg: msg.to_string(),
                finished: false,
            }
        }
    }

    pub struct Step {
        pb: Option<ProgressBar>,
        msg: String,
        finished: bool,
    }

    impl Step {
        pub fn ok(mut self) {
            if let Some(pb) = &self.pb {
                pb.finish_with_message(format!("{} ok", self.msg));
            }
            self.finished = true;
        }
    }

    impl Drop for Step {
        fn drop(&mut self) {
            if self.finished {
                return;
            }
            if let Some(pb) = self.pb.take() {
                pb.finish_and_clear();
            }
        }
    }
}

use std::borrow::Cow;

use quick_xml::Reader;
use quick_xml::events::Event;
use reqwest::Url;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue};

use crate::error::AppError;

#[derive(Debug, Clone)]
pub struct HostProfile {
    pub address: String,
    pub user_group: String,
    pub auth_group: String,
}

impl HostProfile {
    pub fn new(address: String, user_group: String, auth_group: String) -> Result<Self, AppError> {
        if address.trim().is_empty() {
            return Err(AppError::InvalidServer("empty".to_string()));
        }
        Ok(Self {
            address,
            user_group,
            auth_group,
        })
    }

    pub fn vpn_url(&self) -> String {
        let (scheme, host_port, group_from_address) = split_server(&self.address);
        let group = if !self.user_group.is_empty() {
            self.user_group.as_str()
        } else {
            group_from_address
        };

        if group.is_empty() {
            format!("{scheme}://{host_port}")
        } else {
            let group = group.trim_matches('/');
            format!("{scheme}://{host_port}/{group}")
        }
    }
}

pub fn canonicalize_remote_key(url: &str) -> String {
    let raw = url.trim();
    let with_scheme = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("https://{raw}")
    };

    let parsed = match Url::parse(&with_scheme) {
        Ok(parsed) => parsed,
        Err(_) => return fallback_canonicalize(raw),
    };

    let host = match parsed.host_str() {
        Some(host) => host.to_ascii_lowercase(),
        None => return fallback_canonicalize(raw),
    };
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };

    let scheme = parsed.scheme().to_ascii_lowercase();
    let port = match parsed.port() {
        Some(port) if !is_default_port(&scheme, port) => format!(":{port}"),
        _ => String::new(),
    };

    let group = parsed.path().trim_matches('/');
    if group.is_empty() {
        format!("{scheme}://{host}{port}")
    } else {
        format!("{scheme}://{host}{port}/{group}")
    }
}

pub fn host_from_url(url: &str) -> Option<String> {
    let with_scheme = if url.contains("://") {
        url.to_string()
    } else {
        format!("https://{url}")
    };
    let parsed = Url::parse(&with_scheme).ok()?;
    parsed.host_str().map(|host| host.to_ascii_lowercase())
}

fn is_default_port(scheme: &str, port: u16) -> bool {
    matches!(
        (scheme, port),
        ("http", 80) | ("https", 443) | ("socks5", 1080)
    )
}

fn fallback_canonicalize(url: &str) -> String {
    let (scheme, host_port, group) = split_server(url);
    let scheme = scheme.to_ascii_lowercase();
    let host_port = host_port.to_ascii_lowercase();
    let group = group.trim_matches('/');
    if group.is_empty() {
        format!("{scheme}://{host_port}")
    } else {
        format!("{scheme}://{host_port}/{group}")
    }
}

fn split_server(input: &str) -> (&str, &str, &str) {
    if let Some((scheme, rest)) = input.split_once("://") {
        let scheme = if scheme.is_empty() { "https" } else { scheme };

        let mut host_port = rest;
        let mut group = "";
        if let Some((h, p)) = rest.split_once('/') {
            host_port = h;
            group = p;
        }
        (scheme, host_port, group)
    } else {
        let mut host_port = input;
        let mut group = "";
        if let Some((h, p)) = input.split_once('/') {
            host_port = h;
            group = p;
        }
        ("https", host_port, group)
    }
}

#[derive(Debug, Clone)]
pub struct AuthRequest {
    pub auth_id: String,
    pub auth_title: String,
    pub auth_message: String,
    pub auth_error: String,
    pub opaque_xml: Vec<u8>,
    pub login_url: String,
    pub token_cookie_name: String,
}

#[derive(Debug, Clone)]
pub struct AuthComplete {
    pub auth_id: String,
    pub auth_message: String,
    pub session_token: String,
    pub server_cert_hash: String,
}

#[derive(Debug, Clone)]
pub struct Authenticator {
    client: Client,
    probe_client: Client,
    version: String,
}

impl Authenticator {
    pub fn new(proxy: Option<&str>, version: &str) -> Result<Self, AppError> {
        let mut headers = HeaderMap::new();
        headers.insert("Accept", HeaderValue::from_static("*/*"));
        headers.insert("Accept-Encoding", HeaderValue::from_static("identity"));
        headers.insert("X-Transcend-Version", HeaderValue::from_static("1"));
        headers.insert("X-Aggregate-Auth", HeaderValue::from_static("1"));
        headers.insert("X-Support-HTTP-Auth", HeaderValue::from_static("true"));
        headers.insert(
            "Content-Type",
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );

        let ua = format!("AnyConnect Linux_64 {version}");
        headers.insert(
            "User-Agent",
            HeaderValue::from_str(&ua).map_err(|_| AppError::InvalidServer("bad ua".into()))?,
        );

        let mut builder = Client::builder().default_headers(headers);
        if let Some(proxy) = proxy {
            builder = builder.proxy(reqwest::Proxy::all(proxy)?);
        }
        let client = builder.build()?;

        let mut probe_builder = Client::builder();
        if let Some(proxy) = proxy {
            probe_builder = probe_builder.proxy(reqwest::Proxy::all(proxy)?);
        }
        let probe_client = probe_builder.build()?;

        Ok(Self {
            client,
            probe_client,
            version: version.to_string(),
        })
    }

    pub fn detect_authentication_target_url(&self, host: &mut HostProfile) -> Result<(), AppError> {
        let resp = self
            .probe_client
            .get(host.vpn_url())
            .send()?
            .error_for_status()?;
        host.address = resp.url().to_string();
        tracing::debug!(url = host.address, "Auth target URL");
        Ok(())
    }

    pub fn start_authentication(&self, host: &HostProfile) -> Result<AuthRequest, AppError> {
        let req = build_auth_init_request(host, &self.version);
        tracing::debug!(len = req.len(), "Sending auth init request");
        let resp = self
            .client
            .post(host.vpn_url())
            .body(req)
            .send()?
            .error_for_status()?;
        let bytes = resp.bytes()?;
        parse_auth_request_response(&bytes)
    }

    pub fn complete_authentication(
        &self,
        host: &HostProfile,
        auth_info: &AuthRequest,
        sso_token: &str,
    ) -> Result<AuthComplete, AppError> {
        let req = build_auth_finish_request(auth_info, sso_token, &self.version);
        tracing::debug!(len = req.len(), "Sending auth finish request");
        let resp = self
            .client
            .post(host.vpn_url())
            .body(req)
            .send()?
            .error_for_status()?;
        let bytes = resp.bytes()?;
        parse_auth_complete_response(&bytes)
    }
}

fn build_auth_init_request(host: &HostProfile, version: &str) -> Vec<u8> {
    let version = xml_escape(version);
    let group_select = xml_escape(&host.auth_group);
    let host_url = host.vpn_url();
    let group_access = xml_escape(&host_url);

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="init" aggregate-auth-version="2">
  <version who="vpn">{version}</version>
  <device-id>linux-64</device-id>
  <group-select>{group_select}</group-select>
  <group-access>{group_access}</group-access>
  <capabilities>
    <auth-method>single-sign-on-v2</auth-method>
  </capabilities>
</config-auth>
"#
    )
    .into_bytes()
}

fn build_auth_finish_request(auth_info: &AuthRequest, sso_token: &str, version: &str) -> Vec<u8> {
    let version = xml_escape(version);
    let sso_token = xml_escape(sso_token);
    let mut out = String::with_capacity(512 + auth_info.opaque_xml.len() + sso_token.len());

    out.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    out.push('\n');
    out.push_str(r#"<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">"#);
    out.push('\n');
    out.push_str(&format!(r#"  <version who="vpn">{version}</version>"#));
    out.push('\n');
    out.push_str("  <device-id>linux-64</device-id>\n");
    out.push_str("  <session-token/>\n");
    out.push_str("  <session-id/>\n");
    out.push_str("  ");
    out.push_str(String::from_utf8_lossy(&auth_info.opaque_xml).trim());
    out.push('\n');
    out.push_str("  <auth>\n");
    out.push_str(&format!("    <sso-token>{sso_token}</sso-token>\n"));
    out.push_str("  </auth>\n");
    out.push_str("</config-auth>\n");
    out.into_bytes()
}

fn xml_escape(input: &str) -> Cow<'_, str> {
    if !input
        .bytes()
        .any(|b| matches!(b, b'<' | b'>' | b'&' | b'\'' | b'"'))
    {
        return Cow::Borrowed(input);
    }
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    Cow::Owned(out)
}

fn local_name(name: &[u8]) -> &[u8] {
    name.rsplit(|&b| b == b':').next().unwrap_or(name)
}

fn parse_auth_request_response(xml: &[u8]) -> Result<AuthRequest, AppError> {
    let mut reader = Reader::from_reader(xml);

    let mut buf = Vec::new();
    let mut stack: Vec<Vec<u8>> = Vec::new();

    let mut auth_id: Option<String> = None;
    let mut auth_title = String::new();
    let mut auth_message: Option<String> = None;
    let mut auth_error = String::new();
    let mut opaque_xml: Option<Vec<u8>> = None;
    let mut login_url: Option<String> = None;
    let mut token_cookie_name: Option<String> = None;

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => {
                let name = local_name(e.name().as_ref()).to_vec();
                if name.as_slice() == b"opaque" {
                    opaque_xml = Some(capture_subtree(&mut reader, Event::Start(e.into_owned()))?);
                    buf.clear();
                    continue;
                }

                if name.as_slice() == b"auth" {
                    for attr in e.attributes() {
                        let attr = attr?;
                        if local_name(attr.key.as_ref()) == b"id" {
                            auth_id = Some(attr.unescape_value()?.to_string());
                        }
                    }
                }

                stack.push(name);
            }
            Event::Empty(e) => {
                let name = local_name(e.name().as_ref()).to_vec();
                if name.as_slice() == b"opaque" {
                    opaque_xml = Some(capture_subtree(&mut reader, Event::Empty(e.into_owned()))?);
                    buf.clear();
                    continue;
                }
            }
            Event::Text(t) => {
                let text = unescape_text(&t)?;
                if stack.len() >= 2 && stack[stack.len() - 2].as_slice() == b"auth" {
                    match stack[stack.len() - 1].as_slice() {
                        b"title" => auth_title.push_str(&text),
                        b"message" => match &mut auth_message {
                            Some(msg) => msg.push_str(&text),
                            None => auth_message = Some(text),
                        },
                        b"error" => auth_error.push_str(&text),
                        b"sso-v2-login" => match &mut login_url {
                            Some(v) => v.push_str(&text),
                            None => login_url = Some(text),
                        },
                        b"sso-v2-token-cookie-name" => match &mut token_cookie_name {
                            Some(v) => v.push_str(&text),
                            None => token_cookie_name = Some(text),
                        },
                        _ => {}
                    }
                }
            }
            Event::GeneralRef(r) => {
                let text = unescape_general_ref(&r)?;
                if stack.len() >= 2 && stack[stack.len() - 2].as_slice() == b"auth" {
                    match stack[stack.len() - 1].as_slice() {
                        b"title" => auth_title.push_str(&text),
                        b"message" => match &mut auth_message {
                            Some(msg) => msg.push_str(&text),
                            None => auth_message = Some(text),
                        },
                        b"error" => auth_error.push_str(&text),
                        b"sso-v2-login" => match &mut login_url {
                            Some(v) => v.push_str(&text),
                            None => login_url = Some(text),
                        },
                        b"sso-v2-token-cookie-name" => match &mut token_cookie_name {
                            Some(v) => v.push_str(&text),
                            None => token_cookie_name = Some(text),
                        },
                        _ => {}
                    }
                }
            }
            Event::End(e) => {
                let _ = e;
                stack.pop();
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    let auth_id = auth_id.ok_or(AppError::MissingField("auth.id"))?;
    let auth_message = auth_message
        .map(|s| s.trim().to_string())
        .ok_or(AppError::MissingField("auth.message"))?;
    let opaque_xml = opaque_xml.ok_or(AppError::MissingField("opaque"))?;
    let login_url = login_url
        .map(|s| s.trim().to_string())
        .ok_or(AppError::MissingField("auth.sso-v2-login"))?;
    let token_cookie_name = token_cookie_name
        .map(|s| s.trim().to_string())
        .ok_or(AppError::MissingField("auth.sso-v2-token-cookie-name"))?;

    Ok(AuthRequest {
        auth_id,
        auth_title: auth_title.trim().to_string(),
        auth_message,
        auth_error: auth_error.trim().to_string(),
        opaque_xml,
        login_url,
        token_cookie_name,
    })
}

fn parse_auth_complete_response(xml: &[u8]) -> Result<AuthComplete, AppError> {
    let mut reader = Reader::from_reader(xml);

    let mut buf = Vec::new();
    let mut stack: Vec<Vec<u8>> = Vec::new();

    let mut auth_id: Option<String> = None;
    let mut auth_message: Option<String> = None;
    let mut session_token: Option<String> = None;
    let mut server_cert_hash: Option<String> = None;

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => {
                let name = local_name(e.name().as_ref()).to_vec();
                if name.as_slice() == b"auth" {
                    for attr in e.attributes() {
                        let attr = attr?;
                        if local_name(attr.key.as_ref()) == b"id" {
                            auth_id = Some(attr.unescape_value()?.to_string());
                        }
                    }
                }
                stack.push(name);
            }
            Event::Text(t) => {
                let text = unescape_text(&t)?;
                if stack.len() >= 2 && stack[stack.len() - 2].as_slice() == b"auth" {
                    if stack[stack.len() - 1].as_slice() == b"message" {
                        match &mut auth_message {
                            Some(v) => v.push_str(&text),
                            None => auth_message = Some(text),
                        }
                    }
                } else if stack
                    .last()
                    .is_some_and(|n| n.as_slice() == b"session-token")
                {
                    match &mut session_token {
                        Some(v) => v.push_str(&text),
                        None => session_token = Some(text),
                    }
                } else if stack.len() >= 3
                    && stack[stack.len() - 3].as_slice() == b"config"
                    && stack[stack.len() - 2].as_slice() == b"vpn-base-config"
                    && stack[stack.len() - 1].as_slice() == b"server-cert-hash"
                {
                    match &mut server_cert_hash {
                        Some(v) => v.push_str(&text),
                        None => server_cert_hash = Some(text),
                    }
                }
            }
            Event::GeneralRef(r) => {
                let text = unescape_general_ref(&r)?;
                if stack.len() >= 2 && stack[stack.len() - 2].as_slice() == b"auth" {
                    if stack[stack.len() - 1].as_slice() == b"message" {
                        match &mut auth_message {
                            Some(v) => v.push_str(&text),
                            None => auth_message = Some(text),
                        }
                    }
                } else if stack
                    .last()
                    .is_some_and(|n| n.as_slice() == b"session-token")
                {
                    match &mut session_token {
                        Some(v) => v.push_str(&text),
                        None => session_token = Some(text),
                    }
                } else if stack.len() >= 3
                    && stack[stack.len() - 3].as_slice() == b"config"
                    && stack[stack.len() - 2].as_slice() == b"vpn-base-config"
                    && stack[stack.len() - 1].as_slice() == b"server-cert-hash"
                {
                    match &mut server_cert_hash {
                        Some(v) => v.push_str(&text),
                        None => server_cert_hash = Some(text),
                    }
                }
            }
            Event::End(_e) => {
                stack.pop();
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    Ok(AuthComplete {
        auth_id: auth_id.unwrap_or_default(),
        auth_message: auth_message.unwrap_or_default().trim().to_string(),
        session_token: session_token
            .map(|s| s.trim().to_string())
            .ok_or(AppError::MissingField("session-token"))?,
        server_cert_hash: server_cert_hash.map(|s| s.trim().to_string()).ok_or(
            AppError::MissingField("config.vpn-base-config.server-cert-hash"),
        )?,
    })
}

fn capture_subtree(reader: &mut Reader<&[u8]>, start: Event<'static>) -> Result<Vec<u8>, AppError> {
    let mut writer = quick_xml::Writer::new(Vec::new());
    let mut depth: usize = 0;

    match start {
        Event::Start(e) => {
            writer.write_event(Event::Start(e))?;
            depth = 1;
        }
        Event::Empty(e) => {
            writer.write_event(Event::Empty(e))?;
            return Ok(writer.into_inner());
        }
        _ => {}
    }

    let mut buf = Vec::new();
    while depth > 0 {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => {
                depth += 1;
                writer.write_event(Event::Start(e.into_owned()))?;
            }
            Event::Empty(e) => {
                writer.write_event(Event::Empty(e.into_owned()))?;
            }
            Event::End(e) => {
                writer.write_event(Event::End(e.into_owned()))?;
                depth = depth.saturating_sub(1);
            }
            Event::Text(e) => {
                writer.write_event(Event::Text(e.into_owned()))?;
            }
            Event::CData(e) => {
                writer.write_event(Event::CData(e.into_owned()))?;
            }
            Event::Comment(e) => {
                writer.write_event(Event::Comment(e.into_owned()))?;
            }
            Event::GeneralRef(e) => {
                writer.write_event(Event::GeneralRef(e.into_owned()))?;
            }
            Event::Eof => return Err(AppError::MissingField("opaque (unexpected EOF)")),
            _ => {}
        }
        buf.clear();
    }

    Ok(writer.into_inner())
}

fn unescape_text(text: &quick_xml::events::BytesText<'_>) -> Result<String, AppError> {
    let raw = std::str::from_utf8(text)?;
    Ok(quick_xml::escape::unescape(raw)?.into_owned())
}

fn unescape_general_ref(general_ref: &quick_xml::events::BytesRef<'_>) -> Result<String, AppError> {
    if let Some(ch) = general_ref.resolve_char_ref()? {
        return Ok(ch.to_string());
    }
    let entity = std::str::from_utf8(general_ref)?;
    if let Some(value) = quick_xml::escape::resolve_xml_entity(entity) {
        return Ok(value.to_string());
    }
    Err(AppError::UnknownEntity(entity.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_profile_url_matches_openconnect_sso() {
        let hp = HostProfile::new("hostname".to_string(), "".to_string(), "".to_string()).unwrap();
        assert_eq!(hp.vpn_url(), "https://hostname");

        let hp =
            HostProfile::new("hostname".to_string(), "group".to_string(), "".to_string()).unwrap();
        assert_eq!(hp.vpn_url(), "https://hostname/group");

        let hp =
            HostProfile::new("hostname/group".to_string(), "".to_string(), "".to_string()).unwrap();
        assert_eq!(hp.vpn_url(), "https://hostname/group");

        let hp = HostProfile::new(
            "https://hostname".to_string(),
            "group".to_string(),
            "".to_string(),
        )
        .unwrap();
        assert_eq!(hp.vpn_url(), "https://hostname/group");

        let hp = HostProfile::new(
            "https://hostname:8443/group".to_string(),
            "".to_string(),
            "".to_string(),
        )
        .unwrap();
        assert_eq!(hp.vpn_url(), "https://hostname:8443/group");
    }

    #[test]
    fn parse_auth_request_response_extracts_fields() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
  <auth id="main">
    <title>Login</title>
    <message>a &amp; b</message>
    <sso-v2-login>https://idp.example.com/login</sso-v2-login>
    <sso-v2-login-final>https://vpn.example.com/sso/final</sso-v2-login-final>
    <sso-v2-token-cookie-name>webvpn</sso-v2-token-cookie-name>
  </auth>
  <opaque>
    <param name="foo">bar</param>
  </opaque>
</config-auth>"#;

        let req = parse_auth_request_response(xml).unwrap();
        assert_eq!(req.auth_id, "main");
        assert_eq!(req.auth_title, "Login");
        assert_eq!(req.auth_message, "a & b");
        assert_eq!(req.login_url, "https://idp.example.com/login");
        assert_eq!(req.token_cookie_name, "webvpn");

        let opaque = std::str::from_utf8(&req.opaque_xml).unwrap();
        assert!(opaque.contains("<opaque"));
        assert!(opaque.contains("param"));
    }

    #[test]
    fn parse_auth_complete_response_extracts_fields() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
  <auth id="success">
    <message>OK</message>
  </auth>
  <session-token>COOKIE</session-token>
  <config>
    <vpn-base-config>
      <server-cert-hash>sha256:deadbeef</server-cert-hash>
    </vpn-base-config>
  </config>
</config-auth>"#;

        let resp = parse_auth_complete_response(xml).unwrap();
        assert_eq!(resp.auth_id, "success");
        assert_eq!(resp.auth_message, "OK");
        assert_eq!(resp.session_token, "COOKIE");
        assert_eq!(resp.server_cert_hash, "sha256:deadbeef");
    }
}

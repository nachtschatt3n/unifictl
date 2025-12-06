// unifictl - CLI for UniFi Site Manager API
// Copyright (C) 2024 Mathias Uhl <mathiasuhl@gmx.de>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use crate::client::ResponseData;
use anyhow::{Context, Result, anyhow};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, HeaderValue, USER_AGENT};
use reqwest::{Method, StatusCode, Url};
use serde::Serialize;
use std::sync::OnceLock;
use std::time::Duration;

#[derive(Debug)]
pub struct LocalClient {
    base_url: Url,
    http: Client,
    username: String,
    password: String,
    site: String,
    logged_in: bool,
    is_legacy: bool,
    csrf: Option<String>,
}

static UA: OnceLock<HeaderValue> = OnceLock::new();

impl LocalClient {
    pub fn new(
        url: &str,
        username: &str,
        password: &str,
        site: &str,
        verify_tls: bool,
    ) -> Result<Self> {
        let base_url = Url::parse(url).context("parsing local controller url")?;
        let user_agent = UA.get_or_init(|| HeaderValue::from_static("unifictl-local/0.1"));
        let http = Client::builder()
            .cookie_store(true)
            .danger_accept_invalid_certs(!verify_tls)
            .user_agent(user_agent.clone())
            .timeout(Duration::from_secs(10))         // Total request timeout
            .connect_timeout(Duration::from_secs(5))  // Connection timeout
            .build()
            .context("building local HTTP client")?;

        Ok(Self {
            base_url,
            http,
            username: username.to_string(),
            password: password.to_string(),
            site: site.to_string(),
            logged_in: false,
            is_legacy: false,
            csrf: None,
        })
    }

    pub fn list_sites(&mut self) -> Result<ResponseData> {
        self.get(false, false, "self/sites", Option::<&()>::None)
    }

    pub fn list_devices(&mut self) -> Result<ResponseData> {
        self.get(true, false, "stat/device", Option::<&()>::None)
    }

    pub fn device_stats(&mut self, mac: &str) -> Result<ResponseData> {
        let mut resp = self.list_devices()?;
        if let Some(mut json) = resp.json.clone() {
            if let Some(arr) = json.get_mut("data").and_then(|d| d.as_array_mut()) {
                arr.retain(|item| item.get("mac").and_then(|m| m.as_str()) == Some(mac));
                resp.body = serde_json::to_string(&json).unwrap_or(resp.body);
                resp.json = Some(json);
            }
        }
        Ok(resp)
    }

    pub fn device_action(&mut self, mac: &str, cmd: &str) -> Result<ResponseData> {
        let body = serde_json::json!({ "cmd": cmd, "mac": mac });
        self.post(true, "cmd/devmgr", Some(&body))
    }

    pub fn client_action(&mut self, mac: &str, cmd: &str) -> Result<ResponseData> {
        let body = serde_json::json!({ "cmd": cmd, "mac": mac });
        self.post(true, "cmd/stamgr", Some(&body))
    }

    pub fn list_clients(&mut self) -> Result<ResponseData> {
        self.get(true, false, "stat/sta", Option::<&()>::None)
    }

    pub fn list_health(&mut self) -> Result<ResponseData> {
        self.get(true, false, "stat/health", Option::<&()>::None)
    }

    pub fn list_events(&mut self) -> Result<ResponseData> {
        self.get(true, false, "stat/event", Option::<&()>::None)
    }

    pub fn dpi(&mut self) -> Result<ResponseData> {
        self.get(true, true, "stat/dpi", Option::<&()>::None)
    }

    pub fn traffic(&mut self) -> Result<ResponseData> {
        self.get(true, true, "stat/traffic", Option::<&()>::None)
    }

    pub fn security_settings(&mut self) -> Result<ResponseData> {
        self.get(true, true, "rest/setting/security", Option::<&()>::None)
    }

    pub fn networks(&mut self) -> Result<ResponseData> {
        self.get(true, true, "rest/networkconf", Option::<&()>::None)
    }

    pub fn create_network(&mut self, payload: &serde_json::Value) -> Result<ResponseData> {
        self.post(true, "rest/networkconf", Some(payload))
    }

    pub fn update_network(
        &mut self,
        id: &str,
        payload: &serde_json::Value,
    ) -> Result<ResponseData> {
        self.put(true, &format!("rest/networkconf/{id}"), Some(payload))
    }

    pub fn delete_network(&mut self, id: &str) -> Result<ResponseData> {
        self.delete(true, &format!("rest/networkconf/{id}"))
    }

    pub fn wlans(&mut self) -> Result<ResponseData> {
        self.get(true, true, "rest/wlanconf", Option::<&()>::None)
    }

    pub fn create_wlan(&mut self, payload: &serde_json::Value) -> Result<ResponseData> {
        self.post(true, "rest/wlanconf", Some(payload))
    }

    pub fn update_wlan(&mut self, id: &str, payload: &serde_json::Value) -> Result<ResponseData> {
        self.put(true, &format!("rest/wlanconf/{id}"), Some(payload))
    }

    pub fn delete_wlan(&mut self, id: &str) -> Result<ResponseData> {
        self.delete(true, &format!("rest/wlanconf/{id}"))
    }

    pub fn port_profiles(&mut self) -> Result<ResponseData> {
        self.get(true, true, "rest/portconf", Option::<&()>::None)
    }

    pub fn firewall_rules(&mut self) -> Result<ResponseData> {
        self.get(true, true, "rest/firewallrule", Option::<&()>::None)
    }

    pub fn create_firewall_rule(&mut self, payload: &serde_json::Value) -> Result<ResponseData> {
        self.post(true, "rest/firewallrule", Some(payload))
    }

    pub fn update_firewall_rule(
        &mut self,
        id: &str,
        payload: &serde_json::Value,
    ) -> Result<ResponseData> {
        self.put(true, &format!("rest/firewallrule/{id}"), Some(payload))
    }

    pub fn delete_firewall_rule(&mut self, id: &str) -> Result<ResponseData> {
        self.delete(true, &format!("rest/firewallrule/{id}"))
    }

    pub fn firewall_groups(&mut self) -> Result<ResponseData> {
        self.get(true, true, "rest/firewallgroup", Option::<&()>::None)
    }

    pub fn create_firewall_group(&mut self, payload: &serde_json::Value) -> Result<ResponseData> {
        self.post(true, "rest/firewallgroup", Some(payload))
    }

    pub fn update_firewall_group(
        &mut self,
        id: &str,
        payload: &serde_json::Value,
    ) -> Result<ResponseData> {
        self.put(true, &format!("rest/firewallgroup/{id}"), Some(payload))
    }

    pub fn delete_firewall_group(&mut self, id: &str) -> Result<ResponseData> {
        self.delete(true, &format!("rest/firewallgroup/{id}"))
    }

    fn get<Q: Serialize + ?Sized>(
        &mut self,
        site_scoped: bool,
        fallback_global: bool,
        path: &str,
        query: Option<&Q>,
    ) -> Result<ResponseData> {
        self.request(
            Method::GET,
            site_scoped,
            fallback_global,
            path,
            query,
            Option::<&()>::None,
        )
    }

    fn post<Q: Serialize + ?Sized>(
        &mut self,
        site_scoped: bool,
        path: &str,
        body: Option<&Q>,
    ) -> Result<ResponseData> {
        self.request(
            Method::POST,
            site_scoped,
            false,
            path,
            Option::<&()>::None,
            body,
        )
    }

    fn put<Q: Serialize + ?Sized>(
        &mut self,
        site_scoped: bool,
        path: &str,
        body: Option<&Q>,
    ) -> Result<ResponseData> {
        self.request(
            Method::PUT,
            site_scoped,
            false,
            path,
            Option::<&()>::None,
            body,
        )
    }

    fn delete(&mut self, site_scoped: bool, path: &str) -> Result<ResponseData> {
        self.request::<(), ()>(Method::DELETE, site_scoped, false, path, None, None::<&()>)
    }

    fn request<Q: Serialize + ?Sized, B: Serialize + ?Sized>(
        &mut self,
        method: Method,
        site_scoped: bool,
        fallback_global: bool,
        path: &str,
        query: Option<&Q>,
        body: Option<&B>,
    ) -> Result<ResponseData> {
        self.ensure_login()?;
        let urls = self.build_urls(site_scoped, fallback_global, path)?;

        let send_once = |mut r: reqwest::blocking::RequestBuilder, csrf: &Option<String>| {
            if let Some(token) = csrf {
                r = r.header("X-CSRF-Token", token);
            }
            r.send()
        };

        let mut last_err: Option<anyhow::Error> = None;

        for url in urls {
            let mut req = self
                .http
                .request(method.clone(), url.clone())
                .header(ACCEPT, HeaderValue::from_static("application/json"))
                .header(
                    USER_AGENT,
                    UA.get_or_init(|| HeaderValue::from_static("unifictl-local/0.1"))
                        .clone(),
                );

            if let Some(q) = query {
                req = req.query(q);
            }
            if let Some(b) = body {
                req = req.json(b);
            }

            let mut resp = send_once(req.try_clone().unwrap_or(req), &self.csrf);

            // If 401, relogin and retry once on same URL
            if let Ok(r) = &resp {
                if r.status() == StatusCode::UNAUTHORIZED {
                    self.force_relogin()?;
                    let mut retry = self
                        .http
                        .request(method.clone(), url.clone())
                        .header(ACCEPT, HeaderValue::from_static("application/json"))
                        .header(
                            USER_AGENT,
                            UA.get_or_init(|| HeaderValue::from_static("unifictl-local/0.1"))
                                .clone(),
                        );
                    if let Some(q) = query {
                        retry = retry.query(q);
                    }
                    if let Some(b) = body {
                        retry = retry.json(b);
                    }
                    resp = send_once(retry, &self.csrf);
                }
            }

            match resp {
                Ok(res) => {
                    let status = res.status();
                    if !status.is_success() {
                        let body = res.text().unwrap_or_default();
                        let msg = Self::format_error_message(
                            &method,
                            path,
                            status,
                            &body,
                            &url.to_string(),
                        );
                        last_err = Some(anyhow!(msg));
                        continue;
                    }
                    let status = status.as_u16();
                    let text = res.text().context("reading response body")?;
                    let json = serde_json::from_str(&text).ok();
                    return Ok(ResponseData {
                        status,
                        body: text,
                        json,
                    });
                }
                Err(err) => {
                    last_err = Some(anyhow!("{} at {}", err, url));
                    continue;
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("request failed")))
    }

    fn ensure_login(&mut self) -> Result<()> {
        if self.logged_in {
            return Ok(());
        }
        self.login()
    }

    fn force_relogin(&mut self) -> Result<()> {
        self.logged_in = false;
        self.csrf = None;
        self.login()
    }

    fn login(&mut self) -> Result<()> {
        let creds = serde_json::json!({
            "username": self.username,
            "password": self.password,
            "remember": true,
            "strict": true,
        });

        // Preserve the original port explicitly
        let original_port = self.base_url.port();
        let mut bases = vec![self.base_url.clone()];
        
        // Only try port 443 alternative if we're using 8443
        if original_port == Some(8443) {
            if let Ok(mut alt) = Url::parse(&self.base_url.to_string()) {
                let _ = alt.set_port(Some(443));
                bases.push(alt);
            }
        }

        let auth_paths = [
            "api/auth/login",
            "proxy/network/api/auth/login",
            "auth/login",
            "api/login",
        ];

        let mut last_err: Option<anyhow::Error> = None;
        for base in bases {
            for path in auth_paths.iter() {
                let url = match base.join(path) {
                    Ok(u) => u,
                    Err(e) => {
                        last_err = Some(e.into());
                        continue;
                    }
                };
                let os_resp = self.request_login(&url, &creds);
                match os_resp {
                    Ok(resp) => {
                        self.base_url = base.clone();
                        self.is_legacy = path.contains("api/login");
                        self.logged_in = true;
                        if let Some(token) = extract_csrf(&resp) {
                            self.csrf = Some(token);
                        }
                        return Ok(());
                    }
                    Err(err) => {
                        last_err = Some(anyhow::anyhow!("login failed at {}: {}", url, err));
                        continue;
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("login failed")))
    }

    fn request_login(
        &self,
        url: &Url,
        creds: &serde_json::Value,
    ) -> Result<reqwest::blocking::Response> {
        self.http
            .post(url.clone())
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .header(
                "X-Requested-With",
                HeaderValue::from_static("XMLHttpRequest"),
            )
            .json(creds)
            .send()
            .and_then(|r| r.error_for_status())
            .context("sending login request")
    }

    fn format_error_message(
        method: &Method,
        path: &str,
        status: StatusCode,
        body: &str,
        url: &str,
    ) -> String {
        let operation = Self::infer_operation(method, path);
        
        if status == StatusCode::UNAUTHORIZED {
            return format!(
                "Authentication failed (401) at {}\n\nPossible causes:\n  • Session expired - credentials may need to be refreshed\n  • Invalid username or password\n  • Controller requires re-authentication\n\nTry:\n  unifictl validate --local-only",
                url
            );
        }

        if status == StatusCode::BAD_REQUEST {
            let mut msg = format!("Failed to {}: HTTP 400", operation);
            
            // Try to parse error message from JSON response
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                if let Some(err_msg) = json.get("meta").and_then(|m| m.get("msg")).and_then(|m| m.as_str()) {
                    msg.push_str(&format!("\n\nError: {}", err_msg));
                } else if let Some(err_msg) = json.get("error").and_then(|e| e.as_str()) {
                    msg.push_str(&format!("\n\nError: {}", err_msg));
                }
            }
            
            // Add context-specific guidance
            msg.push_str(&Self::get_operation_guidance(path, operation));
            
            return msg;
        }

        if status == StatusCode::NOT_FOUND {
            return format!(
                "Resource not found (404) at {}\n\nPossible causes:\n  • The {} does not exist\n  • Invalid ID or identifier\n  • Resource was deleted\n\nTry:\n  unifictl local {} -o json",
                url,
                operation.replace("create", "resource").replace("update", "resource").replace("delete", "resource"),
                Self::get_list_command(path)
            );
        }

        if status == StatusCode::CONFLICT {
            return format!(
                "Conflict (409) at {}\n\nPossible causes:\n  • Resource already exists\n  • Conflicting configuration\n  • Duplicate name or identifier\n\nTry:\n  unifictl local {} -o json",
                url,
                Self::get_list_command(path)
            );
        }

        // Generic error with body
        format!("HTTP {} at {}\n\nResponse: {}", status, url, 
            if body.len() > 200 { format!("{}...", &body[..200]) } else { body.to_string() })
    }

    fn infer_operation(method: &Method, _path: &str) -> &'static str {
        match *method {
            Method::POST => "create",
            Method::PUT => "update",
            Method::DELETE => "delete",
            Method::GET => "fetch",
            _ => "operate on",
        }
    }

    fn get_operation_guidance(path: &str, _operation: &str) -> &'static str {
        if path.contains("networkconf") {
            return "\n\nPossible causes for network operations:\n  • VLAN ID already in use\n  • Invalid subnet format (expected: 192.168.1.0/24)\n  • Conflicting DHCP range\n  • Invalid network name\n\nCheck existing networks:\n  unifictl local networks -o json";
        }
        if path.contains("wlanconf") {
            return "\n\nPossible causes for WLAN operations:\n  • SSID already exists\n  • Invalid password (must be 8+ characters for WPA2)\n  • Invalid security settings\n\nCheck existing WLANs:\n  unifictl local wlans -o json";
        }
        if path.contains("firewallrule") {
            return "\n\nPossible causes for firewall rule operations:\n  • Invalid action (must be: accept, drop, reject)\n  • Invalid firewall group IDs\n  • Rule index conflict\n\nCheck existing rules:\n  unifictl local firewall-rules -o json";
        }
        if path.contains("firewallgroup") {
            return "\n\nPossible causes for firewall group operations:\n  • Invalid group type\n  • Invalid member addresses\n  • Duplicate group name\n\nCheck existing groups:\n  unifictl local firewall-groups -o json";
        }
        ""
    }

    fn get_list_command(path: &str) -> &'static str {
        if path.contains("networkconf") {
            "networks"
        } else if path.contains("wlanconf") {
            "wlans"
        } else if path.contains("firewallrule") {
            "firewall-rules"
        } else if path.contains("firewallgroup") {
            "firewall-groups"
        } else if path.contains("device") {
            "devices"
        } else if path.contains("sta") {
            "clients"
        } else {
            "sites"
        }
    }

    fn build_urls(&self, site_scoped: bool, fallback_global: bool, path: &str) -> Result<Vec<Url>> {
        let cleaned = path.trim_start_matches('/');
        let mut urls = Vec::new();

        if self.is_legacy {
            if site_scoped {
                urls.push(
                    self.base_url
                        .join(&format!("api/s/{}/{}", self.site, cleaned))?,
                );
                if fallback_global {
                    urls.push(self.base_url.join(&format!("api/{}", cleaned))?);
                }
            } else {
                urls.push(self.base_url.join(&format!("api/{}", cleaned))?);
            }
        } else {
            if site_scoped {
                urls.push(
                    self.base_url
                        .join(&format!("proxy/network/api/s/{}/{}", self.site, cleaned))?,
                );
                urls.push(self.base_url.join(&format!(
                    "proxy/network/v2/api/site/{}/{}",
                    self.site, cleaned
                ))?);
                urls.push(
                    self.base_url
                        .join(&format!("proxy/network/v2/api/s/{}/{}", self.site, cleaned))?,
                );
                if fallback_global {
                    urls.push(
                        self.base_url
                            .join(&format!("proxy/network/api/{}", cleaned))?,
                    );
                    urls.push(
                        self.base_url
                            .join(&format!("proxy/network/v2/api/{}", cleaned))?,
                    );
                }
                // Legacy path as last resort
                urls.push(
                    self.base_url
                        .join(&format!("api/s/{}/{}", self.site, cleaned))?,
                );
            } else {
                urls.push(
                    self.base_url
                        .join(&format!("proxy/network/api/{}", cleaned))?,
                );
                urls.push(
                    self.base_url
                        .join(&format!("proxy/network/v2/api/{}", cleaned))?,
                );
                urls.push(self.base_url.join(&format!("api/{}", cleaned))?);
            }
        }
        Ok(urls)
    }
}

fn extract_csrf(resp: &reqwest::blocking::Response) -> Option<String> {
    if let Some(header) = resp.headers().get("X-CSRF-Token") {
        return header.to_str().ok().map(|s| s.to_string());
    }
    if let Some(cookie) = resp.cookies().find(|c| c.name() == "csrf_token") {
        return Some(cookie.value().to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;
    use serde_json::json;
    use std::collections::HashSet;

    #[test]
    fn logs_in_unifi_os_and_sends_csrf() {
        let server = MockServer::start();
        let login = server.mock(|when, then| {
            when.method(POST)
                .path("/api/auth/login")
                .json_body(
                    json!({"username": "u", "password": "p", "remember": true, "strict": true}),
                )
                .header("X-Requested-With", "XMLHttpRequest");
            then.status(200)
                .header("X-CSRF-Token", "abc123")
                .json_body(json!({"ok": true}));
        });
        let devices = server.mock(|when, then| {
            when.method(GET)
                .path("/proxy/network/api/s/default/stat/device")
                .header("X-CSRF-Token", "abc123");
            then.status(200).json_body(json!({"data": []}));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let resp = client.list_devices().unwrap();
        login.assert();
        devices.assert();
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn falls_back_to_legacy_paths() {
        let server = MockServer::start();
        let legacy_login = server.mock(|when, then| {
            when.method(POST)
                .path("/api/login")
                .json_body(
                    json!({"username": "u", "password": "p", "remember": true, "strict": true}),
                )
                .header("X-Requested-With", "XMLHttpRequest");
            then.status(200).json_body(json!({"logged_in": true}));
        });
        let sites = server.mock(|when, then| {
            when.method(GET).path("/api/self/sites");
            then.status(200)
                .json_body(json!({"data": [{"name": "default"}]}));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", false).unwrap();
        let resp = client.list_sites().unwrap();

        legacy_login.assert();
        sites.assert();
        assert_eq!(resp.status, 200);
        assert!(resp.json.unwrap()["data"].is_array());
    }

    #[test]
    fn build_urls_includes_v2_paths_and_global() {
        let client =
            LocalClient::new("https://example.test:8443/", "u", "p", "default", true).unwrap();
        let urls = client
            .build_urls(true, true, "rest/networkconf")
            .unwrap()
            .iter()
            .map(|u| u.path().to_string())
            .collect::<HashSet<_>>();

        assert!(urls.contains("/proxy/network/api/s/default/rest/networkconf"));
        assert!(urls.contains("/proxy/network/v2/api/site/default/rest/networkconf"));
        assert!(urls.contains("/proxy/network/v2/api/s/default/rest/networkconf"));
        assert!(urls.contains("/proxy/network/api/rest/networkconf"));
        assert!(urls.contains("/api/s/default/rest/networkconf"));
    }

    #[test]
    fn device_stats_filters_to_mac() {
        let server = MockServer::start();
        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(200)
                .header("X-CSRF-Token", "abc123")
                .json_body(json!({"ok": true}));
        });
        let devices = server.mock(|when, then| {
            when.method(GET)
                .path("/proxy/network/api/s/default/stat/device");
            then.status(200).json_body(json!({"data": [
                {"mac": "aa:bb", "name": "match"},
                {"mac": "cc:dd", "name": "other"}
            ]}));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let resp = client.device_stats("aa:bb").unwrap();
        login.assert();
        devices.assert();
        let data = resp.json.unwrap()["data"].as_array().unwrap().clone();
        assert_eq!(data.len(), 1);
        assert_eq!(data[0]["mac"], "aa:bb");
    }

    #[test]
    fn login_preserves_port_8443() {
        // Test that URLs with port 8443 preserve the port through login
        let url_with_port = "https://192.168.55.1:8443";
        let client = LocalClient::new(url_with_port, "u", "p", "default", false);
        assert!(client.is_ok());
        let client = client.unwrap();
        // Verify port is preserved when parsing URL
        assert_eq!(client.base_url.port(), Some(8443));
        assert_eq!(client.base_url.host_str(), Some("192.168.55.1"));
        
        // Test URL join preserves port
        let joined = client.base_url.join("api/login").unwrap();
        assert_eq!(joined.port(), Some(8443));
        assert!(joined.to_string().contains(":8443"));
    }

    #[test]
    fn format_error_message_provides_actionable_guidance() {
        use reqwest::{Method, StatusCode};
        
        // Test 401 error
        let msg = LocalClient::format_error_message(
            &Method::GET,
            "rest/networkconf",
            StatusCode::UNAUTHORIZED,
            "",
            "https://example.com/api",
        );
        assert!(msg.contains("Authentication failed"));
        assert!(msg.contains("Possible causes"));
        assert!(msg.contains("unifictl validate"));

        // Test 400 error with network path
        let msg = LocalClient::format_error_message(
            &Method::POST,
            "rest/networkconf",
            StatusCode::BAD_REQUEST,
            r#"{"meta":{"msg":"VLAN already in use"}}"#,
            "https://example.com/api",
        );
        assert!(msg.contains("Failed to create"));
        assert!(msg.contains("VLAN already in use"));
        assert!(msg.contains("unifictl local networks"));

        // Test 404 error
        let msg = LocalClient::format_error_message(
            &Method::DELETE,
            "rest/networkconf",
            StatusCode::NOT_FOUND,
            "",
            "https://example.com/api",
        );
        assert!(msg.contains("Resource not found"));
        assert!(msg.contains("Possible causes"));
        assert!(msg.contains("unifictl local networks"));

        // Test 409 error
        let msg = LocalClient::format_error_message(
            &Method::POST,
            "rest/wlanconf",
            StatusCode::CONFLICT,
            "",
            "https://example.com/api",
        );
        assert!(msg.contains("Conflict"));
        assert!(msg.contains("Resource already exists"));
    }
}

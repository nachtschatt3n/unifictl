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
            .timeout(Duration::from_secs(10)) // Total request timeout
            .connect_timeout(Duration::from_secs(5)) // Connection timeout
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
        if let Some(mut json) = resp.json.clone()
            && let Some(arr) = json.get_mut("data").and_then(|d| d.as_array_mut())
        {
            arr.retain(|item| item.get("mac").and_then(|m| m.as_str()) == Some(mac));
            resp.body = serde_json::to_string(&json).unwrap_or(resp.body);
            resp.json = Some(json);
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

    // Clients (v2 API)
    pub fn clients_v2_active(&mut self) -> Result<ResponseData> {
        self.get(true, false, "clients/active", Option::<&()>::None)
    }

    pub fn clients_v2_history(&mut self) -> Result<ResponseData> {
        self.get(true, false, "clients/history", Option::<&()>::None)
    }

    pub fn update_client_metadata(
        &mut self,
        _mac: &str,
        payload: &serde_json::Value,
    ) -> Result<ResponseData> {
        // Note: MAC address should be included in the payload JSON
        self.post(true, "clients/metadata", Some(payload))
    }

    // System Log (v2 API)
    pub fn system_log_settings(&mut self) -> Result<ResponseData> {
        self.get(true, false, "system-log/setting", Option::<&()>::None)
    }

    pub fn system_log_all(&mut self, payload: Option<&serde_json::Value>) -> Result<ResponseData> {
        self.post(true, "system-log/all", payload)
    }

    pub fn system_log_count(
        &mut self,
        payload: Option<&serde_json::Value>,
    ) -> Result<ResponseData> {
        // POST endpoints require a payload, use empty object if None
        let empty = serde_json::json!({});
        let payload = payload.unwrap_or(&empty);
        self.post(true, "system-log/count", Some(payload))
    }

    pub fn system_log_critical(
        &mut self,
        payload: Option<&serde_json::Value>,
    ) -> Result<ResponseData> {
        self.post(true, "system-log/critical", payload)
    }

    pub fn system_log_device_alert(
        &mut self,
        payload: Option<&serde_json::Value>,
    ) -> Result<ResponseData> {
        self.post(true, "system-log/device-alert", payload)
    }

    // WiFi/Radio (v2 API)
    pub fn wifi_connectivity(&mut self) -> Result<ResponseData> {
        self.get(true, false, "wifi-connectivity", Option::<&()>::None)
    }

    pub fn wifi_stats_details(&mut self, query: &serde_json::Value) -> Result<ResponseData> {
        // Query parameters: start, end, apMac (required)
        self.get(true, false, "wifi-stats/details", Some(query))
    }

    pub fn wifi_stats_radios(&mut self, query: &serde_json::Value) -> Result<ResponseData> {
        // Query parameters: start, end (required)
        self.get(true, false, "wifi-stats/radios", Some(query))
    }

    pub fn radio_ai_isolation_matrix(&mut self) -> Result<ResponseData> {
        self.get(
            true,
            false,
            "radio-ai/isolation-matrix",
            Option::<&()>::None,
        )
    }

    pub fn wifiman(&mut self) -> Result<ResponseData> {
        self.get(true, false, "wifiman", Option::<&()>::None)
    }

    pub fn wlan_enriched_config(&mut self) -> Result<ResponseData> {
        self.get(
            true,
            false,
            "wlan/enriched-configuration",
            Option::<&()>::None,
        )
    }

    // Traffic/Flow (v2 API)
    pub fn traffic_stats(&mut self, query: &serde_json::Value) -> Result<ResponseData> {
        // Query parameters: start, end, includeUnidentified (required)
        self.get(true, false, "traffic", Some(query))
    }

    pub fn traffic_flow_latest(&mut self, query: &serde_json::Value) -> Result<ResponseData> {
        // Query parameters: period (DAY/MONTH), top (number) (required)
        self.get(true, false, "traffic-flow-latest-statistics", Some(query))
    }

    pub fn traffic_flows_filter_data(&mut self) -> Result<ResponseData> {
        self.get(
            true,
            false,
            "traffic-flows/filter-data",
            Option::<&()>::None,
        )
    }

    pub fn traffic_routes(&mut self) -> Result<ResponseData> {
        self.get(true, false, "trafficroutes", Option::<&()>::None)
    }

    pub fn traffic_rules(&mut self) -> Result<ResponseData> {
        self.get(true, false, "trafficrules", Option::<&()>::None)
    }

    pub fn app_traffic_rate(
        &mut self,
        payload: &serde_json::Value,
        query: &serde_json::Value,
    ) -> Result<ResponseData> {
        // POST endpoints require a payload and query parameters: start, end, includeUnidentified (all required)
        self.post_with_query(true, "app-traffic-rate", Some(query), Some(payload))
    }

    pub fn traffic_flows_query(
        &mut self,
        payload: Option<&serde_json::Value>,
    ) -> Result<ResponseData> {
        // POST endpoints require a payload, use empty object if None
        let empty = serde_json::json!({});
        let payload = payload.unwrap_or(&empty);
        self.post(true, "traffic-flows", Some(payload))
    }

    // Statistics (v1 API)
    pub fn stat_ccode(&mut self) -> Result<ResponseData> {
        self.get(true, false, "stat/ccode", Option::<&()>::None)
    }

    pub fn stat_current_channel(&mut self) -> Result<ResponseData> {
        self.get(true, false, "stat/current-channel", Option::<&()>::None)
    }

    pub fn stat_device_basic(&mut self) -> Result<ResponseData> {
        self.get(true, false, "stat/device-basic", Option::<&()>::None)
    }

    pub fn stat_guest(&mut self) -> Result<ResponseData> {
        self.get(true, false, "stat/guest", Option::<&()>::None)
    }

    pub fn stat_rogueap(&mut self) -> Result<ResponseData> {
        self.get(true, false, "stat/rogueap", Option::<&()>::None)
    }

    pub fn stat_sdn(&mut self) -> Result<ResponseData> {
        self.get(true, false, "stat/sdn", Option::<&()>::None)
    }

    pub fn stat_spectrum_scan(&mut self, mac: &str) -> Result<ResponseData> {
        self.get(
            true,
            false,
            &format!("stat/spectrum-scan/{mac}"),
            Option::<&()>::None,
        )
    }

    pub fn stat_report_5min_ap(
        &mut self,
        payload: Option<&serde_json::Value>,
    ) -> Result<ResponseData> {
        self.post(true, "stat/report/5minutes.ap", payload)
    }

    // Ports (v2 API)
    pub fn ports_anomalies(&mut self) -> Result<ResponseData> {
        self.get(true, false, "ports/port-anomalies", Option::<&()>::None)
    }

    pub fn ports_mac_tables(
        &mut self,
        payload: Option<&serde_json::Value>,
    ) -> Result<ResponseData> {
        // POST endpoints require a payload, use empty object if None
        let empty = serde_json::json!({});
        let payload = payload.unwrap_or(&empty);
        self.post(true, "ports/mac-tables", Some(payload))
    }

    pub fn list_health(&mut self) -> Result<ResponseData> {
        self.get(true, false, "stat/health", Option::<&()>::None)
    }

    pub fn vpn_health(&mut self) -> Result<ResponseData> {
        let mut resp = self.list_health()?;
        if let Some(mut json) = resp.json.clone() {
            if let Some(arr) = json.get_mut("data").and_then(|d| d.as_array_mut()) {
                arr.retain(|item| {
                    item.get("subsystem")
                        .and_then(|v| v.as_str())
                        .map(|s| s.eq_ignore_ascii_case("vpn"))
                        .unwrap_or(false)
                });
            }
            resp.body = serde_json::to_string(&json).unwrap_or_else(|_| resp.body.clone());
            resp.json = Some(json);
        }
        Ok(resp)
    }

    pub fn list_events(&mut self) -> Result<ResponseData> {
        self.get(true, false, "stat/event", Option::<&()>::None)
    }

    pub fn dpi(&mut self) -> Result<ResponseData> {
        self.get(true, true, "stat/dpi", Option::<&()>::None)
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

    pub fn policy_tables(&mut self) -> Result<ResponseData> {
        self.get(true, true, "rest/routing", Option::<&()>::None)
    }

    pub fn create_policy_table(&mut self, payload: &serde_json::Value) -> Result<ResponseData> {
        self.post(true, "rest/routing", Some(payload))
    }

    pub fn update_policy_table(
        &mut self,
        id: &str,
        payload: &serde_json::Value,
    ) -> Result<ResponseData> {
        self.put(true, &format!("rest/routing/{id}"), Some(payload))
    }

    pub fn delete_policy_table(&mut self, id: &str) -> Result<ResponseData> {
        self.delete(true, &format!("rest/routing/{id}"))
    }

    pub fn zones(&mut self) -> Result<ResponseData> {
        // Use v2 API endpoint: /proxy/network/v2/api/site/{site}/firewall/zone
        // build_urls() will add the "v2/api/site/{site}/" prefix
        self.get(true, false, "firewall/zone", Option::<&()>::None)
    }

    pub fn create_zone(&mut self, payload: &serde_json::Value) -> Result<ResponseData> {
        self.post(true, "firewall/zone", Some(payload))
    }

    pub fn update_zone(&mut self, id: &str, payload: &serde_json::Value) -> Result<ResponseData> {
        self.put(true, &format!("firewall/zone/{id}"), Some(payload))
    }

    pub fn delete_zone(&mut self, id: &str) -> Result<ResponseData> {
        self.delete(true, &format!("firewall/zone/{id}"))
    }

    pub fn objects(&mut self) -> Result<ResponseData> {
        // Use v2 API endpoint: /proxy/network/v2/api/site/{site}/object-oriented-network-configs
        self.get(
            true,
            false,
            "object-oriented-network-configs",
            Option::<&()>::None,
        )
    }

    pub fn create_object(&mut self, payload: &serde_json::Value) -> Result<ResponseData> {
        self.post(true, "object-oriented-network-configs", Some(payload))
    }

    pub fn update_object(&mut self, id: &str, payload: &serde_json::Value) -> Result<ResponseData> {
        self.put(
            true,
            &format!("object-oriented-network-configs/{id}"),
            Some(payload),
        )
    }

    pub fn delete_object(&mut self, id: &str) -> Result<ResponseData> {
        self.delete(true, &format!("object-oriented-network-configs/{id}"))
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
        self.post_with_query(site_scoped, path, Option::<&()>::None, body)
    }

    fn post_with_query<Q: Serialize + ?Sized, B: Serialize + ?Sized>(
        &mut self,
        site_scoped: bool,
        path: &str,
        query: Option<&Q>,
        body: Option<&B>,
    ) -> Result<ResponseData> {
        self.request(Method::POST, site_scoped, false, path, query, body)
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
            if let Ok(r) = &resp
                && r.status() == StatusCode::UNAUTHORIZED
            {
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

            match resp {
                Ok(res) => {
                    let status = res.status();
                    if !status.is_success() {
                        let body = res.text().unwrap_or_default();
                        let msg =
                            Self::format_error_message(&method, path, status, &body, url.as_str());
                        last_err = Some(anyhow!(msg));
                        continue;
                    }

                    let status = status.as_u16();
                    let text = res.text().context("reading response body")?;

                    // Validate that the response is actually JSON, not HTML
                    // If parsing fails and response looks like HTML, try next URL
                    let json = serde_json::from_str(&text).ok();
                    if json.is_none() && text.trim_start().starts_with("<!doctype") {
                        last_err = Some(anyhow!("received HTML instead of JSON at {}", url));
                        continue;
                    }

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
        if original_port == Some(8443)
            && let Ok(mut alt) = Url::parse(self.base_url.as_str())
        {
            let _ = alt.set_port(Some(443));
            bases.push(alt);
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
        url: impl AsRef<str>,
    ) -> String {
        let operation = Self::infer_operation(method, path);
        let url_str = url.as_ref();

        if status == StatusCode::UNAUTHORIZED {
            return format!(
                "Authentication failed (401) at {}\n\nPossible causes:\n  • Session expired - credentials may need to be refreshed\n  • Invalid username or password\n  • Controller requires re-authentication\n\nTry:\n  unifictl validate --local-only",
                url_str
            );
        }

        if status == StatusCode::BAD_REQUEST {
            let mut msg = format!("Failed to {}: HTTP 400", operation);

            // Try to parse error message from JSON response
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                if let Some(err_msg) = json
                    .get("meta")
                    .and_then(|m| m.get("msg"))
                    .and_then(|m| m.as_str())
                {
                    msg.push_str(&format!("\n\nError: {}", err_msg));
                } else if let Some(err_msg) = json.get("error").and_then(|e| e.as_str()) {
                    msg.push_str(&format!("\n\nError: {}", err_msg));
                }
            }

            // Add context-specific guidance
            msg.push_str(Self::get_operation_guidance(path, operation));

            return msg;
        }

        if status == StatusCode::NOT_FOUND {
            return format!(
                "Resource not found (404) at {}\n\nPossible causes:\n  • The {} does not exist\n  • Invalid ID or identifier\n  • Resource was deleted\n\nTry:\n  unifictl local {} -o json",
                url_str,
                operation
                    .replace("create", "resource")
                    .replace("update", "resource")
                    .replace("delete", "resource"),
                Self::get_list_command(path)
            );
        }

        if status == StatusCode::CONFLICT {
            return format!(
                "Conflict (409) at {}\n\nPossible causes:\n  • Resource already exists\n  • Conflicting configuration\n  • Duplicate name or identifier\n\nTry:\n  unifictl local {} -o json",
                url_str,
                Self::get_list_command(path)
            );
        }

        // Generic error with body
        format!(
            "HTTP {} at {}\n\nResponse: {}",
            status,
            url_str,
            if body.len() > 200 {
                format!("{}...", &body[..200])
            } else {
                body.to_string()
            }
        )
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
            return "\n\nPossible causes for network operations:\n  • VLAN ID already in use\n  • Invalid subnet format (expected: 192.168.1.0/24)\n  • Conflicting DHCP range\n  • Invalid network name\n\nCheck existing networks:\n  unifictl local network list -o json";
        }
        if path.contains("wlanconf") {
            return "\n\nPossible causes for WLAN operations:\n  • SSID already exists\n  • Invalid password (must be 8+ characters for WPA2)\n  • Invalid security settings\n\nCheck existing WLANs:\n  unifictl local wlan list -o json";
        }
        if path.contains("firewallrule") {
            return "\n\nPossible causes for firewall rule operations:\n  • Invalid action (must be: accept, drop, reject)\n  • Invalid firewall group IDs\n  • Rule index conflict\n\nCheck existing rules:\n  unifictl local firewall-rule list -o json";
        }
        if path.contains("firewallgroup") {
            return "\n\nPossible causes for firewall group operations:\n  • Invalid group type\n  • Invalid member addresses\n  • Duplicate group name\n\nCheck existing groups:\n  unifictl local firewall-group list -o json";
        }
        if path.contains("routing") {
            return "\n\nPossible causes for policy table operations:\n  • Invalid policy table name\n  • Conflicting routing rules\n  • Invalid rule configuration\n\nCheck existing policy tables:\n  unifictl local policy-table list -o json";
        }
        if path.contains("zone")
            || path.contains("firewall/zone")
            || path.contains("firewall/zones")
        {
            return "\n\nPossible causes for zone operations:\n  • Invalid zone name\n  • Conflicting zone configuration\n  • Invalid interface assignment\n\nCheck existing zones:\n  unifictl local zone list -o json";
        }
        if path.contains("object")
            || path.contains("object-oriented-network-configs")
            || path.contains("network-objects")
        {
            return "\n\nPossible causes for object operations:\n  • Invalid object name\n  • Invalid object type (address/service)\n  • Invalid object value\n\nCheck existing objects:\n  unifictl local object list -o json";
        }
        ""
    }

    fn get_list_command(path: &str) -> &'static str {
        if path.contains("networkconf") {
            "network list"
        } else if path.contains("wlanconf") {
            "wlan list"
        } else if path.contains("firewallrule") {
            "firewall-rule list"
        } else if path.contains("firewallgroup") {
            "firewall-group list"
        } else if path.contains("routing") {
            "policy-table list"
        } else if path.contains("zone")
            || path.contains("firewall/zone")
            || path.contains("firewall/zones")
        {
            "zone list"
        } else if path.contains("object")
            || path.contains("object-oriented-network-configs")
            || path.contains("network-objects")
        {
            "object list"
        } else if path.contains("device") {
            "device list"
        } else if path.contains("sta") {
            "client list"
        } else {
            "site list"
        }
    }

    fn build_urls(&self, site_scoped: bool, fallback_global: bool, path: &str) -> Result<Vec<Url>> {
        let cleaned = path.trim_start_matches('/');
        let mut urls = Vec::new();

        // Check if this is an Integration API v1 path
        let is_integration_api = cleaned.starts_with("integration/v1/");

        if is_integration_api && site_scoped {
            // Integration API v1 uses /integration/v1/sites/{site}/{resource}
            // Extract the resource part after "integration/v1/"
            let resource = cleaned.strip_prefix("integration/v1/").unwrap_or(cleaned);

            // Try Integration API v1 path first
            urls.push(
                self.base_url
                    .join(&format!("integration/v1/sites/{}/{}", self.site, resource))?,
            );

            // If fallback is enabled, try REST API equivalent
            if fallback_global {
                // Map Integration API resources to REST API paths
                let rest_path = if resource.starts_with("firewall/zones") {
                    resource.replace("firewall/zones", "rest/zone")
                } else if resource.starts_with("network-objects") {
                    resource.replace("network-objects", "rest/object")
                } else {
                    format!("rest/{}", resource)
                };

                // Try REST API paths
                urls.push(
                    self.base_url
                        .join(&format!("proxy/network/api/s/{}/{}", self.site, rest_path))?,
                );
                urls.push(
                    self.base_url
                        .join(&format!("api/s/{}/{}", self.site, rest_path))?,
                );
            }
        } else if self.is_legacy {
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
        } else if site_scoped {
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
    fn build_urls_for_v2_endpoints() {
        let client =
            LocalClient::new("https://example.test:8443/", "u", "p", "default", true).unwrap();

        // Test zones endpoint (v2 API)
        let urls = client
            .build_urls(true, false, "firewall/zone")
            .unwrap()
            .iter()
            .map(|u| u.path().to_string())
            .collect::<HashSet<_>>();

        assert!(urls.contains("/proxy/network/api/s/default/firewall/zone"));
        assert!(urls.contains("/proxy/network/v2/api/site/default/firewall/zone"));
        assert!(urls.contains("/proxy/network/v2/api/s/default/firewall/zone"));
        assert!(urls.contains("/api/s/default/firewall/zone"));

        // Test objects endpoint (v2 API)
        let urls = client
            .build_urls(true, false, "object-oriented-network-configs")
            .unwrap()
            .iter()
            .map(|u| u.path().to_string())
            .collect::<HashSet<_>>();

        assert!(urls.contains("/proxy/network/api/s/default/object-oriented-network-configs"));
        assert!(
            urls.contains("/proxy/network/v2/api/site/default/object-oriented-network-configs")
        );
        assert!(urls.contains("/proxy/network/v2/api/s/default/object-oriented-network-configs"));
        assert!(urls.contains("/api/s/default/object-oriented-network-configs"));
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
        assert!(msg.contains("unifictl local network list"));

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
        assert!(msg.contains("unifictl local network list"));

        // Test zone endpoint error handling
        let msg = LocalClient::format_error_message(
            &Method::POST,
            "firewall/zone",
            StatusCode::BAD_REQUEST,
            r#"{"meta":{"msg":"Invalid zone configuration"}}"#,
            "https://example.com/api",
        );
        assert!(msg.contains("zone operations"));
        assert!(msg.contains("unifictl local zone list"));

        // Test object endpoint error handling
        let msg = LocalClient::format_error_message(
            &Method::POST,
            "object-oriented-network-configs",
            StatusCode::BAD_REQUEST,
            r#"{"meta":{"msg":"Invalid object type"}}"#,
            "https://example.com/api",
        );
        assert!(msg.contains("object operations"));
        assert!(msg.contains("unifictl local object list"));

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

    #[test]
    fn clients_v2_active_calls_correct_endpoint() {
        let server = MockServer::start();
        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(200)
                .header("X-CSRF-Token", "abc123")
                .json_body(json!({"ok": true}));
        });
        let clients = server.mock(|when, then| {
            when.method(GET)
                .path("/proxy/network/v2/api/site/default/clients/active");
            then.status(200).json_body(json!({"data": []}));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let resp = client.clients_v2_active().unwrap();

        login.assert();
        clients.assert();
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn clients_v2_history_calls_correct_endpoint() {
        let server = MockServer::start();
        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(200)
                .header("X-CSRF-Token", "abc123")
                .json_body(json!({"ok": true}));
        });
        let history = server.mock(|when, then| {
            when.method(GET)
                .path("/proxy/network/v2/api/site/default/clients/history");
            then.status(200).json_body(json!({"data": []}));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let resp = client.clients_v2_history().unwrap();

        login.assert();
        history.assert();
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn system_log_settings_calls_correct_endpoint() {
        let server = MockServer::start();
        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(200)
                .header("X-CSRF-Token", "abc123")
                .json_body(json!({"ok": true}));
        });
        let settings = server.mock(|when, then| {
            when.method(GET)
                .path("/proxy/network/v2/api/site/default/system-log/setting");
            then.status(200).json_body(json!({"enabled": true}));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let resp = client.system_log_settings().unwrap();

        login.assert();
        settings.assert();
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn wifi_connectivity_calls_correct_endpoint() {
        let server = MockServer::start();
        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(200)
                .header("X-CSRF-Token", "abc123")
                .json_body(json!({"ok": true}));
        });
        let wifi = server.mock(|when, then| {
            when.method(GET)
                .path("/proxy/network/v2/api/site/default/wifi-connectivity");
            then.status(200).json_body(json!({"data": []}));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let resp = client.wifi_connectivity().unwrap();

        login.assert();
        wifi.assert();
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn traffic_stats_calls_correct_endpoint() {
        let server = MockServer::start();
        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(200)
                .header("X-CSRF-Token", "abc123")
                .json_body(json!({"ok": true}));
        });
        let traffic = server.mock(|when, then| {
            when.method(GET)
                .path("/proxy/network/v2/api/site/default/traffic");
            then.status(200).json_body(json!({"data": []}));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let query = json!({"start": 0, "end": 1000, "includeUnidentified": false});
        let resp = client.traffic_stats(&query).unwrap();

        login.assert();
        traffic.assert();
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn stat_rogueap_calls_correct_endpoint() {
        let server = MockServer::start();
        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(200)
                .header("X-CSRF-Token", "abc123")
                .json_body(json!({"ok": true}));
        });
        let rogueap = server.mock(|when, then| {
            when.method(GET)
                .path("/proxy/network/api/s/default/stat/rogueap");
            then.status(200).json_body(json!({"data": []}));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let resp = client.stat_rogueap().unwrap();

        login.assert();
        rogueap.assert();
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn ports_anomalies_calls_correct_endpoint() {
        let server = MockServer::start();
        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(200)
                .header("X-CSRF-Token", "abc123")
                .json_body(json!({"ok": true}));
        });
        let ports = server.mock(|when, then| {
            when.method(GET)
                .path("/proxy/network/v2/api/site/default/ports/port-anomalies");
            then.status(200).json_body(json!({"data": []}));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let resp = client.ports_anomalies().unwrap();

        login.assert();
        ports.assert();
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn vpn_health_filters_and_calls_health() {
        let server = MockServer::start();
        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(200)
                .header("X-CSRF-Token", "abc123")
                .json_body(json!({"ok": true}));
        });
        let health = server.mock(|when, then| {
            when.method(GET)
                .path("/proxy/network/api/s/default/stat/health");
            then.status(200).json_body(json!({
                "data": [
                    { "subsystem": "vpn", "status": "error", "packet_loss": 0.5 },
                    { "subsystem": "wan", "status": "ok" }
                ]
            }));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let resp = client.vpn_health().unwrap();

        login.assert();
        health.assert();

        let data = resp.json.unwrap()["data"].as_array().unwrap().clone();
        assert_eq!(data.len(), 1);
        assert_eq!(data[0]["subsystem"], "vpn");
    }
}

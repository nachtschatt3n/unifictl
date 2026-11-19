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
use crate::session;
use anyhow::{Context, Result, anyhow};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, COOKIE, HeaderValue, SET_COOKIE, USER_AGENT};
use reqwest::{Method, StatusCode, Url};
use serde::Serialize;
use std::sync::OnceLock;
use std::time::Duration;

pub struct LocalClient {
    base_url: Url,
    /// The controller URL exactly as configured (cache key; may differ from
    /// `base_url` (legacy cache entries may name a different resolved URL).
    configured_url: String,
    http: Client,
    username: String,
    password: String,
    site: String,
    logged_in: bool,
    is_legacy: bool,
    csrf: Option<String>,
    session_cookie: Option<String>,
    trust_profile: String,
    refresh_used: bool,
    auth_blocked: Option<ControllerFailure>,
    port_fallback: bool,
}

#[derive(Debug, Clone)]
struct ControllerFailure {
    status: Option<u16>,
    message: String,
}

impl std::fmt::Display for ControllerFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ControllerFailure {}

/// A batch must not keep submitting actions after authentication, permission,
/// or rate-limit rejection. Downcasting survives anyhow context wrappers.
pub fn should_stop_batch(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<ControllerFailure>()
        .is_some_and(|failure| matches!(failure.status, Some(401 | 403 | 429)))
}

// Hand-written Debug so credentials and session tokens never leak into logs,
// panic messages, or error chains.
impl std::fmt::Debug for LocalClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let present = |o: &Option<String>| if o.is_some() { "<redacted>" } else { "<none>" };
        f.debug_struct("LocalClient")
            .field("base_url", &self.base_url.as_str())
            .field("configured_url", &self.configured_url)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("site", &self.site)
            .field("logged_in", &self.logged_in)
            .field("is_legacy", &self.is_legacy)
            .field("csrf", &present(&self.csrf))
            .field("session_cookie", &present(&self.session_cookie))
            .finish()
    }
}

static UA: OnceLock<HeaderValue> = OnceLock::new();

/// Upper bound on how long we will sleep to honor a `Retry-After` on a 429
/// read before giving up and surfacing the rate-limit error. Keeps the CLI
/// responsive rather than blocking on a multi-minute lockout window.
const RETRY_AFTER_CAP_SECS: u64 = 30;

/// Identifiers are one path segment, never an endpoint or an encoded path.
/// Reject before login so an invalid target cannot cause network side effects.
pub fn validate_target_id(value: &str) -> Result<()> {
    if value.is_empty()
        || matches!(value, "." | "..")
        || value
            .chars()
            .any(|c| c.is_control() || "/\\%?#".contains(c))
    {
        return Err(anyhow!(
            "invalid target identifier: expected one URL path segment"
        ));
    }
    Ok(())
}

fn resource_path(resource: &str, id: &str) -> Result<String> {
    validate_target_id(id)?;
    Ok(format!("{resource}/{id}"))
}

fn validate_path(path: &str) -> Result<()> {
    for segment in path.split('/') {
        validate_target_id(segment)?;
    }
    Ok(())
}

/// POST is also used for queries; only these known query endpoints may replay.
fn is_read_operation(method: &Method, path: &str) -> bool {
    *method == Method::GET
        || (*method == Method::POST
            && matches!(
                path,
                "system-log/all"
                    | "system-log/count"
                    | "system-log/critical"
                    | "system-log/device-alert"
                    | "system-log/admin-activity"
                    | "app-traffic-rate"
                    | "traffic-flows"
                    | "ports/mac-tables"
                    | "stat/report/5minutes.ap"
            ))
}

/// Only named collection endpoints have this contract. Settings, aggregates,
/// and mutation responses may legitimately be objects without a `data` array.
fn expects_collection(method: &Method, path: &str) -> bool {
    (*method == Method::GET
        && matches!(
            path,
            "self/sites"
                | "stat/device"
                | "stat/sta"
                | "clients/active"
                | "clients/history"
                | "list/alarm"
                | "stat/health"
                | "rest/networkconf"
                | "static-dns"
                | "rest/wlanconf"
                | "rest/portconf"
                | "rest/firewallrule"
                | "rest/firewallgroup"
                | "rest/routing"
                | "firewall/zone"
                | "object-oriented-network-configs"
        ))
        || (*method == Method::POST
            && matches!(
                path,
                "system-log/all"
                    | "system-log/critical"
                    | "system-log/device-alert"
                    | "system-log/admin-activity"
            ))
}

fn uses_v2_api(path: &str) -> bool {
    !path.starts_with("rest/")
        && !path.starts_with("cmd/")
        && !path.starts_with("stat/")
        && !path.starts_with("list/")
        && !path.starts_with("self/")
        && !path.starts_with("integration/")
}

/// Parse a `Retry-After` header expressed in delta-seconds. HTTP-date form is
/// intentionally not handled (UniFi controllers emit delta-seconds).
fn parse_retry_after(resp: &reqwest::blocking::Response) -> Option<u64> {
    resp.headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
}

/// Largest `pageSize` we will ask the controller for in a single request.
/// (Omitting `pageSize` entirely makes the controller fall back to 50 — the
/// default that silently capped `event list --limit 3000` at 50 rows.)
/// Bigger requests are served by paginating rather than by one huge fetch.
pub const SYSTEM_LOG_MAX_PAGE_SIZE: usize = 1000;

/// Safety stop so a controller that keeps handing back full pages can never
/// spin this into an unbounded request loop.
pub const SYSTEM_LOG_MAX_PAGES: usize = 500;

/// Mutable access to the list payload of a UniFi controller response.
///
/// The two API generations disagree on shape: v1 (`/api/s/{site}/...`) wraps
/// results in `{"meta": …, "data": [...]}`, while v2
/// (`/proxy/network/v2/api/site/{site}/...`, e.g. `clients/history` and
/// `clients/active`) returns a **bare array**. Code that reached only for
/// `data` therefore found nothing on every v2 list endpoint and silently
/// skipped both filtering and `--limit`.
pub fn list_payload_mut(json: &mut serde_json::Value) -> Option<&mut Vec<serde_json::Value>> {
    if json.is_array() {
        return json.as_array_mut();
    }
    json.get_mut("data").and_then(|d| d.as_array_mut())
}

/// Read-only counterpart to [`list_payload_mut`].
pub fn list_payload(json: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
    if json.is_array() {
        return json.as_array();
    }
    json.get("data").and_then(|d| d.as_array())
}

/// Strip the separators UniFi and users mix freely (`:`, `-`, `.`, spaces) so
/// `d4:8a:fc:44:0c:48`, `D4-8A-FC-44-0C-48` and `d48afc440c48` all compare
/// equal.
fn normalize_mac(mac: &str) -> String {
    mac.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Compare two MAC addresses case-insensitively and independently of
/// separator style.
pub fn mac_matches(a: &str, b: &str) -> bool {
    let (a, b) = (normalize_mac(a), normalize_mac(b));
    !a.is_empty() && a == b
}

/// Outcome of a paginated fetch, so callers can tell "that is all there is"
/// apart from "we could not deliver everything you asked for".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PagedFetch {
    /// Number of records the caller asked for.
    pub requested: usize,
    /// Number of records actually returned.
    pub returned: usize,
    /// Total records the controller reports as available, when it says so.
    pub total_available: Option<usize>,
    /// True when the controller holds more records than we returned *and* the
    /// caller asked for more than we could deliver. Callers must surface this
    /// — a silent short read reads as "that is all there is".
    pub truncated: bool,
}

impl LocalClient {
    pub fn from_config(config: &crate::config::LocalEffectiveConfig) -> Result<Self> {
        if !config.verify_tls {
            eprintln!("unifictl: TLS verification disabled by explicit configuration (--insecure)");
        }
        Self::build(
            &config.url,
            &config.username,
            &config.password,
            &config.site,
            config.verify_tls,
            config.ca_file.as_deref(),
            config.port_fallback,
        )
    }

    #[cfg(test)]
    pub fn new(
        url: &str,
        username: &str,
        password: &str,
        site: &str,
        verify_tls: bool,
    ) -> Result<Self> {
        Self::build(url, username, password, site, verify_tls, None, false)
    }

    fn build(
        url: &str,
        username: &str,
        password: &str,
        site: &str,
        verify_tls: bool,
        ca_file: Option<&std::path::Path>,
        port_fallback: bool,
    ) -> Result<Self> {
        validate_target_id(site)?;
        let base_url = crate::client::validate_base_url(url, !verify_tls || cfg!(test))?;
        if ca_file.is_some() && !verify_tls {
            return Err(anyhow!(
                "a CA file requires TLS verification; remove --insecure/verify_tls: false"
            ));
        }
        let user_agent = UA.get_or_init(|| HeaderValue::from_static("unifictl-local/0.1"));
        let mut builder = Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(!verify_tls)
            .user_agent(user_agent.clone())
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5));
        let mut ca_pem = Vec::new();
        if let Some(path) = ca_file {
            let pem = std::fs::read(path).context("reading controller CA file")?;
            let certificates = reqwest::Certificate::from_pem_bundle(&pem)
                .context("parsing controller CA certificates (PEM required)")?;
            if certificates.is_empty() {
                return Err(anyhow!("controller CA file contains no certificates"));
            }
            for certificate in certificates {
                builder = builder.add_root_certificate(certificate);
            }
            ca_pem = pem;
        }
        let http = builder.build().context("building local HTTP client")?;
        let mut client = Self {
            base_url,
            configured_url: url.to_string(),
            http,
            username: username.to_string(),
            password: password.to_string(),
            site: site.to_string(),
            logged_in: false,
            is_legacy: false,
            csrf: None,
            session_cookie: None,
            trust_profile: session::trust_profile(verify_tls, &ca_pem),
            refresh_used: false,
            auth_blocked: None,
            port_fallback,
        };
        client.restore_cached_session();
        Ok(client)
    }

    /// Adopt a persisted session, if one is cached for this controller. The
    /// session is used optimistically: its validity is only confirmed on the
    /// first read (a 401 allows one re-login; permission denial is terminal).
    fn restore_cached_session(&mut self) {
        if let Some(sess) = session::load(&self.configured_url, &self.username, &self.site) {
            if sess.trust_profile.as_deref() != Some(&self.trust_profile) {
                return;
            }
            // Cache entries never expand the configured destination, including
            // port/path. Older 8443->443 fallback entries require a fresh login.
            let resolved = match Url::parse(&sess.resolved_url) {
                Ok(u) if u == self.base_url => u,
                Ok(u) if self.port_fallback && self.is_fallback_of_configured(&u) => u,
                _ => return,
            };
            self.base_url = resolved;
            self.csrf = sess.csrf;
            self.session_cookie = sess.session_cookie;
            self.is_legacy = sess.is_legacy;
            self.logged_in = true;
        }
    }

    /// True when `u` is the configured `:8443` URL moved to port 443 and the
    /// user opted in to that fallback.
    fn is_fallback_of_configured(&self, u: &Url) -> bool {
        let mut alt = self.base_url.clone();
        self.base_url.port() == Some(8443) && alt.set_port(Some(443)).is_ok() && *u == alt
    }

    /// Persist the current authenticated session to the on-disk cache
    /// (best-effort; a cache-write failure never fails the command).
    fn persist_session(&self) {
        let _ = session::save(&session::CachedSession {
            key_url: self.configured_url.clone(),
            resolved_url: self.base_url.to_string(),
            username: self.username.clone(),
            site: self.site.clone(),
            is_legacy: self.is_legacy,
            csrf: self.csrf.clone(),
            session_cookie: self.session_cookie.clone(),
            created_at: session::now_secs(),
            trust_profile: Some(self.trust_profile.clone()),
        });
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
            && let Some(arr) = list_payload_mut(&mut json)
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
        // Modern UniFi OS serves system-log queries at
        // `/proxy/network/v2/api/site/{site}/system-log/{category}` (POST). The
        // legacy `/api/s/{site}/system-log/...` route is gone, and the v2 route
        // requires a JSON body, so always send at least `{}` (never None) — a
        // body-less POST omits Content-Type and the v2 endpoint rejects it.
        let empty = serde_json::json!({});
        let payload = payload.unwrap_or(&empty);
        self.post(true, "system-log/all", Some(payload))
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
        let empty = serde_json::json!({});
        let payload = payload.unwrap_or(&empty);
        self.post(true, "system-log/critical", Some(payload))
    }

    pub fn system_log_device_alert(
        &mut self,
        payload: Option<&serde_json::Value>,
    ) -> Result<ResponseData> {
        let empty = serde_json::json!({});
        let payload = payload.unwrap_or(&empty);
        self.post(true, "system-log/device-alert", Some(payload))
    }

    /// Admin-activity / audit log (ADMIN_ACCESS and other AUDIT-category
    /// events). On modern UniFi OS this lives at
    /// `/proxy/network/v2/api/site/{site}/system-log/admin-activity` (POST).
    pub fn system_log_admin_activity(
        &mut self,
        payload: Option<&serde_json::Value>,
    ) -> Result<ResponseData> {
        let empty = serde_json::json!({});
        let payload = payload.unwrap_or(&empty);
        self.post(true, "system-log/admin-activity", Some(payload))
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

    /// Threat-management / IPS-IDS alarms (and other system alarms).
    ///
    /// On modern UniFi OS (proxied Network app) the legacy `stat/event` route
    /// is gone, but the alarm list survives at `list/alarm` under the Network
    /// API namespace. `archived=false` returns currently-active alarms;
    /// `archived=true` returns historical/acknowledged ones.
    pub fn list_alarms(&mut self, archived: bool) -> Result<ResponseData> {
        let query = serde_json::json!({ "archived": archived });
        self.get(true, false, "list/alarm", Some(&query))
    }

    pub fn stat_sdn(&mut self) -> Result<ResponseData> {
        self.get(true, false, "stat/sdn", Option::<&()>::None)
    }

    pub fn stat_spectrum_scan(&mut self, mac: &str) -> Result<ResponseData> {
        self.get(
            true,
            false,
            &resource_path("stat/spectrum-scan", mac)?,
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
            if let Some(arr) = list_payload_mut(&mut json) {
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

    /// Fetch up to `limit` events, paginating `system-log/all` as needed.
    ///
    /// The v2 endpoint pages at 50 records when `pageSize` is omitted, so the
    /// old "fetch once, truncate client-side" approach could never return more
    /// than 50 events no matter what `--limit` asked for. We request
    /// `pageSize` explicitly and walk `pageNumber` (**0-based** — page 0 is the
    /// newest slice; starting at 1 silently drops the most recent page) until
    /// the limit is
    /// met or the controller runs out of records, then report — via
    /// [`PagedFetch`] — whether anything was left behind.
    pub fn list_events_paged(&mut self, limit: usize) -> Result<(ResponseData, PagedFetch)> {
        let mut collected: Vec<serde_json::Value> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut total_available: Option<usize> = None;
        let mut page_size = limit.clamp(1, SYSTEM_LOG_MAX_PAGE_SIZE);
        // Page numbering is 0-based: page 0 holds the newest records.
        let mut page_number = 0usize;
        let mut last_resp: Option<ResponseData> = None;
        let mut hit_page_cap = false;

        while collected.len() < limit {
            if page_number >= SYSTEM_LOG_MAX_PAGES {
                hit_page_cap = true;
                break;
            }

            let payload = serde_json::json!({
                "pageSize": page_size,
                "pageNumber": page_number,
            });
            // A non-success status is turned into an `Err` by `request`, so any
            // API failure propagates here rather than being masked behind a
            // half-filled page.
            let resp = self.system_log_all(Some(&payload))?;

            let json = resp
                .json
                .as_ref()
                .ok_or_else(|| anyhow!("event page is missing a JSON response"))?;
            if let Some(total) = json
                .get("total_element_count")
                .and_then(|v| v.as_u64())
                .map(|v| v as usize)
            {
                if total_available.is_some_and(|previous| previous != total) {
                    return Err(anyhow!(
                        "event inventory changed during pagination; retry the read"
                    ));
                }
                total_available = Some(total);
            }
            let page_items = list_payload(json)
                .ok_or_else(|| anyhow!("event page is missing its records array"))?;
            let got = page_items.len();
            for item in page_items {
                let identity = item.get("_id").or_else(|| item.get("id"));
                let key = serde_json::to_string(identity.unwrap_or(item))?;
                if !seen.insert(key) {
                    return Err(anyhow!(
                        "event pagination repeated a record; incomplete or unstable inventory"
                    ));
                }
                collected.push(item.clone());
            }
            last_resp = Some(resp);

            if got == 0 {
                break;
            }
            if let Some(total) = total_available
                && collected.len() >= total
            {
                break;
            }
            // A controller that clamps `pageSize` below what we asked for would
            // otherwise leave holes in the next page's offset window — adopt
            // the size it actually honored so paging stays contiguous.
            // Negotiate a clamp only at offset zero. Shrinking the page size
            // later moves pageNumber * pageSize backward and repeats records.
            if page_number == 0 && got < page_size {
                page_size = got;
            }
            page_number += 1;
        }

        let mut resp = last_resp.unwrap_or(ResponseData {
            status: 200,
            body: "{\"data\":[]}".to_string(),
            json: Some(serde_json::json!({ "data": [] })),
        });

        collected.truncate(limit);
        let returned = collected.len();

        let mut json = resp.json.clone().unwrap_or_else(|| serde_json::json!({}));
        if !json.is_object() {
            json = serde_json::json!({});
        }
        json["data"] = serde_json::Value::Array(collected);
        json["page_number"] = serde_json::json!(0);
        json["page_size"] = serde_json::json!(returned);
        resp.body = serde_json::to_string(&json).unwrap_or_else(|_| resp.body.clone());
        resp.json = Some(json);

        let truncated = hit_page_cap
            || (returned < limit && total_available.map(|t| t > returned).unwrap_or(false));
        let stats = PagedFetch {
            requested: limit,
            returned,
            total_available,
            truncated,
        };
        Ok((resp, stats))
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
        self.put(true, &resource_path("rest/networkconf", id)?, Some(payload))
    }

    pub fn delete_network(&mut self, id: &str) -> Result<ResponseData> {
        self.delete(true, &resource_path("rest/networkconf", id)?)
    }

    pub fn list_dns_records(&mut self) -> Result<ResponseData> {
        self.get(true, false, "static-dns", Option::<&()>::None)
    }

    pub fn create_dns_record(&mut self, payload: &serde_json::Value) -> Result<ResponseData> {
        self.post(true, "static-dns", Some(payload))
    }

    pub fn update_dns_record(
        &mut self,
        id: &str,
        payload: &serde_json::Value,
    ) -> Result<ResponseData> {
        self.put(true, &resource_path("static-dns", id)?, Some(payload))
    }

    pub fn delete_dns_record(&mut self, id: &str) -> Result<ResponseData> {
        self.delete(true, &resource_path("static-dns", id)?)
    }

    pub fn wlans(&mut self) -> Result<ResponseData> {
        self.get(true, true, "rest/wlanconf", Option::<&()>::None)
    }

    pub fn create_wlan(&mut self, payload: &serde_json::Value) -> Result<ResponseData> {
        self.post(true, "rest/wlanconf", Some(payload))
    }

    pub fn update_wlan(&mut self, id: &str, payload: &serde_json::Value) -> Result<ResponseData> {
        self.put(true, &resource_path("rest/wlanconf", id)?, Some(payload))
    }

    pub fn delete_wlan(&mut self, id: &str) -> Result<ResponseData> {
        self.delete(true, &resource_path("rest/wlanconf", id)?)
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
        self.put(
            true,
            &resource_path("rest/firewallrule", id)?,
            Some(payload),
        )
    }

    pub fn delete_firewall_rule(&mut self, id: &str) -> Result<ResponseData> {
        self.delete(true, &resource_path("rest/firewallrule", id)?)
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
        self.put(
            true,
            &resource_path("rest/firewallgroup", id)?,
            Some(payload),
        )
    }

    pub fn delete_firewall_group(&mut self, id: &str) -> Result<ResponseData> {
        self.delete(true, &resource_path("rest/firewallgroup", id)?)
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
        self.put(true, &resource_path("rest/routing", id)?, Some(payload))
    }

    pub fn delete_policy_table(&mut self, id: &str) -> Result<ResponseData> {
        self.delete(true, &resource_path("rest/routing", id)?)
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
        self.put(true, &resource_path("firewall/zone", id)?, Some(payload))
    }

    pub fn delete_zone(&mut self, id: &str) -> Result<ResponseData> {
        self.delete(true, &resource_path("firewall/zone", id)?)
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
            &resource_path("object-oriented-network-configs", id)?,
            Some(payload),
        )
    }

    pub fn delete_object(&mut self, id: &str) -> Result<ResponseData> {
        self.delete(true, &resource_path("object-oriented-network-configs", id)?)
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

    /// Build a fully-formed request (headers + optional query/body). The CSRF
    /// token and session cookie are added per-send by the caller's `send_once`.
    fn build_request<Q: Serialize + ?Sized, B: Serialize + ?Sized>(
        &self,
        method: &Method,
        url: &Url,
        query: Option<&Q>,
        body: Option<&B>,
    ) -> reqwest::blocking::RequestBuilder {
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
        req
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
        validate_path(path)?;
        let read_only = is_read_operation(&method, path);
        self.ensure_login()?;
        let mut urls = self.build_urls(site_scoped, fallback_global, path)?;
        // Mutation routes are selected before submission. Even a 404/405 may
        // come from a proxy after forwarding, so never discover by replaying a write.
        if !read_only {
            urls.truncate(1);
        }
        let mut rate_retried = false;
        for url in urls {
            loop {
                let mut req = self.build_request(&method, &url, query, body);
                if let Some(token) = &self.csrf {
                    req = req.header("X-CSRF-Token", token);
                }
                if let Some(cookie) = &self.session_cookie {
                    req = req.header(COOKIE, cookie);
                }
                let res = req.send().map_err(|err| {
                    if !read_only {
                        anyhow!("outcome=unknown: mutation response unavailable; read back controller state before any retry")
                    } else if err.is_timeout() {
                        anyhow!("Network timeout talking to the controller; session was not re-authenticated")
                    } else {
                        anyhow!("Controller transport failure; session was not re-authenticated")
                    }
                })?;
                let status = res.status();
                // Permission denial is terminal. Only a read can be retried
                // after one 401 refresh; writes require explicit reconciliation.
                if read_only && status == StatusCode::UNAUTHORIZED && !self.refresh_used {
                    self.refresh_used = true;
                    self.force_relogin()?;
                    continue;
                }
                if read_only
                    && status == StatusCode::TOO_MANY_REQUESTS
                    && !rate_retried
                    && let Some(wait) = parse_retry_after(&res)
                    && wait <= RETRY_AFTER_CAP_SECS
                {
                    rate_retried = true;
                    std::thread::sleep(Duration::from_secs(wait));
                    continue;
                }
                if !status.is_success() {
                    if read_only
                        && matches!(
                            status,
                            StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
                        )
                    {
                        break;
                    }
                    if status == StatusCode::UNAUTHORIZED {
                        self.logged_in = false;
                        self.csrf = None;
                        self.session_cookie = None;
                        session::clear_identity(&self.configured_url, &self.username, &self.site);
                    }
                    let message = Self::format_error_message(&method, path, status, "", "");
                    if matches!(
                        status,
                        StatusCode::UNAUTHORIZED
                            | StatusCode::FORBIDDEN
                            | StatusCode::TOO_MANY_REQUESTS
                    ) {
                        let failure = ControllerFailure {
                            status: Some(status.as_u16()),
                            message,
                        };
                        if status == StatusCode::UNAUTHORIZED {
                            self.auth_blocked = Some(failure.clone());
                        }
                        return Err(failure.into());
                    }
                    if !read_only
                        && (status.is_server_error()
                            || status.is_redirection()
                            || matches!(
                                status,
                                StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
                            ))
                    {
                        return Err(anyhow!(
                            "outcome=unknown: {message}; verify controller state before retrying"
                        ));
                    }
                    return Err(anyhow!(message));
                }
                let mut text = res.text().map_err(|_| {
                    if read_only {
                        anyhow!("reading controller response body failed")
                    } else {
                        anyhow!("outcome=unknown: mutation response body incomplete; read back controller state before any retry")
                    }
                })?;
                let json = if status == StatusCode::NO_CONTENT && text.is_empty() && !read_only {
                    None
                } else {
                    let parsed = serde_json::from_str::<serde_json::Value>(&text)
                        .ok()
                        .filter(|value| value.is_object() || value.is_array());
                    let Some(mut value) = parsed else {
                        return Err(anyhow!(if read_only {
                            "invalid controller JSON response"
                        } else {
                            "outcome=unknown: invalid mutation JSON response; read back controller state before any retry"
                        }));
                    };
                    if let Some(rc) = value.get("meta").and_then(|meta| meta.get("rc"))
                        && rc.as_str() != Some("ok")
                    {
                        return Err(anyhow!(
                            "controller reported an application error; response body omitted"
                        ));
                    }
                    if expects_collection(&method, path) && list_payload(&value).is_none() {
                        return Err(anyhow!(
                            "invalid controller collection response: expected an array or data array"
                        ));
                    }
                    // This namespace belongs to local completeness metadata,
                    // never to untrusted controller-provided claims.
                    if let Some(object) = value.as_object_mut()
                        && object.remove("_unifictl").is_some()
                    {
                        text = serde_json::to_string(&value)?;
                    }
                    Some(value)
                };
                return Ok(ResponseData {
                    status: status.as_u16(),
                    body: text,
                    json,
                });
            }
        }
        Err(anyhow!(
            "controller endpoint unavailable (404/405); no supported read route found"
        ))
    }

    fn ensure_login(&mut self) -> Result<()> {
        if let Some(failure) = &self.auth_blocked {
            return Err(failure.clone().into());
        }
        if self.logged_in {
            return Ok(());
        }
        self.login()
    }

    fn force_relogin(&mut self) -> Result<()> {
        if let Some(failure) = &self.auth_blocked {
            return Err(failure.clone().into());
        }
        self.logged_in = false;
        self.csrf = None;
        self.session_cookie = None;
        // Invalidate the stale on-disk session; login() rewrites it on success.
        session::clear_identity(&self.configured_url, &self.username, &self.site);
        self.login()
    }

    /// Validate the supplied password, never just the cached session.
    pub fn validate_credentials(&mut self) -> Result<ResponseData> {
        self.force_relogin()?;
        self.list_sites()
    }

    fn login(&mut self) -> Result<()> {
        if let Some(failure) = &self.auth_blocked {
            return Err(failure.clone().into());
        }
        match self.login_once() {
            Ok(()) => Ok(()),
            Err(error) => {
                let failure = error
                    .downcast_ref::<ControllerFailure>()
                    .cloned()
                    .unwrap_or_else(|| ControllerFailure {
                        status: None,
                        message: error.to_string(),
                    });
                self.auth_blocked = Some(failure.clone());
                Err(failure.into())
            }
        }
    }

    fn login_once(&mut self) -> Result<()> {
        let creds = serde_json::json!({
            "username": self.username,
            "password": self.password,
            "remember": true,
            "strict": true,
        });
        // Login discovery is same-origin by default. A different port is a
        // different authority, so the legacy `:8443` -> `:443` fallback only
        // runs when the user opted in (`port_fallback`), and then only when the
        // first authority is unreachable or has no login endpoint. A credential
        // rejection or ambiguous response never submits the password elsewhere.
        let mut bases = vec![self.base_url.clone()];
        if self.port_fallback
            && self.base_url.port() == Some(8443)
            && let Ok(mut alt) = Url::parse(self.base_url.as_str())
            && alt.set_port(Some(443)).is_ok()
        {
            bases.push(alt);
        }
        let mut last_err = anyhow!("login endpoint unavailable (404/405)");
        for base in bases {
            match self.login_on(&base, &creds)? {
                Ok(()) => return Ok(()),
                Err(unavailable) => last_err = unavailable,
            }
        }
        Err(last_err)
    }

    /// Try every login path on one base URL. The outer `Result` is terminal
    /// (credentials rejected, ambiguous response); the inner `Err` means this
    /// authority offered no usable login endpoint, so the next one may be tried.
    fn login_on(
        &mut self,
        base: &Url,
        creds: &serde_json::Value,
    ) -> Result<std::result::Result<(), anyhow::Error>> {
        for path in [
            "api/auth/login",
            "proxy/network/api/auth/login",
            "auth/login",
            "api/login",
        ] {
            let url = base.join(path).context("building login endpoint")?;
            let resp = match self.request_login(&url, creds) {
                Ok(resp) => resp,
                // Nothing was received, so nothing was accepted or rejected.
                Err(err) => return Ok(Err(err)),
            };
            let status = resp.status();
            if matches!(
                status,
                StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
            ) {
                continue;
            }
            if !status.is_success() {
                return Err(ControllerFailure {
                    status: Some(status.as_u16()),
                    message: format!(
                        "login failed: HTTP {}; credentials were not retried",
                        status.as_u16()
                    ),
                }
                .into());
            }
            if !login_established(&resp) {
                return Err(anyhow!(
                    "login response did not establish a session; credentials were not retried"
                ));
            }
            self.base_url = base.clone();
            self.is_legacy = path == "api/login";
            self.logged_in = true;
            self.csrf = extract_csrf(&resp);
            self.session_cookie = extract_session_cookie(&resp);
            self.persist_session();
            return Ok(Ok(()));
        }
        Ok(Err(anyhow!("login endpoint unavailable (404/405)")))
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
            .map_err(|_| anyhow!("login transport failed; credentials were not retried"))
    }

    fn format_error_message(
        method: &Method,
        path: &str,
        status: StatusCode,
        body: &str,
        url: impl AsRef<str>,
    ) -> String {
        let _ = (body, url); // Controller errors may contain credentials or terminal controls.
        let operation = Self::infer_operation(method, path);
        match status {
            StatusCode::UNAUTHORIZED => "Authentication failed (401). Session expired or credentials rejected. Run unifictl login validate --local-only; do not blindly retry mutations.".to_string(),
            StatusCode::FORBIDDEN => "Permission denied (403); the session was not re-authenticated. Check the principal's site and operation permissions.".to_string(),
            StatusCode::TOO_MANY_REQUESTS => "Rate limited (429); do NOT re-login. Back off before retrying reads; verify liveness with unifictl local health get.".to_string(),
            StatusCode::BAD_REQUEST => format!("Failed to {operation}: HTTP 400{}", Self::get_operation_guidance(path, operation)),
            StatusCode::NOT_FOUND => format!("Resource not found (404). Check unifictl local {} -o json", Self::get_list_command(path)),
            StatusCode::CONFLICT => format!("Conflict (409). Resource already exists or state changed. Check unifictl local {} -o json", Self::get_list_command(path)),
            _ => format!("Controller request failed: HTTP {}", status.as_u16()),
        }
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
        if !self.is_legacy && site_scoped && uses_v2_api(cleaned) {
            // The first URL is also the sole mutation URL. Keep v2 writes on
            // the route used by the existing v2 methods and endpoint tests.
            let preferred = self.base_url.join(&format!(
                "proxy/network/v2/api/site/{}/{}",
                self.site, cleaned
            ))?;
            urls.retain(|url| url != &preferred);
            urls.insert(0, preferred);
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

fn login_established(resp: &reqwest::blocking::Response) -> bool {
    extract_csrf(resp).is_some() || extract_session_cookie(resp).is_some()
}

fn extract_session_cookie(resp: &reqwest::blocking::Response) -> Option<String> {
    if let Some(cookie) = resp.cookies().find(|c| c.name() != "csrf_token") {
        return Some(format!("{}={}", cookie.name(), cookie.value()));
    }

    resp.headers().get_all(SET_COOKIE).iter().find_map(|value| {
        let raw = value.to_str().ok()?;
        let pair = raw.split(';').next()?.trim();
        if pair.is_empty() || pair.starts_with("csrf_token=") || !pair.contains('=') {
            return None;
        }
        Some(pair.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;
    use reqwest::Method;
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
            then.status(200)
                .header("Set-Cookie", "unifises=legacy-session; Path=/; HttpOnly")
                .json_body(json!({"logged_in": true}));
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
    fn login_without_session_is_terminal() {
        let server = MockServer::start();
        let incomplete = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(200).json_body(json!({"ok": true}));
        });
        let fallback = server.mock(|when, then| {
            when.method(POST).path("/api/login");
            then.status(200).header("X-CSRF-Token", "unused");
        });
        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        assert!(
            client
                .list_sites()
                .unwrap_err()
                .to_string()
                .contains("did not establish")
        );
        incomplete.assert_calls(1);
        fallback.assert_calls(0);
    }

    #[test]
    fn login_stops_on_rate_limit_instead_of_falling_back() {
        let server = MockServer::start();
        let limited = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(429).json_body(json!({
                "message": "You've reached the login attempt limit",
                "code": "AUTHENTICATION_FAILED_LIMIT_REACHED"
            }));
        });
        let legacy = server.mock(|when, then| {
            when.method(POST).path("/api/login");
            then.status(401).json_body(json!({
                "error": { "code": 401, "message": "Unauthorized" }
            }));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let err = client.list_sites().unwrap_err().to_string();

        limited.assert();
        legacy.assert_calls(0);
        assert!(err.contains("HTTP 429"));
        assert!(!err.contains("AUTHENTICATION_FAILED_LIMIT_REACHED"));
    }

    #[test]
    fn port_fallback_is_off_by_default_and_only_maps_8443_to_443() {
        let mut client =
            LocalClient::new("https://example.test:8443/", "u", "p", "default", true).unwrap();
        let alt = Url::parse("https://example.test:443/").unwrap();
        assert!(!client.port_fallback);
        assert!(client.is_fallback_of_configured(&alt));
        assert!(!client.is_fallback_of_configured(&Url::parse("https://evil.test/").unwrap()));
        client.base_url = Url::parse("https://example.test:9443/").unwrap();
        assert!(!client.is_fallback_of_configured(&alt));
    }

    #[test]
    fn login_unreachable_without_fallback_reports_single_failure() {
        let server = MockServer::start();
        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(401);
        });
        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        assert!(client.list_sites().is_err());
        login.assert_calls(1);
    }

    #[test]
    fn format_error_message_classifies_429_as_rate_limit_not_session_expiry() {
        let msg = LocalClient::format_error_message(
            &Method::GET,
            "stat/device",
            StatusCode::TOO_MANY_REQUESTS,
            r#"{"message":"You've reached the login attempt limit","code":"AUTHENTICATION_FAILED_LIMIT_REACHED"}"#,
            "https://controller.test/proxy/network/api/s/default/stat/device",
        );
        // Must be classified as rate limiting, never as an expired session.
        assert!(msg.contains("Rate limited (429)"));
        assert!(msg.contains("do NOT re-login"));
        assert!(msg.contains("unifictl local health get"));
        assert!(!msg.contains("Session expired"));
        // Untrusted controller detail must not expose tokens or controls.
        assert!(!msg.contains("AUTHENTICATION_FAILED_LIMIT_REACHED"));
    }

    #[test]
    fn format_error_message_401_still_reports_session_expiry() {
        let msg = LocalClient::format_error_message(
            &Method::GET,
            "stat/device",
            StatusCode::UNAUTHORIZED,
            "",
            "https://controller.test/proxy/network/api/s/default/stat/device",
        );
        assert!(msg.contains("Authentication failed (401)"));
        assert!(msg.contains("Session expired"));
    }

    #[test]
    fn cached_session_is_reused_without_relogin() {
        let dir = tempfile::tempdir().unwrap();
        session::test_set_dir(dir.path());

        let server = MockServer::start();
        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
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

        // First invocation authenticates and persists the session.
        let mut c1 = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        c1.list_devices().unwrap();

        // Second invocation restores the cached session — no second login.
        let mut c2 = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        c2.list_devices().unwrap();

        login.assert_calls(1);
        devices.assert_calls(2);
    }

    #[test]
    fn genuine_401_triggers_exactly_one_reauth() {
        let dir = tempfile::tempdir().unwrap();
        session::test_set_dir(dir.path());

        let server = MockServer::start();
        // Seed a stale cached session.
        session::save(&session::CachedSession {
            key_url: server.base_url(),
            resolved_url: server.base_url(),
            username: "u".into(),
            site: "default".into(),
            is_legacy: false,
            csrf: Some("stale".into()),
            session_cookie: None,
            created_at: session::now_secs(),
            trust_profile: Some(session::trust_profile(true, &[])),
        })
        .unwrap();

        let stale = server.mock(|when, then| {
            when.method(GET)
                .path("/proxy/network/api/s/default/stat/device")
                .header("X-CSRF-Token", "stale");
            then.status(401).json_body(json!({"error": "unauthorized"}));
        });
        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(200)
                .header("X-CSRF-Token", "fresh")
                .json_body(json!({"ok": true}));
        });
        let fresh = server.mock(|when, then| {
            when.method(GET)
                .path("/proxy/network/api/s/default/stat/device")
                .header("X-CSRF-Token", "fresh");
            then.status(200).json_body(json!({"data": []}));
        });

        let mut c = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let resp = c.list_devices().unwrap();

        stale.assert_calls(1);
        login.assert_calls(1); // exactly one re-auth
        fresh.assert_calls(1);
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn rate_limited_429_never_reauths() {
        let dir = tempfile::tempdir().unwrap();
        session::test_set_dir(dir.path());

        let server = MockServer::start();
        session::save(&session::CachedSession {
            key_url: server.base_url(),
            resolved_url: server.base_url(),
            username: "u".into(),
            site: "default".into(),
            is_legacy: false,
            csrf: Some("abc".into()),
            session_cookie: None,
            created_at: session::now_secs(),
            trust_profile: Some(session::trust_profile(true, &[])),
        })
        .unwrap();

        // Every candidate device URL is rate limited (no Retry-After header).
        let devices = server.mock(|when, then| {
            when.method(GET).path_includes("stat/device");
            then.status(429).json_body(json!({
                "message": "You've reached the login attempt limit",
                "code": "AUTHENTICATION_FAILED_LIMIT_REACHED"
            }));
        });
        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(200)
                .header("X-CSRF-Token", "x")
                .json_body(json!({"ok": true}));
        });

        let mut c = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let err = c.list_devices().unwrap_err().to_string();

        login.assert_calls(0); // a 429 must NEVER trigger a re-login
        assert!(devices.calls() >= 1);
        assert!(err.contains("Rate limited (429)"));
        assert!(!err.contains("Session expired"));
    }

    #[test]
    fn poisoned_resolved_url_falls_back_to_fresh_login() {
        let dir = tempfile::tempdir().unwrap();
        session::test_set_dir(dir.path());

        let server = MockServer::start();
        // A tampered cache entry whose resolved_url points at a DIFFERENT host
        // than the configured controller, with an attacker-supplied token.
        session::save(&session::CachedSession {
            key_url: server.base_url(),
            resolved_url: "http://attacker.example:9".into(),
            username: "u".into(),
            site: "default".into(),
            is_legacy: false,
            csrf: Some("evil".into()),
            session_cookie: Some("TOKEN=evil".into()),
            created_at: session::now_secs(),
            trust_profile: Some(session::trust_profile(true, &[])),
        })
        .unwrap();

        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(200)
                .header("X-CSRF-Token", "good")
                .json_body(json!({"ok": true}));
        });
        let devices = server.mock(|when, then| {
            when.method(GET)
                .path("/proxy/network/api/s/default/stat/device")
                .header("X-CSRF-Token", "good");
            then.status(200).json_body(json!({"data": []}));
        });

        let mut c = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let resp = c.list_devices().unwrap();

        // The tampered host is ignored: we log in fresh against the configured
        // controller and never send the "evil" token to attacker.example.
        login.assert_calls(1);
        devices.assert_calls(1);
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn extract_session_cookie_reads_partitioned_token_header() {
        let server = MockServer::start();
        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(200)
                .header(
                    "Set-Cookie",
                    "TOKEN=session-123; Path=/; Secure; HttpOnly; Partitioned",
                )
                .json_body(json!({"ok": true}));
        });

        let client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let resp = client
            .http
            .post(server.url("/api/auth/login"))
            .header("X-Requested-With", "XMLHttpRequest")
            .json(&json!({"username": "u", "password": "p"}))
            .send()
            .unwrap();

        login.assert();
        assert_eq!(
            extract_session_cookie(&resp).as_deref(),
            Some("TOKEN=session-123")
        );
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
        assert!(msg.contains("unifictl login validate"));

        // Test 400 error with network path
        let msg = LocalClient::format_error_message(
            &Method::POST,
            "rest/networkconf",
            StatusCode::BAD_REQUEST,
            r#"{"meta":{"msg":"VLAN already in use"}}"#,
            "https://example.com/api",
        );
        assert!(msg.contains("Failed to create"));
        assert!(!msg.contains("VLAN already in use"));
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
    fn system_log_critical_uses_v2_site_endpoint() {
        // Regression: legacy `/api/s/{site}/system-log/critical` is gone on
        // modern UniFi OS. The v1 proxy candidate 404s; the v2 site path serves
        // it as a POST. Verify we fall through to the working v2 endpoint.
        let server = MockServer::start();
        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(200)
                .header("X-CSRF-Token", "abc123")
                .json_body(json!({"ok": true}));
        });
        let critical = server.mock(|when, then| {
            when.method(POST)
                .path("/proxy/network/v2/api/site/default/system-log/critical");
            then.status(200).json_body(json!([]));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let resp = client.system_log_critical(None).unwrap();

        login.assert();
        critical.assert();
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn system_log_device_alert_uses_v2_site_endpoint() {
        let server = MockServer::start();
        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(200)
                .header("X-CSRF-Token", "abc123")
                .json_body(json!({"ok": true}));
        });
        let alert = server.mock(|when, then| {
            when.method(POST)
                .path("/proxy/network/v2/api/site/default/system-log/device-alert");
            then.status(200).json_body(json!({"data": []}));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let resp = client.system_log_device_alert(None).unwrap();

        login.assert();
        alert.assert();
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn system_log_admin_activity_uses_v2_site_endpoint() {
        let server = MockServer::start();
        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(200)
                .header("X-CSRF-Token", "abc123")
                .json_body(json!({"ok": true}));
        });
        let audit = server.mock(|when, then| {
            when.method(POST)
                .path("/proxy/network/v2/api/site/default/system-log/admin-activity");
            then.status(200).json_body(json!([{"key": "ADMIN_ACCESS"}]));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let resp = client.system_log_admin_activity(None).unwrap();

        login.assert();
        audit.assert();
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn system_log_all_uses_v2_endpoint() {
        // Regression: legacy `stat/event` (GET) is gone; events now come from
        // the v2 `system-log/all` POST endpoint.
        let server = MockServer::start();
        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(200)
                .header("X-CSRF-Token", "abc123")
                .json_body(json!({"ok": true}));
        });
        let events = server.mock(|when, then| {
            when.method(POST)
                .path("/proxy/network/v2/api/site/default/system-log/all");
            then.status(200)
                .json_body(json!({"data": [{"key": "CLIENT_CONNECTED_WIRELESS_2"}]}));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let resp = client.system_log_all(None).unwrap();

        login.assert();
        events.assert();
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn list_alarms_calls_list_alarm_endpoint() {
        let server = MockServer::start();
        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(200)
                .header("X-CSRF-Token", "abc123")
                .json_body(json!({"ok": true}));
        });
        let alarms = server.mock(|when, then| {
            when.method(GET)
                .path("/proxy/network/api/s/default/list/alarm")
                .query_param("archived", "false");
            then.status(200).json_body(json!({"data": []}));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let resp = client.list_alarms(false).unwrap();

        login.assert();
        alarms.assert();
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

    #[test]
    fn list_dns_records_calls_correct_endpoint() {
        let server = MockServer::start();
        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(200)
                .header("X-CSRF-Token", "abc123")
                .json_body(json!({"ok": true}));
        });
        let records = server.mock(|when, then| {
            when.method(GET)
                .path("/proxy/network/v2/api/site/default/static-dns");
            then.status(200).json_body(json!([]));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let resp = client.list_dns_records().unwrap();

        login.assert();
        records.assert();
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn create_dns_record_posts_expected_body() {
        let server = MockServer::start();
        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(200)
                .header("X-CSRF-Token", "abc123")
                .json_body(json!({"ok": true}));
        });
        let create = server.mock(|when, then| {
            when.method(POST)
                .path("/proxy/network/v2/api/site/default/static-dns")
                .json_body(json!({
                    "key": "sure.uhl.cool",
                    "record_type": "A",
                    "value": "192.168.55.100",
                    "enabled": true
                }));
            then.status(200)
                .json_body(json!({"_id": "abc123", "key": "sure.uhl.cool"}));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let payload = json!({
            "key": "sure.uhl.cool",
            "record_type": "A",
            "value": "192.168.55.100",
            "enabled": true
        });
        let resp = client.create_dns_record(&payload).unwrap();

        login.assert();
        create.assert();
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn update_dns_record_puts_to_id_path() {
        let server = MockServer::start();
        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(200)
                .header("X-CSRF-Token", "abc123")
                .json_body(json!({"ok": true}));
        });
        let update = server.mock(|when, then| {
            when.method(PUT)
                .path("/proxy/network/v2/api/site/default/static-dns/abc123")
                .json_body(json!({"value": "192.168.55.101"}));
            then.status(200).json_body(json!({"_id": "abc123"}));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let payload = json!({"value": "192.168.55.101"});
        let resp = client.update_dns_record("abc123", &payload).unwrap();

        login.assert();
        update.assert();
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn delete_dns_record_deletes_id_path() {
        let server = MockServer::start();
        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(200)
                .header("X-CSRF-Token", "abc123")
                .json_body(json!({"ok": true}));
        });
        let delete = server.mock(|when, then| {
            when.method(DELETE)
                .path("/proxy/network/v2/api/site/default/static-dns/abc123");
            then.status(200).json_body(json!({"_id": "abc123"}));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let resp = client.delete_dns_record("abc123").unwrap();

        login.assert();
        delete.assert();
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn device_action_force_provision_sends_expected_body() {
        let server = MockServer::start();
        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(200)
                .header("X-CSRF-Token", "abc123")
                .json_body(json!({"ok": true}));
        });
        let provision = server.mock(|when, then| {
            when.method(POST)
                .path("/proxy/network/api/s/default/cmd/devmgr")
                .json_body(json!({"cmd": "force-provision", "mac": "aa:bb:cc:dd:ee:ff"}));
            then.status(200).json_body(json!({"ok": true}));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let resp = client
            .device_action("aa:bb:cc:dd:ee:ff", "force-provision")
            .unwrap();

        login.assert();
        provision.assert();
        assert_eq!(resp.status, 200);
    }

    // ---- Regression: v1/v2 response-envelope handling (bug: --mac and
    // --limit silently ignored on every v2 list endpoint) ----

    #[test]
    fn list_payload_mut_reads_v1_data_envelope() {
        let mut json = json!({"meta": {"rc": "ok"}, "data": [{"mac": "a"}, {"mac": "b"}]});
        let arr = list_payload_mut(&mut json).expect("v1 envelope yields array");
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn list_payload_mut_reads_bare_v2_array() {
        // `clients/history` and `clients/active` answer with a bare array.
        // Reaching only for `data` found nothing here, so filters and limits
        // were dropped on the floor.
        let mut json = json!([{"mac": "a"}, {"mac": "b"}, {"mac": "c"}]);
        let arr = list_payload_mut(&mut json).expect("bare array yields array");
        assert_eq!(arr.len(), 3);
        arr.truncate(1);
        assert_eq!(json.as_array().unwrap().len(), 1);
    }

    #[test]
    fn list_payload_mut_returns_none_for_non_list() {
        let mut json = json!({"meta": {"rc": "ok"}});
        assert!(list_payload_mut(&mut json).is_none());
    }

    // ---- Regression: MAC matching ----

    #[test]
    fn mac_matches_is_case_insensitive() {
        assert!(mac_matches("d4:8a:fc:44:0c:48", "D4:8A:FC:44:0C:48"));
        assert!(mac_matches("D4:8A:FC:44:0C:48", "d4:8a:fc:44:0c:48"));
    }

    #[test]
    fn mac_matches_tolerates_separator_styles() {
        assert!(mac_matches("d4:8a:fc:44:0c:48", "d48afc440c48"));
        assert!(mac_matches("d4-8a-fc-44-0c-48", "d4:8a:fc:44:0c:48"));
        assert!(mac_matches("d48a.fc44.0c48", "D4:8A:FC:44:0C:48"));
    }

    #[test]
    fn mac_matches_rejects_different_macs() {
        assert!(!mac_matches("d4:8a:fc:44:0c:48", "d4:8a:fc:44:0c:49"));
        assert!(!mac_matches("", "d4:8a:fc:44:0c:48"));
        assert!(!mac_matches("", ""));
    }

    // ---- Regression: `event list --limit N` was capped at the controller's
    // 50-per-page default because `pageSize` was never sent ----

    fn login_mock(server: &MockServer) -> httpmock::Mock<'_> {
        server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(200)
                .header("X-CSRF-Token", "abc123")
                .json_body(json!({"ok": true}));
        })
    }

    /// Build `n` synthetic event records starting at `start`.
    fn events(start: usize, n: usize) -> serde_json::Value {
        serde_json::Value::Array(
            (start..start + n)
                .map(|i| json!({"key": format!("EVT_{i}"), "timestamp": i}))
                .collect(),
        )
    }

    #[test]
    fn list_events_paged_sends_explicit_page_size() {
        // The core of the bug: an empty body let the controller apply its own
        // 50-record default. We must ask for what the user requested.
        //
        // The `pageNumber: 0` in the matcher is load-bearing: page numbering is
        // 0-based, so starting the walk at page 1 silently drops the newest
        // slice of events — the exact window a "what happened just now?" query
        // cares about.
        let server = MockServer::start();
        let login = login_mock(&server);
        let page = server.mock(|when, then| {
            when.method(POST)
                .path("/proxy/network/v2/api/site/default/system-log/all")
                .json_body(json!({"pageSize": 120, "pageNumber": 0}));
            then.status(200).json_body(json!({
                "data": events(0, 120),
                "total_element_count": 120,
            }));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let (resp, stats) = client.list_events_paged(120).unwrap();

        login.assert();
        page.assert();
        assert_eq!(resp.status, 200);
        assert_eq!(stats.returned, 120);
        assert!(!stats.truncated);
        assert_eq!(
            resp.json.unwrap()["data"].as_array().unwrap().len(),
            120,
            "all requested events survive into the rendered payload"
        );
    }

    #[test]
    fn list_events_paged_walks_pages_until_limit_is_met() {
        // limit > SYSTEM_LOG_MAX_PAGE_SIZE must paginate rather than truncate.
        let server = MockServer::start();
        let login = login_mock(&server);
        let page1 = server.mock(|when, then| {
            when.method(POST)
                .path("/proxy/network/v2/api/site/default/system-log/all")
                .json_body(json!({"pageSize": 1000, "pageNumber": 0}));
            then.status(200).json_body(json!({
                "data": events(0, 1000),
                "total_element_count": 2500,
            }));
        });
        let page2 = server.mock(|when, then| {
            when.method(POST)
                .path("/proxy/network/v2/api/site/default/system-log/all")
                .json_body(json!({"pageSize": 1000, "pageNumber": 1}));
            then.status(200).json_body(json!({
                "data": events(1000, 1000),
                "total_element_count": 2500,
            }));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let (resp, stats) = client.list_events_paged(1500).unwrap();

        login.assert();
        page1.assert();
        page2.assert();
        assert_eq!(stats.returned, 1500, "limit honored across page boundaries");
        assert!(!stats.truncated);
        let data = resp.json.unwrap();
        let arr = data["data"].as_array().unwrap();
        assert_eq!(arr.len(), 1500);
        // Pages must be stitched in order, without gaps or repeats.
        assert_eq!(arr[0]["key"], json!("EVT_0"));
        assert_eq!(arr[999]["key"], json!("EVT_999"));
        assert_eq!(arr[1000]["key"], json!("EVT_1000"));
        assert_eq!(arr[1499]["key"], json!("EVT_1499"));
    }

    #[test]
    fn list_events_paged_stops_when_controller_runs_out() {
        // Fewer events exist than requested: that is not truncation, it is the
        // whole dataset. No warning should be raised.
        let server = MockServer::start();
        let login = login_mock(&server);
        let page = server.mock(|when, then| {
            when.method(POST)
                .path("/proxy/network/v2/api/site/default/system-log/all")
                .json_body(json!({"pageSize": 500, "pageNumber": 0}));
            then.status(200).json_body(json!({
                "data": events(0, 12),
                "total_element_count": 12,
            }));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let (_resp, stats) = client.list_events_paged(500).unwrap();

        login.assert();
        page.assert();
        assert_eq!(stats.returned, 12);
        assert_eq!(stats.total_available, Some(12));
        assert!(
            !stats.truncated,
            "exhausting the dataset is not a truncated result"
        );
    }

    #[test]
    fn list_events_paged_flags_truncation_when_more_exist() {
        // Controller clamps the page and then reports an empty follow-up page
        // while claiming more records exist. The caller MUST be told the answer
        // is incomplete rather than reading 40 as "that is all there is".
        let server = MockServer::start();
        let login = login_mock(&server);
        let page1 = server.mock(|when, then| {
            when.method(POST)
                .path("/proxy/network/v2/api/site/default/system-log/all")
                .json_body(json!({"pageSize": 200, "pageNumber": 0}));
            then.status(200).json_body(json!({
                "data": events(0, 40),
                "total_element_count": 9000,
            }));
        });
        // After the clamp we adopt the honored size (40) to keep offsets aligned.
        let page2 = server.mock(|when, then| {
            when.method(POST)
                .path("/proxy/network/v2/api/site/default/system-log/all")
                .json_body(json!({"pageSize": 40, "pageNumber": 1}));
            then.status(200).json_body(json!({
                "data": [],
                "total_element_count": 9000,
            }));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let (_resp, stats) = client.list_events_paged(200).unwrap();

        login.assert();
        page2.assert();
        page1.assert();
        assert_eq!(stats.requested, 200);
        assert_eq!(stats.returned, 40);
        assert_eq!(stats.total_available, Some(9000));
        assert!(
            stats.truncated,
            "short read while records remain must be reported, never silent"
        );
    }

    #[test]
    fn list_events_paged_surfaces_api_errors() {
        let server = MockServer::start();
        let login = login_mock(&server);
        let page = server.mock(|when, then| {
            when.method(POST)
                .path("/proxy/network/v2/api/site/default/system-log/all");
            then.status(500).json_body(json!({"error": "boom"}));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let result = client.list_events_paged(100);

        login.assert();
        page.assert();
        assert!(
            result.is_err(),
            "an API failure must propagate, not silently return a short page"
        );
    }

    #[test]
    fn mutations_have_one_submission_on_every_http_failure() {
        for method in [Method::POST, Method::PUT, Method::DELETE] {
            for status in [401, 403, 404, 405, 429, 500, 307] {
                let server = MockServer::start();
                let login = login_mock(&server);
                let primary = server.mock(|when, then| {
                    when.path("/proxy/network/api/s/default/rest/networkconf");
                    then.status(status)
                        .header("Retry-After", "0")
                        .header("Location", server.url("/must-not-follow"))
                        .body("synthetic-secret-拒否\u{1b}[31m");
                });
                let alternate = server.mock(|when, then| {
                    when.path_excludes("/api/auth/login")
                        .path_excludes("/proxy/network/api/s/default/rest/networkconf");
                    then.status(200).json_body(json!({"ok": true}));
                });
                let mut client =
                    LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
                let err = client
                    .request::<(), serde_json::Value>(
                        method.clone(),
                        true,
                        false,
                        "rest/networkconf",
                        None,
                        Some(&json!({"name":"test"})),
                    )
                    .unwrap_err()
                    .to_string();
                assert!(!err.contains("synthetic-secret"));
                assert!(!err.contains('\u{1b}'));
                if matches!(status, 404 | 405 | 500 | 307) {
                    assert!(err.contains("outcome=unknown"));
                }
                login.assert_calls(1);
                primary.assert_calls(1);
                alternate.assert_calls(0);
            }
        }
    }

    #[test]
    fn read_refresh_budget_spans_all_compatible_routes() {
        let server = MockServer::start();
        let login = login_mock(&server);
        let stale = server.mock(|when, then| {
            when.path("/proxy/network/api/s/default/stat/device")
                .header("X-CSRF-Token", "stale");
            then.status(401);
        });
        let unsupported = server.mock(|when, then| {
            when.path("/proxy/network/api/s/default/stat/device")
                .header("X-CSRF-Token", "abc123");
            then.status(404);
        });
        let denied = server.mock(|when, then| {
            when.path("/proxy/network/v2/api/site/default/stat/device");
            then.status(401);
        });
        let third = server.mock(|when, then| {
            when.path("/proxy/network/v2/api/s/default/stat/device");
            then.status(200).json_body(json!({"data":[]}));
        });
        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        client.logged_in = true;
        client.csrf = Some("stale".into());
        assert!(
            client
                .list_devices()
                .unwrap_err()
                .to_string()
                .contains("401")
        );
        stale.assert_calls(1);
        login.assert_calls(1);
        unsupported.assert_calls(1);
        denied.assert_calls(1);
        third.assert_calls(0);
    }

    #[test]
    fn forbidden_read_and_rejected_login_are_terminal() {
        for status in [401, 403, 429, 500] {
            let server = MockServer::start();
            let rejected = server.mock(|when, then| {
                when.method(POST).path("/api/auth/login");
                then.status(status).body("synthetic-password");
            });
            let later = server.mock(|when, then| {
                when.path_excludes("/api/auth/login");
                then.status(200).header("X-CSRF-Token", "unused");
            });
            let mut client =
                LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
            let error = client.list_devices().unwrap_err().to_string();
            assert!(error.contains(&format!("HTTP {status}")));
            assert!(!error.contains("synthetic-password"));
            rejected.assert_calls(1);
            later.assert_calls(0);
        }
        let server = MockServer::start();
        let login = login_mock(&server);
        let denied = server.mock(|when, then| {
            when.method(GET).path_includes("stat/device");
            then.status(403);
        });
        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        assert!(
            client
                .list_devices()
                .unwrap_err()
                .to_string()
                .contains("Permission denied")
        );
        login.assert_calls(1);
        denied.assert_calls(1);
    }

    #[test]
    fn strict_json_and_legacy_errors_do_not_report_success() {
        for body in [
            "not json",
            "<html>synthetic-secret</html>",
            "null",
            "42",
            "",
            r#"{"meta":{"rc":"error","msg":"synthetic-secret"},"data":[]}"#,
        ] {
            let server = MockServer::start();
            let login = login_mock(&server);
            let endpoint = server.mock(|when, then| {
                when.method(POST)
                    .path("/proxy/network/api/s/default/rest/networkconf");
                then.status(200).body(body);
            });
            let mut client =
                LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
            let error = client
                .create_network(&json!({"name":"test"}))
                .unwrap_err()
                .to_string();
            assert!(!error.contains("synthetic-secret"));
            login.assert_calls(1);
            endpoint.assert_calls(1);
        }
    }

    #[test]
    fn delete_no_content_is_valid_and_controller_cannot_forge_collection_metadata() {
        let server = MockServer::start();
        login_mock(&server);
        let delete = server.mock(|when, then| {
            when.method(DELETE)
                .path("/proxy/network/v2/api/site/default/static-dns/test");
            then.status(204);
        });
        let read = server.mock(|when, then| {
            when.method(GET)
                .path("/proxy/network/api/s/default/stat/device");
            then.status(200)
                .json_body(json!({"data":[],"_unifictl":{"collection":{"complete":true}}}));
        });
        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        assert_eq!(client.delete_dns_record("test").unwrap().status, 204);
        let response = client.list_devices().unwrap();
        assert!(response.json.unwrap().get("_unifictl").is_none());
        assert!(!response.body.contains("_unifictl"));
        delete.assert_calls(1);
        read.assert_calls(1);
    }

    #[test]
    fn dynamic_targets_reject_path_syntax_before_authentication() {
        let server = MockServer::start();
        let any_request = server.mock(|_, then| {
            then.status(500);
        });
        for invalid in [
            "",
            ".",
            "..",
            "../wlanconf/other",
            "one/two",
            "one\\two",
            "%2e%2e",
            "id?key=value",
            "id#fragment",
            "bad\nvalue",
        ] {
            assert!(LocalClient::new(&server.base_url(), "u", "p", invalid, true).is_err());
            let mut client =
                LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
            assert!(
                client
                    .update_network(invalid, &json!({"name":"test"}))
                    .is_err()
            );
            assert!(client.delete_dns_record(invalid).is_err());
            assert!(
                client
                    .update_object(invalid, &json!({"name":"test"}))
                    .is_err()
            );
            assert!(client.stat_spectrum_scan(invalid).is_err());
        }
        any_request.assert_calls(0);
    }

    #[test]
    fn modern_mutation_families_use_the_intended_single_route() {
        for (path, expected) in [
            (
                "rest/networkconf",
                "/proxy/network/api/s/default/rest/networkconf",
            ),
            ("cmd/devmgr", "/proxy/network/api/s/default/cmd/devmgr"),
            ("cmd/stamgr", "/proxy/network/api/s/default/cmd/stamgr"),
            (
                "static-dns",
                "/proxy/network/v2/api/site/default/static-dns",
            ),
            (
                "clients/metadata",
                "/proxy/network/v2/api/site/default/clients/metadata",
            ),
            (
                "firewall/zone",
                "/proxy/network/v2/api/site/default/firewall/zone",
            ),
            (
                "object-oriented-network-configs",
                "/proxy/network/v2/api/site/default/object-oriented-network-configs",
            ),
        ] {
            let server = MockServer::start();
            login_mock(&server);
            let exact = server.mock(|when, then| {
                when.method(POST).path(expected);
                then.status(200).json_body(json!({"ok":true}));
            });
            let mut client =
                LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
            client.post(true, path, Some(&json!({}))).unwrap();
            exact.assert_calls(1);
        }
    }

    #[test]
    fn explicit_credential_validation_cannot_succeed_from_cached_session() {
        let server = MockServer::start();
        let login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login");
            then.status(401);
        });
        let sites = server.mock(|when, then| {
            when.method(GET).path_includes("self/sites");
            then.status(200).json_body(json!({"data":[]}));
        });
        let mut client =
            LocalClient::new(&server.base_url(), "u", "old-password", "default", true).unwrap();
        client.logged_in = true;
        client.csrf = Some("valid-cached-session".into());
        assert!(client.validate_credentials().is_err());
        login.assert_calls(1);
        sites.assert_calls(0);
    }

    #[test]
    fn later_short_event_page_never_changes_the_offset() {
        let server = MockServer::start();
        login_mock(&server);
        let first = server.mock(|when, then| {
            when.method(POST)
                .path_includes("system-log/all")
                .json_body(json!({"pageSize":1000,"pageNumber":0}));
            then.status(200).json_body(json!({"data":events(0,1000)}));
        });
        let short = server.mock(|when, then| {
            when.method(POST)
                .path_includes("system-log/all")
                .json_body(json!({"pageSize":1000,"pageNumber":1}));
            then.status(200).json_body(json!({"data":events(1000,5)}));
        });
        let end = server.mock(|when, then| {
            when.method(POST)
                .path_includes("system-log/all")
                .json_body(json!({"pageSize":1000,"pageNumber":2}));
            then.status(200).json_body(json!({"data":[]}));
        });
        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let (response, stats) = client.list_events_paged(1010).unwrap();
        assert_eq!(stats.returned, 1005);
        assert!(!stats.truncated);
        let values = response.json.unwrap();
        assert_eq!(values["data"][1004]["key"], "EVT_1004");
        first.assert_calls(1);
        short.assert_calls(1);
        end.assert_calls(1);
    }

    #[test]
    fn event_pagination_rejects_wrong_shape_and_repeated_records() {
        for body in [
            json!({"unexpected":[]}),
            json!({"data":[{"id":"repeat"}],"total_element_count":3}),
        ] {
            let server = MockServer::start();
            login_mock(&server);
            let page = server.mock(|when, then| {
                when.method(POST).path_includes("system-log/all");
                then.status(200).json_body(body.clone());
            });
            let mut client =
                LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
            assert!(client.list_events_paged(3).is_err());
            assert!(page.calls() <= 2);
        }
    }

    #[test]
    fn timed_out_write_is_unknown_and_never_replayed() {
        let server = MockServer::start();
        let mutation = server.mock(|when, then| {
            when.method(POST)
                .path("/proxy/network/api/s/default/rest/networkconf");
            then.status(200)
                .delay(Duration::from_millis(250))
                .json_body(json!({"ok":true}));
        });
        let alternate = server.mock(|when, then| {
            when.path_excludes("/proxy/network/api/s/default/rest/networkconf");
            then.status(200).json_body(json!({"ok":true}));
        });
        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        client.logged_in = true;
        client.http = Client::builder()
            .timeout(Duration::from_millis(50))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        assert!(
            client
                .create_network(&json!({"name":"test"}))
                .unwrap_err()
                .to_string()
                .contains("outcome=unknown")
        );
        mutation.assert_calls(1);
        alternate.assert_calls(0);
    }

    #[test]
    fn lost_headers_and_truncated_write_body_are_unknown_without_replay() {
        use std::io::{Read, Write};
        use std::net::{Shutdown, TcpListener};
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use std::time::Instant;
        for partial_body in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            listener.set_nonblocking(true).unwrap();
            let submitted = Arc::new(AtomicUsize::new(0));
            let count = submitted.clone();
            let server = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_millis(400);
                while Instant::now() < deadline {
                    match listener.accept() {
                        Ok((mut socket, _)) => {
                            socket
                                .set_read_timeout(Some(Duration::from_millis(100)))
                                .unwrap();
                            let mut received = [0; 4096];
                            if socket.read(&mut received).unwrap_or(0) > 0 {
                                count.fetch_add(1, Ordering::SeqCst);
                                if partial_body {
                                    socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{").unwrap();
                                }
                            }
                            let _ = socket.shutdown(Shutdown::Both);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5))
                        }
                        Err(error) => panic!("synthetic server failed: {error}"),
                    }
                }
            });
            let mut client =
                LocalClient::new(&format!("http://{address}"), "u", "p", "default", true).unwrap();
            client.logged_in = true;
            let error = client
                .create_network(&json!({"name":"test"}))
                .unwrap_err()
                .to_string();
            assert!(error.contains("outcome=unknown"), "{error}");
            server.join().unwrap();
            assert_eq!(submitted.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn post_query_retry_is_bounded_without_reauthentication() {
        let server = MockServer::start();
        let login = login_mock(&server);
        let limited = server.mock(|when, then| {
            when.method(POST)
                .path("/proxy/network/v2/api/site/default/system-log/all");
            then.status(429).header("Retry-After", "0");
        });
        let fallback = server.mock(|when, then| {
            when.path("/proxy/network/api/s/default/system-log/all");
            then.status(200).json_body(json!({"data":[]}));
        });
        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        assert!(
            client
                .system_log_all(None)
                .unwrap_err()
                .to_string()
                .contains("429")
        );
        login.assert_calls(1);
        limited.assert_calls(2);
        fallback.assert_calls(0);
    }

    #[test]
    fn http_error_messages_are_body_free_and_utf8_safe() {
        let secret = "密碼\u{1b}]52;c;secret\u{7}".repeat(40);
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            let error = LocalClient::format_error_message(
                &Method::POST,
                "rest/networkconf",
                status,
                &secret,
                "https://user:password@controller.test/?key=secret",
            );
            assert!(!error.contains("密碼"));
            assert!(!error.contains("secret"));
            assert!(!error.contains("password"));
            assert!(!error.contains('\u{1b}'));
        }
    }

    #[test]
    fn cached_port_change_cannot_redirect_the_session() {
        let dir = tempfile::tempdir().unwrap();
        session::test_set_dir(dir.path());
        let intended = MockServer::start();
        let other_port = MockServer::start();
        session::save(&session::CachedSession {
            key_url: intended.base_url(),
            resolved_url: other_port.base_url(),
            username: "u".into(),
            site: "default".into(),
            is_legacy: false,
            csrf: Some("untrusted-cached-token".into()),
            session_cookie: None,
            created_at: session::now_secs(),
            trust_profile: Some(session::trust_profile(true, &[])),
        })
        .unwrap();
        let login = login_mock(&intended);
        let device = intended.mock(|when, then| {
            when.method(GET)
                .path("/proxy/network/api/s/default/stat/device")
                .header("X-CSRF-Token", "abc123");
            then.status(200).json_body(json!({"data":[]}));
        });
        let forbidden = other_port.mock(|_, then| {
            then.status(500);
        });
        let mut client = LocalClient::new(&intended.base_url(), "u", "p", "default", true).unwrap();
        client.list_devices().unwrap();
        login.assert_calls(1);
        device.assert_calls(1);
        forbidden.assert_calls(0);
    }

    #[test]
    fn from_config_enforces_ca_and_target_validation() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = crate::config::LocalEffectiveConfig {
            url: "https://controller.invalid/".into(),
            username: "u".into(),
            password: "p".into(),
            site: "default".into(),
            verify_tls: true,
            ca_file: None,
            port_fallback: false,
        };
        assert!(LocalClient::from_config(&config).is_ok());
        config.ca_file = Some(temp.path().join("missing.pem"));
        assert!(LocalClient::from_config(&config).is_err());
        let invalid_ca = temp.path().join("invalid.pem");
        std::fs::write(&invalid_ca, "synthetic-invalid-ca").unwrap();
        config.ca_file = Some(invalid_ca);
        assert!(LocalClient::from_config(&config).is_err());
        config.verify_tls = false;
        assert!(
            LocalClient::from_config(&config)
                .unwrap_err()
                .to_string()
                .contains("requires TLS verification")
        );
        config.ca_file = None;
        config.url = "https://user:secret@controller.invalid/".into();
        assert!(LocalClient::from_config(&config).is_err());
        config.url = "https://controller.invalid/".into();
        config.site = "../other".into();
        assert!(LocalClient::from_config(&config).is_err());
    }

    #[test]
    fn cached_credentials_cannot_cross_tls_trust_profiles() {
        for (cached_profile, current_verify) in [
            (Some(session::trust_profile(true, &[])), false),
            (Some(session::trust_profile(false, &[])), true),
            (Some(session::trust_profile(true, b"old-custom-ca")), true),
            (None, true),
        ] {
            let dir = tempfile::tempdir().unwrap();
            session::test_set_dir(dir.path());
            let server = MockServer::start();
            session::save(&session::CachedSession {
                key_url: server.base_url(),
                resolved_url: server.base_url(),
                username: "u".into(),
                site: "default".into(),
                is_legacy: false,
                csrf: None,
                session_cookie: Some("TOKEN=synthetic-user-secret".into()),
                created_at: session::now_secs(),
                trust_profile: cached_profile,
            })
            .unwrap();
            let login = server.mock(|when,then| {
                when.method(POST).path("/api/auth/login")
                    .json_body(json!({"username":"u","password":"untrusted-project-placeholder","remember":true,"strict":true}));
                then.status(401);
            });
            let leak = server.mock(|when, then| {
                when.header("Cookie", "TOKEN=synthetic-user-secret");
                then.status(200).json_body(json!({"data":[]}));
            });
            let mut client = LocalClient::new(
                &server.base_url(),
                "u",
                "untrusted-project-placeholder",
                "default",
                current_verify,
            )
            .unwrap();
            assert!(client.list_devices().is_err());
            login.assert_calls(1);
            leak.assert_calls(0);
        }
    }

    #[test]
    fn session_trust_profile_changes_with_tls_policy_and_ca_contents() {
        assert_eq!(
            session::trust_profile(true, b"ca-a"),
            session::trust_profile(true, b"ca-a")
        );
        assert_ne!(
            session::trust_profile(true, b"ca-a"),
            session::trust_profile(false, b"ca-a")
        );
        assert_ne!(
            session::trust_profile(true, b"ca-a"),
            session::trust_profile(true, b"ca-b")
        );
        assert_ne!(
            session::trust_profile(true, b"ca-a"),
            session::trust_profile(true, &[])
        );
    }

    #[test]
    fn persistent_401_blocks_later_operations_without_new_logins() {
        let server = MockServer::start();
        let login = login_mock(&server);
        let health = server.mock(|when, then| {
            when.method(GET).path_includes("stat/health");
            then.status(401);
        });
        let later = server.mock(|when, then| {
            when.method(GET).path_excludes("stat/health");
            then.status(200).json_body(json!({"data":[]}));
        });
        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let error = client.list_health().unwrap_err().context("health source");
        assert!(should_stop_batch(&error));
        assert!(should_stop_batch(&client.list_devices().unwrap_err()));
        assert!(should_stop_batch(&client.list_sites().unwrap_err()));
        assert!(should_stop_batch(
            &client.validate_credentials().unwrap_err()
        ));
        login.assert_calls(2);
        health.assert_calls(2);
        later.assert_calls(0);
    }

    #[test]
    fn successful_refresh_is_not_reset_by_the_next_operation() {
        let server = MockServer::start();
        let login = login_mock(&server);
        let stale = server.mock(|when, then| {
            when.method(GET)
                .path_includes("stat/health")
                .header("X-CSRF-Token", "stale");
            then.status(401);
        });
        let healthy = server.mock(|when, then| {
            when.method(GET)
                .path_includes("stat/health")
                .header("X-CSRF-Token", "abc123");
            then.status(200).json_body(json!({"data":[]}));
        });
        let expired = server.mock(|when, then| {
            when.method(GET).path_includes("stat/device");
            then.status(401);
        });
        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        client.logged_in = true;
        client.csrf = Some("stale".into());
        client.list_health().unwrap();
        assert!(should_stop_batch(&client.list_devices().unwrap_err()));
        assert!(should_stop_batch(&client.list_health().unwrap_err()));
        login.assert_calls(1);
        stale.assert_calls(1);
        healthy.assert_calls(1);
        expired.assert_calls(1);
    }

    #[test]
    fn login_denial_is_latched_and_terminal_status_is_typed() {
        for status in [401, 403, 429, 500] {
            let server = MockServer::start();
            let denied = server.mock(|when, then| {
                when.method(POST).path("/api/auth/login");
                then.status(status).body("synthetic-private-body");
            });
            let later = server.mock(|when, then| {
                when.path_excludes("/api/auth/login");
                then.status(200).json_body(json!({"data":[]}));
            });
            let mut client =
                LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
            for result in [
                client.list_health(),
                client.list_devices(),
                client.validate_credentials(),
            ] {
                let error = result.unwrap_err().context("source failed");
                assert_eq!(should_stop_batch(&error), matches!(status, 401 | 403 | 429));
                assert!(!format!("{error:#}").contains("synthetic-private-body"));
            }
            denied.assert_calls(1);
            later.assert_calls(0);
        }
        assert!(!should_stop_batch(&anyhow!(
            "untrusted text mentions HTTP 401"
        )));
    }

    #[test]
    fn collection_contract_is_explicit_and_method_specific() {
        for path in [
            "self/sites",
            "stat/device",
            "stat/sta",
            "clients/active",
            "clients/history",
            "list/alarm",
            "stat/health",
            "rest/networkconf",
            "static-dns",
            "rest/wlanconf",
            "rest/portconf",
            "rest/firewallrule",
            "rest/firewallgroup",
            "rest/routing",
            "firewall/zone",
            "object-oriented-network-configs",
        ] {
            assert!(expects_collection(&Method::GET, path), "{path}");
            for method in [Method::POST, Method::PUT, Method::DELETE] {
                assert!(!expects_collection(&method, path), "{method} {path}");
            }
        }
        for path in [
            "system-log/all",
            "system-log/critical",
            "system-log/device-alert",
            "system-log/admin-activity",
        ] {
            assert!(expects_collection(&Method::POST, path), "{path}");
            assert!(!expects_collection(&Method::GET, path), "{path}");
        }
        for path in [
            "system-log/setting",
            "system-log/count",
            "wifi-connectivity",
            "traffic",
            "traffic-flows",
            "rest/setting/security",
            "cmd/devmgr",
        ] {
            assert!(!expects_collection(&Method::GET, path), "{path}");
            assert!(!expects_collection(&Method::POST, path), "{path}");
        }
    }

    #[test]
    fn collections_reject_wrong_shapes_without_fallback_and_accept_empty_arrays() {
        for body in [
            json!({"unexpected":true}),
            json!({"error":"synthetic-private-body"}),
            json!({}),
            json!({"data":null}),
            json!({"data":{}}),
            json!({"data":"wrong"}),
            json!([]),
            json!({"data":[]}),
            json!([{"id":"one"}]),
            json!({"data":[{"id":"one"}]}),
        ] {
            for method in [Method::GET, Method::POST] {
                let server = MockServer::start();
                let login = login_mock(&server);
                let endpoint = if method == Method::GET {
                    "/proxy/network/api/s/default/stat/device"
                } else {
                    "/proxy/network/v2/api/site/default/system-log/all"
                };
                let response = server.mock(|when, then| {
                    when.method(method.as_str()).path(endpoint);
                    then.status(200).json_body(body.clone());
                });
                let fallback = server.mock(|when, then| {
                    when.path_excludes("/api/auth/login")
                        .path_excludes(endpoint);
                    then.status(200).json_body(json!({"data":[]}));
                });
                let mut client =
                    LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
                let result = if method == Method::GET {
                    client.list_devices()
                } else {
                    client.system_log_all(None)
                };
                assert_eq!(
                    result.is_ok(),
                    list_payload(&body).is_some(),
                    "{method} {body}"
                );
                if let Err(error) = result {
                    assert!(
                        error
                            .to_string()
                            .contains("invalid controller collection response")
                    );
                    assert!(!error.to_string().contains("synthetic-private-body"));
                }
                login.assert_calls(1);
                response.assert_calls(1);
                fallback.assert_calls(0);
            }
        }
    }

    #[test]
    fn settings_and_mutations_keep_object_response_contracts() {
        let server = MockServer::start();
        login_mock(&server);
        let settings = server.mock(|when, then| {
            when.method(GET)
                .path("/proxy/network/v2/api/site/default/system-log/setting");
            then.status(200)
                .json_body(json!({"enabled":true,"error":"an ordinary field"}));
        });
        let mutation = server.mock(|when, then| {
            when.method(POST)
                .path("/proxy/network/v2/api/site/default/static-dns");
            then.status(200).json_body(json!({"id":"created"}));
        });
        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        assert_eq!(
            client.system_log_settings().unwrap().json.unwrap()["enabled"],
            true
        );
        assert_eq!(
            client
                .create_dns_record(&json!({"key":"example.invalid"}))
                .unwrap()
                .json
                .unwrap()["id"],
            "created"
        );
        settings.assert_calls(1);
        mutation.assert_calls(1);
    }

    #[test]
    fn derived_collections_filter_bare_arrays() {
        let server = MockServer::start();
        login_mock(&server);
        let devices = server.mock(|when, then| {
            when.method(GET).path_includes("stat/device");
            then.status(200).json_body(json!([{"mac":"a"},{"mac":"b"}]));
        });
        let health = server.mock(|when, then| {
            when.method(GET).path_includes("stat/health");
            then.status(200)
                .json_body(json!([{"subsystem":"wan"},{"subsystem":"vpn"}]));
        });
        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        assert_eq!(
            client.device_stats("b").unwrap().json.unwrap(),
            json!([{"mac":"b"}])
        );
        assert_eq!(
            client.vpn_health().unwrap().json.unwrap(),
            json!([{"subsystem":"vpn"}])
        );
        devices.assert_calls(1);
        health.assert_calls(1);
    }

    #[test]
    fn event_pagination_rejects_changed_reported_total() {
        let server = MockServer::start();
        login_mock(&server);
        let first = server.mock(|when, then| {
            when.method(POST)
                .path_includes("system-log/all")
                .json_body(json!({"pageSize":3,"pageNumber":0}));
            then.status(200)
                .json_body(json!({"data":[{"id":"first"}],"total_element_count":3}));
        });
        let changed = server.mock(|when, then| {
            when.method(POST)
                .path_includes("system-log/all")
                .json_body(json!({"pageSize":1,"pageNumber":1}));
            then.status(200)
                .json_body(json!({"data":[{"id":"second"}],"total_element_count":4}));
        });
        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        assert!(
            client
                .list_events_paged(3)
                .unwrap_err()
                .to_string()
                .contains("inventory changed")
        );
        first.assert_calls(1);
        changed.assert_calls(1);
    }
}

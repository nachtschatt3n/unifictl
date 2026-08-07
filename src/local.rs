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
    /// `base_url` when login falls back from `:8443` to `:443`).
    configured_url: String,
    http: Client,
    username: String,
    password: String,
    site: String,
    logged_in: bool,
    is_legacy: bool,
    csrf: Option<String>,
    session_cookie: Option<String>,
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
        };
        client.restore_cached_session();
        Ok(client)
    }

    /// Adopt a persisted session, if one is cached for this controller. The
    /// session is used optimistically: its validity is only confirmed on the
    /// first request (a genuine 401/403 triggers exactly one re-login).
    fn restore_cached_session(&mut self) {
        if let Some(sess) = session::load(&self.configured_url, &self.username, &self.site) {
            // Only adopt the cached resolved URL if it shares the configured
            // controller's scheme and host. A tampered cache must not be able to
            // redirect requests — or, via the 401 re-login path, the credential
            // POST — to an attacker-controlled host. The port may legitimately
            // differ (8443 -> 443 fallback), so it is not compared.
            let resolved = match Url::parse(&sess.resolved_url) {
                Ok(u)
                    if u.scheme() == self.base_url.scheme()
                        && u.host_str() == self.base_url.host_str() =>
                {
                    u
                }
                // Untrusted or mismatched cache entry: ignore it and fall back
                // to a fresh login against the configured URL.
                _ => return,
            };
            self.base_url = resolved;
            self.csrf = sess.csrf;
            self.session_cookie = sess.session_cookie;
            self.is_legacy = sess.is_legacy;
            self.logged_in = true;
        }
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
        // Legacy `stat/event` is gone on modern UniFi OS. The general event feed
        // now lives at `/proxy/network/v2/api/site/{site}/system-log/all` (POST,
        // returns `{"data":[...]}`). Requires a JSON body — send `{}`.
        //
        // NOTE: an empty body means the controller applies its own default
        // page size (50). Callers that honor a user-supplied `--limit` must use
        // [`LocalClient::list_events_paged`] instead.
        let payload = serde_json::json!({});
        self.post(true, "system-log/all", Some(&payload))
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

            let json = match resp.json.clone() {
                Some(j) => j,
                None => {
                    last_resp = Some(resp);
                    break;
                }
            };
            if let Some(total) = json
                .get("total_element_count")
                .and_then(|v| v.as_u64())
                .map(|v| v as usize)
            {
                total_available = Some(total);
            }
            let page_items = list_payload(&json).cloned().unwrap_or_default();
            let got = page_items.len();
            collected.extend(page_items);
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
            if got < page_size {
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
        self.put(true, &format!("rest/networkconf/{id}"), Some(payload))
    }

    pub fn delete_network(&mut self, id: &str) -> Result<ResponseData> {
        self.delete(true, &format!("rest/networkconf/{id}"))
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
        self.put(true, &format!("static-dns/{id}"), Some(payload))
    }

    pub fn delete_dns_record(&mut self, id: &str) -> Result<ResponseData> {
        self.delete(true, &format!("static-dns/{id}"))
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
        self.ensure_login()?;
        let urls = self.build_urls(site_scoped, fallback_global, path)?;

        let send_once = |mut r: reqwest::blocking::RequestBuilder,
                         csrf: &Option<String>,
                         session_cookie: &Option<String>| {
            if let Some(token) = csrf {
                r = r.header("X-CSRF-Token", token);
            }
            if let Some(cookie) = session_cookie {
                r = r.header(COOKIE, cookie);
            }
            r.send()
        };

        let mut last_err: Option<anyhow::Error> = None;

        for url in urls {
            let mut resp = send_once(
                self.build_request(&method, &url, query, body),
                &self.csrf,
                &self.session_cookie,
            );

            // Genuine session expiry (401/403): re-login exactly once and retry.
            // A 429 (rate limit) or a network timeout must NEVER reach this
            // branch — re-authenticating on a 429 extends the per-IP lockout.
            if let Ok(r) = &resp
                && matches!(r.status(), StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
            {
                self.force_relogin()?;
                resp = send_once(
                    self.build_request(&method, &url, query, body),
                    &self.csrf,
                    &self.session_cookie,
                );
            }

            // Rate limited (429) on an idempotent read: honor Retry-After by
            // backing off once and retrying WITHOUT re-authenticating.
            if method == Method::GET
                && let Ok(r) = &resp
                && r.status() == StatusCode::TOO_MANY_REQUESTS
                && let Some(wait) = parse_retry_after(r)
                && wait <= RETRY_AFTER_CAP_SECS
            {
                std::thread::sleep(Duration::from_secs(wait));
                resp = send_once(
                    self.build_request(&method, &url, query, body),
                    &self.csrf,
                    &self.session_cookie,
                );
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
                    // Classify transport failures distinctly from auth failures:
                    // a timeout/connection error is not an expired session and
                    // must never trigger a re-login.
                    let msg = if err.is_timeout() {
                        format!(
                            "Network timeout talking to the controller at {url} — not an authentication problem; the session was not re-authenticated"
                        )
                    } else if err.is_connect() {
                        format!(
                            "Connection error reaching the controller at {url} — not an authentication problem; the session was not re-authenticated"
                        )
                    } else {
                        format!("{err} at {url}")
                    };
                    last_err = Some(anyhow!(msg));
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
        self.session_cookie = None;
        // Invalidate the stale on-disk session; login() rewrites it on success.
        session::clear();
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
                        if !login_established(&resp) {
                            last_err = Some(anyhow::anyhow!(
                                "login succeeded at {} but no session cookie or CSRF token was returned",
                                url
                            ));
                            continue;
                        }
                        self.base_url = base.clone();
                        self.is_legacy = path.contains("api/login");
                        self.logged_in = true;
                        if let Some(token) = extract_csrf(&resp) {
                            self.csrf = Some(token);
                        }
                        self.session_cookie = extract_session_cookie(&resp);
                        self.persist_session();
                        return Ok(());
                    }
                    Err(err) => {
                        if err.to_string().contains("HTTP 429") {
                            return Err(anyhow::anyhow!("login failed at {}: {}", url, err));
                        }
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
        let resp = self
            .http
            .post(url.clone())
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .header(
                "X-Requested-With",
                HeaderValue::from_static("XMLHttpRequest"),
            )
            .json(creds)
            .send()
            .context("sending login request")?;

        // Detect HTTP -> HTTPS redirect: the POST body is dropped on redirect (301 becomes GET),
        // so login appears to succeed but no session cookie is set, causing silent auth failure.
        if url.scheme() == "http" && resp.url().scheme() == "https" {
            let https_url = format!(
                "https://{}{}",
                url.host_str().unwrap_or("your-controller"),
                url.port().map(|p| format!(":{p}")).unwrap_or_default()
            );
            eprintln!(
                "Warning: controller at {url} redirected to HTTPS. \
                 Update your controller URL to avoid authentication failures:\n  \
                 unifictl login --controller-url \"{https_url}\" ..."
            );
            return Err(anyhow::anyhow!(
                "controller redirected http:// to https:// — re-run login with https://"
            ));
        }

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            let detail = format_login_error(&body);
            return Err(anyhow!(
                "HTTP {} {}",
                status.as_u16(),
                if detail.is_empty() {
                    status
                        .canonical_reason()
                        .unwrap_or("login request failed")
                        .to_string()
                } else {
                    detail
                }
            ));
        }

        Ok(resp)
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

        if status == StatusCode::TOO_MANY_REQUESTS {
            // A 429 is rate limiting, NOT an expired session. Re-authenticating
            // here would extend the controller's per-IP login lockout, so this
            // must never be conflated with the 401 "session expired" path.
            let detail = format_login_error(body);
            let detail_line = if detail.is_empty() {
                String::new()
            } else {
                format!("\n\nController: {detail}")
            };
            return format!(
                "Rate limited (429) at {url_str} - the controller is throttling requests, NOT a session expiry.{detail_line}\n\nWhat to do:\n  • Back off and retry after the rate-limit window; do NOT re-login on a 429 (it extends the per-IP lockout)\n  • Reads on a still-valid session can keep working - verify liveness with:\n      unifictl local health get"
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

fn format_login_error(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|json| {
            let message = json
                .get("message")
                .and_then(|m| m.as_str())
                .map(str::to_string);
            let code = json
                .get("code")
                .and_then(|c| c.as_str())
                .map(str::to_string);
            match (message, code) {
                (Some(message), Some(code)) => Some(format!("{message} ({code})")),
                (Some(message), None) => Some(message),
                (None, Some(code)) => Some(code),
                (None, None) => None,
            }
        })
        .unwrap_or_else(|| body.trim().to_string())
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
    fn login_requires_session_artifacts_and_falls_back() {
        let server = MockServer::start();
        let incomplete_login = server.mock(|when, then| {
            when.method(POST).path("/api/auth/login").json_body(
                json!({"username": "u", "password": "p", "remember": true, "strict": true}),
            );
            then.status(200).json_body(json!({"ok": true}));
        });
        let fallback_login = server.mock(|when, then| {
            when.method(POST)
                .path("/proxy/network/api/auth/login")
                .json_body(
                    json!({"username": "u", "password": "p", "remember": true, "strict": true}),
                );
            then.status(200)
                .header("Set-Cookie", "TOKEN=session-123; Path=/; HttpOnly")
                .json_body(json!({"ok": true}));
        });
        let devices = server.mock(|when, then| {
            when.method(GET)
                .path("/proxy/network/api/s/default/stat/device")
                .header("Cookie", "TOKEN=session-123");
            then.status(200).json_body(json!({"data": []}));
        });

        let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
        let resp = client.list_devices().unwrap();

        incomplete_login.assert();
        fallback_login.assert();
        devices.assert();
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn format_login_error_uses_controller_message_and_code() {
        let msg = format_login_error(
            r#"{"message":"You've reached the login attempt limit","code":"AUTHENTICATION_FAILED_LIMIT_REACHED"}"#,
        );
        assert_eq!(
            msg,
            "You've reached the login attempt limit (AUTHENTICATION_FAILED_LIMIT_REACHED)"
        );
    }

    #[test]
    fn format_login_error_falls_back_to_plain_text() {
        let msg = format_login_error("plain text failure");
        assert_eq!(msg, "plain text failure");
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
        legacy.assert_hits(0);
        assert!(err.contains("HTTP 429"));
        assert!(err.contains("AUTHENTICATION_FAILED_LIMIT_REACHED"));
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
        // Controller detail surfaced for triage.
        assert!(msg.contains("AUTHENTICATION_FAILED_LIMIT_REACHED"));
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

        login.assert_hits(1);
        devices.assert_hits(2);
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

        stale.assert_hits(1);
        login.assert_hits(1); // exactly one re-auth
        fresh.assert_hits(1);
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
        })
        .unwrap();

        // Every candidate device URL is rate limited (no Retry-After header).
        let devices = server.mock(|when, then| {
            when.method(GET).path_contains("stat/device");
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

        login.assert_hits(0); // a 429 must NEVER trigger a re-login
        assert!(devices.hits() >= 1);
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
        login.assert_hits(1);
        devices.assert_hits(1);
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
    fn list_events_uses_v2_system_log_all() {
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
        let resp = client.list_events().unwrap();

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
}

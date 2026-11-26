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

use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, HeaderValue, USER_AGENT};
use reqwest::{Method, Url};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct ResponseData {
    pub status: u16,
    pub body: String,
    pub json: Option<Value>,
}

#[derive(Clone)]
pub struct ApiClient {
    base_url: Url,
    http: Client,
    api_key: String,
}

/// Encode one externally supplied identifier before composing an API route.
pub(crate) fn id_segment(id: &str) -> Result<String> {
    if id.is_empty()
        || matches!(id, "." | "..")
        || !id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-._:".contains(&c))
    {
        bail!("invalid API path segment");
    }
    Ok(id.replace(':', "%3A"))
}

impl ApiClient {
    pub fn new(base_url: &str, api_key: &str, allow_http_mock: bool) -> Result<Self> {
        let parsed = Url::parse(base_url).context("parsing base URL")?;
        let loopback = match parsed.host() {
            Some(url_host) => match url_host.to_string().as_str() {
                "localhost" => true,
                host => host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback()),
            },
            None => false,
        };
        if parsed.host().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            bail!(
                "cloud URL requires a host and may not include credentials, a query or a fragment"
            );
        }
        if parsed.scheme() != "https" && !(parsed.scheme() == "http" && allow_http_mock && loopback)
        {
            bail!("use HTTPS for the cloud API; for a loopback mock, pass --allow-http-mock");
        }
        let http = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(HeaderValue::from_static("unifictl/0.1"))
            .build()
            .context("building HTTP client")?;

        Ok(Self {
            base_url: parsed,
            http,
            api_key: api_key.to_string(),
        })
    }

    pub fn get(&self, path: &str, query: &[(&str, String)]) -> Result<ResponseData> {
        self.request(Method::GET, path, query, Option::<&Value>::None)
    }

    pub fn post_json<T: Serialize + ?Sized>(
        &self,
        path: &str,
        query: &[(&str, String)],
        body: Option<&T>,
    ) -> Result<ResponseData> {
        self.request(Method::POST, path, query, body)
    }

    fn request<T: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&T>,
    ) -> Result<ResponseData> {
        let normalized = path
            .strip_prefix('/')
            .context("expected absolute API path")?;
        for part in normalized.split('/') {
            let decoded = part.replace("%3A", ":");
            if id_segment(&decoded)? != part {
                bail!("invalid API path segment");
            }
        }
        let url = self
            .base_url
            .join(normalized)
            .with_context(|| format!("joining path `{}` to base URL", path))?;

        let mut request = self
            .http
            .request(method, url)
            .header("X-API-Key", &self.api_key)
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .header(USER_AGENT, HeaderValue::from_static("unifictl/0.1"));

        if !query.is_empty() {
            request = request.query(query);
        }

        if let Some(body) = body {
            request = request.json(body);
        }

        let response = request
            .send()
            .map_err(|_| anyhow::anyhow!("cloud request failed (connection, TLS, or timeout)"))?;
        if !response.status().is_success() {
            bail!(
                "cloud request rejected (HTTP {})",
                response.status().as_u16()
            );
        }

        let status = response.status().as_u16();
        let text = response.text().context("reading response body")?;
        let json = serde_json::from_str(&text).ok();

        Ok(ResponseData {
            status,
            body: text,
            json,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;
    use serde_json::json;

    #[test]
    fn sends_api_key_and_parses_json() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET)
                .path("/v1/hosts")
                .header("X-API-Key", "test-key");
            then.status(200).json_body(json!({"ok": true, "items": []}));
        });

        let client = ApiClient::new(&server.base_url(), "test-key", true).unwrap();
        let response = client.get("/v1/hosts", &[]).unwrap();

        mock.assert();
        assert_eq!(response.status, 200);
        assert_eq!(response.json.unwrap()["ok"], true);
    }

    #[test]
    fn posts_json_body() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/ea/isp-metrics/5m/query")
                .json_body(json!({"siteId": "123"}));
            then.status(200).body(r#"{"result": "ok"}"#);
        });

        let client = ApiClient::new(&server.base_url(), "abc", true).unwrap();
        let response = client
            .post_json(
                "/ea/isp-metrics/5m/query",
                &[],
                Some(&json!({"siteId": "123"})),
            )
            .unwrap();

        mock.assert();
        assert_eq!(response.json.unwrap()["result"], "ok");
    }

    #[test]
    fn loopback_http_is_explicit_and_cloud_credentials_stay_on_origin() {
        let origin = MockServer::start();
        let destination = MockServer::start();
        assert!(ApiClient::new(&origin.base_url(), "test-key", false).is_err());
        assert!(ApiClient::new("http://example.invalid", "test-key", true).is_err());
        assert!(ApiClient::new("https://user@example.invalid", "test-key", false).is_err());
        let redirect = origin.mock(|when, then| {
            when.method(GET).path("/v1/hosts");
            then.status(302)
                .header("location", destination.url("/next"));
        });
        let other = destination.mock(|when, then| {
            when.path("/next");
            then.status(200);
        });
        let api = ApiClient::new(&origin.base_url(), "test-key", true).unwrap();
        assert!(api.get("/v1/hosts", &[]).is_err());
        redirect.assert();
        other.assert_hits(0);
        for id in ["", ".", "..", "a/b", "a?b", "%2f"] {
            assert!(id_segment(id).is_err());
        }
        assert_eq!(id_segment("aabbcc:42").unwrap(), "aabbcc%3A42");
    }
}

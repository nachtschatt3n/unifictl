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

impl std::fmt::Debug for ApiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiClient")
            .field("base_url", &self.base_url)
            .field("api_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Credentials are sent only to an explicit HTTP(S) authority, without URL
/// userinfo or query/fragment data. HTTP requires a deliberate insecure mode.
pub(crate) fn validate_base_url(value: &str, allow_http: bool) -> Result<Url> {
    let url = Url::parse(value).context("parsing controller URL")?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("controller URL must contain a host and no credentials, query or fragment");
    }
    if url.scheme() != "https" && !(allow_http && url.scheme() == "http") {
        bail!(
            "HTTPS is required; configure a trusted CA, or explicitly select --insecure for a local controller"
        );
    }
    Ok(url)
}

impl ApiClient {
    pub fn new(base_url: &str, api_key: &str) -> Result<Self> {
        let parsed = validate_base_url(base_url, cfg!(test))?;
        let http = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(5))
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
        let normalized = path.trim_start_matches('/');
        if normalized.split('/').any(|s| {
            s.is_empty()
                || s == "."
                || s == ".."
                || !s
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        }) {
            bail!("invalid API path segment");
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

        let response = request.send().map_err(|err| {
            if err.is_timeout() {
                anyhow::anyhow!("cloud request timed out")
            } else {
                anyhow::anyhow!(
                    "cloud request failed (connection or TLS); response details suppressed"
                )
            }
        })?;
        let status = response.status().as_u16();
        if !response.status().is_success() {
            bail!("cloud request rejected (HTTP {status}); response body suppressed");
        }
        let mut text = response
            .text()
            .map_err(|_| anyhow::anyhow!("could not read cloud response body"))?;
        let mut json: Value = serde_json::from_str(&text)
            .map_err(|_| anyhow::anyhow!("cloud returned invalid JSON"))?;
        if !json.is_object() && !json.is_array() {
            bail!("cloud returned an unexpected response shape");
        }
        if let Some(object) = json.as_object_mut()
            && object.remove("_unifictl").is_some()
        {
            text = serde_json::to_string(&json)?;
        }
        let json = Some(json);

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

        let client = ApiClient::new(&server.base_url(), "test-key").unwrap();
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

        let client = ApiClient::new(&server.base_url(), "abc").unwrap();
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
    fn redirects_never_forward_api_keys() {
        let destination = MockServer::start();
        let leak = destination.mock(|when, then| {
            when.path("/capture");
            then.status(200).json_body(json!({}));
        });
        for code in [301, 302, 303, 307, 308] {
            let origin = MockServer::start();
            origin.mock(|when, then| {
                when.path("/v1/hosts");
                then.status(code)
                    .header("location", format!("{}/capture", destination.base_url()));
            });
            let client = ApiClient::new(&origin.base_url(), "synthetic-secret").unwrap();
            assert!(client.get("/v1/hosts", &[]).is_err());
        }
        leak.assert_calls(0);
    }

    #[test]
    fn validates_urls_paths_and_redacts_failures() {
        for url in [
            "http://controller.test",
            "ftp://controller.test",
            "https://u:p@controller.test",
            "https://controller.test/?secret=x",
        ] {
            assert!(validate_base_url(url, false).is_err());
        }
        let server = MockServer::start();
        server.mock(|when, then| {
            when.path("/v1/hosts");
            then.status(500).body("synthetic-secret\u{1b}[31m");
        });
        let client = ApiClient::new(&server.base_url(), "synthetic-secret").unwrap();
        let error = format!("{:?}", client.get("/v1/hosts", &[]).unwrap_err());
        assert!(!error.contains("synthetic-secret"));
        assert!(!format!("{client:?}").contains("synthetic-secret"));
        for path in [
            "/v1/hosts/../sites",
            "/v1/hosts/a?x=y",
            "/v1/hosts/%2f",
            "https://other.test",
        ] {
            assert!(
                client
                    .get(path, &[])
                    .unwrap_err()
                    .to_string()
                    .contains("invalid API path")
            );
        }
    }

    #[test]
    fn rejects_non_json_success_and_reserved_metadata() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.path("/invalid");
            then.status(200).body("<html>login</html>");
        });
        server.mock(|when, then| {
            when.path("/valid");
            then.status(200)
                .json_body(json!({"data":[], "_unifictl":{"complete":true}}));
        });
        let client = ApiClient::new(&server.base_url(), "key").unwrap();
        assert!(client.get("/invalid", &[]).is_err());
        assert!(
            client
                .get("/valid", &[])
                .unwrap()
                .json
                .unwrap()
                .get("_unifictl")
                .is_none()
        );
    }
}

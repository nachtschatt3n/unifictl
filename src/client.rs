use anyhow::{Context, Result};
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

#[derive(Debug, Clone)]
pub struct ApiClient {
    base_url: Url,
    http: Client,
    api_key: String,
}

impl ApiClient {
    pub fn new(base_url: &str, api_key: &str) -> Result<Self> {
        let parsed = Url::parse(base_url).context("parsing base URL")?;
        let http = Client::builder()
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
            .and_then(|r| r.error_for_status())
            .context("sending request")?;

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
}

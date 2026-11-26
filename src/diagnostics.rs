//! Bounded, opt-in diagnostics for untrusted HTTP error responses.

use regex::Regex;
use reqwest::{StatusCode, Url, blocking::Response};
use serde_json::Value;
use std::io::{Read, Write};
use std::sync::{Mutex, OnceLock};

const MAX_BODY_BYTES: usize = 8192;
const MAX_SUMMARY_CHARS: usize = 200;
const MAX_DEBUG_BYTES: usize = 8192;
// A process may try several compatibility routes. Bound the whole debug stream,
// not only each response. This budget never affects successful response output.
static DEBUG_REMAINING: Mutex<usize> = Mutex::new(MAX_DEBUG_BYTES);

#[derive(Default)]
struct Details {
    summary: String,
    debug: Option<String>,
}

/// Omit URL credentials, paths, queries and fragments from diagnostic context.
pub fn endpoint(url: &Url) -> String {
    strip_controls(&url.origin().ascii_serialization())
}

/// Do not retain reqwest's source chain, which can contain a credential-bearing URL.
pub fn transport_error(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "network request timed out"
    } else if error.is_connect() {
        "connection failed (check reachability and TLS trust)"
    } else if error.is_redirect() {
        "request redirect failed"
    } else if error.is_body() || error.is_decode() {
        "could not read response body"
    } else {
        "HTTP transport failed"
    }
}

/// Return only a sanitized short summary. Optional body diagnostics go directly
/// to stderr; callers must never copy the body or an unsanitized URL into errors.
/// `secrets` contains current credentials/session artifacts. `request_body` lets
/// validation errors redact an echoed write secret even outside a named field.
pub fn response_details(
    mut response: Response,
    login: bool,
    secrets: &[&str],
    request_body: Option<Value>,
) -> String {
    let status = response.status();
    if login || matches!(status.as_u16(), 401 | 403 | 429) || status.is_success() {
        return String::new();
    }
    let debug_enabled = std::env::var_os("UNIFICTL_DEBUG").is_some_and(|value| value == "1");
    if !debug_enabled && !matches!(status.as_u16(), 400 | 409 | 422) {
        return String::new();
    }
    let mut sensitive: Vec<String> = secrets.iter().map(|s| (*s).to_string()).collect();
    // A Cookie header is usually stored as name=value; redact its value when
    // echoed without the name as well as the complete header.
    for secret in secrets {
        sensitive.extend(secret.split(';').filter_map(|part| {
            part.split_once('=')
                .map(|(_, value)| value.trim().to_string())
        }));
    }
    sensitive.push(response.url().username().to_string());
    if let Some(password) = response.url().password() {
        sensitive.push(password.to_string());
    }
    sensitive.extend(
        response
            .url()
            .query_pairs()
            .map(|(_, value)| value.into_owned()),
    );
    if let Some(body) = request_body {
        collect_secrets(&body, &mut sensitive);
    }
    let details = read_details(&mut response, status, sensitive);
    if debug_enabled && let Some(debug) = details.debug {
        emit_debug(status, &debug);
    }
    details.summary
}

fn read_details(reader: impl Read, status: StatusCode, mut secrets: Vec<String>) -> Details {
    let mut body = Vec::new();
    if reader
        .take((MAX_BODY_BYTES + 1) as u64)
        .read_to_end(&mut body)
        .is_err()
    {
        return omitted("body omitted: could not read bounded response");
    }
    // Never parse a truncated prefix or fall back to raw text. In particular,
    // secret fields could occur beyond the cutoff and be echoed earlier.
    if body.len() > MAX_BODY_BYTES {
        return omitted("body omitted: response exceeds 8192-byte input limit");
    }
    let Ok(mut value) = serde_json::from_slice::<Value>(&body) else {
        return omitted("body omitted: response is not valid JSON");
    };
    if !value.is_object() && !value.is_array() {
        return omitted("body omitted: response is not a JSON object or array");
    }
    collect_secrets(&value, &mut secrets);
    let original = secrets.clone();
    for secret in original {
        secrets.push(strip_controls(&secret));
        let encoded: String =
            reqwest::Url::parse_with_params("https://redaction.invalid", [("v", &secret)])
                .expect("static URL is valid")
                .query()
                .unwrap_or_default()
                .trim_start_matches("v=")
                .to_string();
        secrets.push(encoded.replace('+', "%20"));
        secrets.push(encoded);
    }
    secrets.retain(|value| !value.is_empty());
    secrets.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
    secrets.dedup();
    let pattern = secrets
        .iter()
        .map(|secret| regex::escape(secret))
        .collect::<Vec<_>>()
        .join("|");
    if pattern.len() > 64 * 1024 {
        return omitted("body omitted: redaction context exceeds safety limit");
    }
    let known = if pattern.is_empty() {
        None
    } else {
        match regex::RegexBuilder::new(&pattern)
            .size_limit(256 * 1024)
            .build()
        {
            Ok(regex) => Some(regex),
            Err(_) => return omitted("body omitted: redaction context is too complex"),
        }
    };
    sanitize(&mut value, known.as_ref());
    let summary = if matches!(status.as_u16(), 400 | 409 | 422) {
        let scopes = [&value, &value["meta"], &value["error"]];
        let message = scopes.iter().find_map(|scope| {
            scope
                .get("message")
                .or_else(|| scope.get("msg"))
                .and_then(Value::as_str)
        });
        let code = scopes.iter().find_map(|scope| {
            scope.get("code").and_then(|code| match code {
                Value::String(code) => Some(code.clone()),
                Value::Number(code) => Some(code.to_string()),
                _ => None,
            })
        });
        let summary = match (message, code) {
            (Some(message), Some(code)) => format!("{message} ({code})"),
            (Some(message), None) => message.to_string(),
            (None, Some(code)) => code,
            _ => String::new(),
        };
        cap_chars(&summary, MAX_SUMMARY_CHARS)
    } else {
        String::new()
    };
    Details {
        summary,
        debug: serde_json::to_string(&value).ok(),
    }
}

fn omitted(reason: &str) -> Details {
    Details {
        summary: String::new(),
        debug: Some(reason.to_string()),
    }
}

fn secret_key(key: &str) -> bool {
    let key: String = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    [
        "password",
        "passwd",
        "passphrase",
        "token",
        "secret",
        "key",
        "credential",
        "authorization",
        "cookie",
        "csrf",
        "session",
        "username",
        "query",
    ]
    .iter()
    .any(|part| key.contains(part))
        || key == "pwd"
        || key == "psk"
}

fn collect_values(value: &Value, secrets: &mut Vec<String>) {
    match value {
        Value::String(value) => secrets.push(value.clone()),
        Value::Number(value) => secrets.push(value.to_string()),
        Value::Array(values) => values
            .iter()
            .for_each(|value| collect_values(value, secrets)),
        Value::Object(values) => values
            .values()
            .for_each(|value| collect_values(value, secrets)),
        _ => (),
    }
}

fn collect_secrets(value: &Value, secrets: &mut Vec<String>) {
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                if secret_key(key) {
                    collect_values(value, secrets);
                }
                collect_secrets(value, secrets);
            }
        }
        Value::Array(values) => values
            .iter()
            .for_each(|value| collect_secrets(value, secrets)),
        _ => (),
    }
}

fn sanitize(value: &mut Value, known: Option<&Regex>) {
    match value {
        Value::Object(values) => {
            let entries = std::mem::take(values);
            for (key, mut value) in entries {
                if secret_key(&key) {
                    value = Value::String("[REDACTED]".into());
                } else {
                    sanitize(&mut value, known);
                }
                values.insert(sanitize_text(&key, known), value);
            }
        }
        Value::Array(values) => values.iter_mut().for_each(|value| sanitize(value, known)),
        Value::String(value) => *value = sanitize_text(value, known),
        Value::Number(number) if known.is_some_and(|regex| regex.is_match(&number.to_string())) => {
            *value = Value::String("[REDACTED]".into());
        }
        _ => (),
    }
}

fn strip_controls(text: &str) -> String {
    text.chars().filter(|c| !c.is_control() && !matches!(c,
        '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )).collect()
}

fn sanitize_text(text: &str, known: Option<&Regex>) -> String {
    static URL: OnceLock<Regex> = OnceLock::new();
    static SENSITIVE_TEXT: OnceLock<Regex> = OnceLock::new();
    let mut text = strip_controls(text);
    // One pass over the original text: never re-redact inserted markers, which
    // could otherwise expand exponentially for many short secret values.
    if let Some(known) = known {
        text = known.replace_all(&text, "[REDACTED]").into_owned();
    }
    let urls = URL.get_or_init(|| Regex::new(r#"(?i)[a-z][a-z0-9+.-]*://[^\s<>\"']+"#).unwrap());
    text = urls.replace_all(&text, "[REDACTED URL]").into_owned();
    // Unstructured credentials/query fragments cannot be safely parsed. Omit
    // the whole string instead of guessing where the sensitive value ends.
    let sensitive = SENSITIVE_TEXT.get_or_init(|| Regex::new(
        r#"(?i)(?:password|passwd|passphrase|token|secret|key|credential|authorization|cookie|csrf|session|username|pwd|psk)[\"'\s]*[:=]|\b(?:bearer|basic)\s+\S+|[?&][^\s]*="#
    ).unwrap());
    if sensitive.is_match(&text) {
        return "[REDACTED sensitive text]".into();
    }
    text
}

fn cap_chars(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    let mut capped: String = text.chars().take(limit.saturating_sub(1)).collect();
    capped.push('…');
    capped
}

fn cap_bytes(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_string();
    }
    let suffix = " [truncated]";
    if limit < suffix.len() {
        return String::new();
    }
    let mut end = limit - suffix.len();
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{suffix}", &text[..end])
}

fn emit_debug(status: StatusCode, body: &str) {
    let Ok(mut remaining) = DEBUG_REMAINING.lock() else {
        return;
    };
    let prefix = format!(
        "UNIFICTL_DEBUG: sanitized diagnostics may still be sensitive (HTTP {}). ",
        status.as_u16()
    );
    if *remaining <= prefix.len() + 32 {
        return;
    }
    let message = cap_bytes(&format!("{prefix}{body}"), *remaining - 1);
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "{message}");
    *remaining -= message.len() + 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn details(status: u16, value: Value) -> Details {
        read_details(
            value.to_string().as_bytes(),
            StatusCode::from_u16(status).unwrap(),
            vec![],
        )
    }

    #[test]
    fn summary_is_allowed_only_for_validation_statuses_and_is_character_bounded() {
        for status in [400, 409, 422] {
            let result = details(
                status,
                json!({"meta":{"msg":"é💃".repeat(200),"code":"api.err.InvalidPayload"}}),
            );
            assert_eq!(result.summary.chars().count(), 200);
            assert!(result.summary.ends_with('…'));
        }
        for status in [404, 500, 302] {
            assert!(
                details(status, json!({"message":"private"}))
                    .summary
                    .is_empty()
            );
        }
        assert_eq!(
            details(400, json!({"error":{"message":"Invalid VLAN","code":42}})).summary,
            "Invalid VLAN (42)"
        );
    }

    #[test]
    fn secret_keys_and_echoes_are_redacted_case_insensitively_at_any_depth() {
        let result = details(
            400,
            json!({"message":"echo submitted-secret","data":[{"X_PaSsPhRaSe":"submitted-secret","ToKeN":"token-value"}],"Password":"password-value","apiKEY":"key-value","nested":{"SECRET":"secret-value"}}),
        );
        let debug = result.debug.unwrap();
        for secret in [
            "submitted-secret",
            "token-value",
            "password-value",
            "key-value",
            "secret-value",
        ] {
            assert!(!debug.contains(secret), "{secret}: {debug}");
            assert!(!result.summary.contains(secret));
        }
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn credentials_query_urls_and_controls_do_not_survive() {
        let result=read_details(json!({"message":"bad known-password / known%20password","url":"https://user:unknown@host/?api_key=unknown","query":"?opaque=unknown","header":"Bearer unknown","detail":"PaSsWoRd: unknown","safe":"Invalid\u{1b}[2J\nVLAN\u{85}\u{202e}\u{2066}"}).to_string().as_bytes(),StatusCode::BAD_REQUEST,vec!["known-password".into(),"known password".into()]);
        let debug = result.debug.unwrap();
        for secret in ["known-password", "known%20password", "unknown"] {
            assert!(!debug.contains(secret));
        }
        assert!(!debug.contains(['\x1b', '\n', '\u{85}', '\u{202e}', '\u{2066}']));
        assert!(debug.contains("Invalid[2JVLAN"));
        assert_eq!(
            endpoint(&Url::parse("https://u:p@host/path-secret?q=secret#fragment").unwrap()),
            "https://host"
        );
    }

    #[test]
    fn oversized_malformed_scalar_and_failed_read_bodies_fail_closed() {
        for body in [
            format!(
                "{{\"message\":\"prefix-secret\",\"tail\":\"{}\"}}",
                "é".repeat(5000)
            ),
            "<html>raw-secret</html>".into(),
            "\"raw-secret\"".into(),
            "{invalid raw-secret".into(),
        ] {
            let result = read_details(body.as_bytes(), StatusCode::BAD_REQUEST, vec![]);
            assert!(result.summary.is_empty());
            let debug = result.debug.unwrap();
            assert!(debug.starts_with("body omitted:"));
            assert!(!debug.contains("secret"));
        }
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("read-secret"))
            }
        }
        let result = read_details(Broken, StatusCode::BAD_REQUEST, vec![]);
        assert!(result.summary.is_empty());
        assert!(!result.debug.unwrap().contains("read-secret"));
    }

    #[test]
    fn byte_limit_does_not_split_unicode() {
        let text = "💃é".repeat(2000);
        let limited = cap_bytes(&text, MAX_DEBUG_BYTES);
        assert!(limited.len() <= MAX_DEBUG_BYTES);
        assert!(limited.ends_with("[truncated]"));
    }

    #[test]
    fn short_secrets_do_not_rewrite_inserted_redaction_markers() {
        let result = read_details(
            br#"{"message":"R E D A C T"}"#.as_slice(),
            StatusCode::BAD_REQUEST,
            ["R", "E", "D", "A", "C", "T"].map(String::from).to_vec(),
        );
        assert_eq!(
            result.summary,
            "[REDACTED] [REDACTED] [REDACTED] [REDACTED] [REDACTED] [REDACTED]"
        );
        assert!(result.debug.unwrap().len() < 100);
    }
}

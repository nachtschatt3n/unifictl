use assert_cmd::cargo::cargo_bin_cmd;
use httpmock::prelude::*;
use serde_json::{Value, json};
use tempfile::TempDir;

fn config(server: &MockServer) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("config.yaml"), serde_json::to_vec(&json!({
        "api_key":"synthetic-api-key", "base_url":server.base_url(),
        "local":{"url":server.base_url(),"username":"synthetic-user","password":"synthetic-password","site":"default","verify_tls":false}
    })).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            dir.path().join("config.yaml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    dir
}

fn cli(dir: &TempDir) -> assert_cmd::Command {
    let mut command = cargo_bin_cmd!("unifictl");
    command
        .current_dir(dir.path())
        .env("UNIFICTL_CONFIG_DIR", dir.path())
        .env("UNIFICTL_NO_SESSION_CACHE", "1")
        .env_remove("UNIFICTL_DEBUG");
    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        command.env_remove(key);
    }
    command
}

fn login(server: &MockServer) -> httpmock::Mock<'_> {
    server.mock(|when, then| {
        when.method(POST).path("/api/auth/login");
        then.status(200)
            .header("X-CSRF-Token", "synthetic-csrf")
            .header("Set-Cookie", "TOKEN=synthetic-session; Path=/; HttpOnly")
            .json_body(json!({"ok":true}));
    })
}

fn command(kind: &str) -> [&str; 3] {
    if kind == "local" {
        ["local", "device", "list"]
    } else {
        ["cloud", "host", "list"]
    }
}

#[test]
fn validation_errors_share_short_details_and_stderr_only_channels() {
    for kind in ["local", "cloud"] {
        for status in [400, 409, 422] {
            let server = MockServer::start();
            let dir = config(&server);
            let _login = login(&server);
            let _error=server.mock(|when,then| {
                when.method(GET);
                then.status(status).json_body(json!({"message":"Invalid VLAN\u{1b}[2J\n\u{202e}","code":"api.err.InvalidPayload","data":[{"field":"debug-only-field"}]}));
            });
            for format in ["pretty", "json", "raw"] {
                let out = cli(&dir)
                    .args(command(kind))
                    .args(["-o", format])
                    .output()
                    .unwrap();
                assert!(!out.status.success());
                assert!(out.stdout.is_empty(), "{kind}: {:?}", out.stdout);
                let error = String::from_utf8(out.stderr).unwrap();
                assert!(error.contains("Invalid VLAN[2J"), "{error}");
                assert!(error.contains("api.err.InvalidPayload"));
                assert!(!error.contains("debug-only-field"));
                assert!(!error.contains(['\x1b', '\u{202e}']));
            }
        }
    }
}

#[test]
fn debug_requires_exact_opt_in_and_redacts_nested_keys_and_echoed_credentials() {
    for kind in ["local", "cloud"] {
        let server = MockServer::start();
        let dir = config(&server);
        let _login = login(&server);
        let _error=server.mock(|when,then| {
            when.method(GET);
            then.status(500).json_body(json!({"message":"debug-only-message","data":[{"field":"debug-only-field","PaSsWoRd":"secret-one","x_PASSPHRASE":"secret-two","ToKeN":"secret-three","SECRET":"secret-four","Key":"secret-five","normal":"echo secret-two"}],"known":"synthetic-api-key synthetic-user synthetic-password synthetic-csrf synthetic-session","url":"https://embedded-user:embedded-secret@host.invalid/?opaque=embedded-query","control":"line\u{1b}[2J\u{85}\u{200f}\u{202e}\n"}));
        });
        for flag in [None, Some("0"), Some("true"), Some("1")] {
            let mut cmd = cli(&dir);
            cmd.args(command(kind)).args(["-o", "json"]);
            if let Some(flag) = flag {
                cmd.env("UNIFICTL_DEBUG", flag);
            }
            let out = cmd.output().unwrap();
            assert!(!out.status.success());
            assert!(out.stdout.is_empty());
            let error = String::from_utf8(out.stderr).unwrap();
            if flag == Some("1") {
                assert!(error.contains("may still be sensitive"));
                assert!(error.contains("debug-only-field"));
                assert!(error.contains("[REDACTED]"));
                // Each client only knows its own credentials; secrets named by
                // the response itself must be removed independently of client.
                for secret in [
                    "secret-one",
                    "secret-two",
                    "secret-three",
                    "secret-four",
                    "secret-five",
                    "embedded-user",
                    "embedded-secret",
                    "embedded-query",
                ] {
                    assert!(!error.contains(secret), "{error}");
                }
                let known = if kind == "local" {
                    vec![
                        "synthetic-user",
                        "synthetic-password",
                        "synthetic-csrf",
                        "synthetic-session",
                    ]
                } else {
                    vec!["synthetic-api-key"]
                };
                for secret in known {
                    assert!(!error.contains(secret), "{error}");
                }
                assert!(!error.contains(['\x1b', '\u{85}', '\u{200f}', '\u{202e}']));
            } else {
                assert!(!error.contains("debug-only"));
                assert!(!error.contains("UNIFICTL_DEBUG"));
            }
        }
    }
}

#[test]
fn authentication_rate_limit_and_every_login_body_are_suppressed_even_in_debug() {
    for kind in ["local", "cloud"] {
        for status in [401, 403, 429] {
            let server = MockServer::start();
            let dir = config(&server);
            let _login = login(&server);
            let _error=server.mock(|when,then| {
                when.method(GET);
                then.status(status).json_body(json!({"message":"forbidden-body-marker","code":"secret-code","data":"secret-body"}));
            });
            let out = cli(&dir)
                .env("UNIFICTL_DEBUG", "1")
                .args(command(kind))
                .output()
                .unwrap();
            assert!(!out.status.success());
            assert!(out.stdout.is_empty());
            let error = String::from_utf8(out.stderr).unwrap();
            assert!(
                !error.contains("forbidden-body-marker")
                    && !error.contains("secret-code")
                    && !error.contains("secret-body")
                    && !error.contains("UNIFICTL_DEBUG"),
                "{error}"
            );
        }
    }
    for status in [400, 401, 403, 409, 422, 429, 500] {
        let server = MockServer::start();
        let dir = config(&server);
        let _error = server.mock(|when, then| {
            when.method(POST);
            then.status(status)
                .json_body(json!({"message":"login-body-marker","code":"login-code"}));
        });
        let out = cli(&dir)
            .env("UNIFICTL_DEBUG", "1")
            .args(command("local"))
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
        let error = String::from_utf8(out.stderr).unwrap();
        assert!(
            !error.contains("login-body-marker")
                && !error.contains("login-code")
                && !error.contains("UNIFICTL_DEBUG"),
            "{error}"
        );
    }
}

#[test]
fn oversized_and_non_json_error_bodies_never_emit_a_raw_prefix() {
    for kind in ["local", "cloud"] {
        for body in [
            json!({"message":"prefix-secret","tail":"💃".repeat(3000)}).to_string(),
            "<html>prefix-secret\u{1b}[2J</html>".into(),
            "{\"message\":\"prefix-secret\",invalid".into(),
            "\"prefix-secret\"".into(),
        ] {
            let server = MockServer::start();
            let dir = config(&server);
            let _login = login(&server);
            let _error = server.mock(|when, then| {
                when.method(GET);
                then.status(400).body(&body);
            });
            let out = cli(&dir)
                .env("UNIFICTL_DEBUG", "1")
                .args(command(kind))
                .output()
                .unwrap();
            assert!(!out.status.success());
            assert!(out.stdout.is_empty());
            let error = String::from_utf8(out.stderr).unwrap();
            assert!(error.contains("body omitted:"), "{error}");
            assert!(!error.contains("prefix-secret"));
            assert!(error.len() < 8192);
        }
    }
}

#[test]
fn debug_budget_is_per_process_across_fallback_routes_and_unicode_safe() {
    let server = MockServer::start();
    let dir = config(&server);
    let _login = login(&server);
    let error = server.mock(|when, then| {
        when.method(GET);
        then.status(404)
            .json_body(json!({"data":"💃é".repeat(1100)}));
    });
    let out = cli(&dir)
        .env("UNIFICTL_DEBUG", "1")
        .args(command("local"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let text = String::from_utf8(out.stderr).unwrap();
    let debug_bytes: usize = text
        .lines()
        .filter(|line| line.starts_with("UNIFICTL_DEBUG:"))
        .map(|line| line.len() + 1)
        .sum();
    assert!(debug_bytes <= 8192 && debug_bytes > 6600, "{debug_bytes}");
    assert!(text.contains("[truncated]"));
    assert!(error.hits() > 1);
}

#[test]
fn submitted_secret_is_redacted_even_when_echoed_under_an_unrelated_key() {
    let server = MockServer::start();
    let dir = config(&server);
    let _login = login(&server);
    let _error=server.mock(|when,then| {
        when.method(POST).path_contains("wlanconf");
        then.status(422).json_body(json!({"message":"rejected submitted-wlan-passphrase","field":"x_passphrase","echo":"submitted-wlan-passphrase"}));
    });
    let out = cli(&dir)
        .env("UNIFICTL_DEBUG", "1")
        .args([
            "local",
            "wlan",
            "create",
            "--name",
            "synthetic",
            "--password",
            "submitted-wlan-passphrase",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let text = String::from_utf8(out.stderr).unwrap();
    assert!(text.contains("[REDACTED]"), "{text}");
    assert!(!text.contains("submitted-wlan-passphrase"));
}

#[test]
fn successful_json_and_raw_body_shapes_remain_unchanged_with_debug_enabled() {
    for payload in [
        json!([{"name":"synthetic"}]),
        json!({"meta":{"rc":"ok"},"data":[{"name":"synthetic"}]}),
    ] {
        let server = MockServer::start();
        let dir = config(&server);
        let _request = server.mock(|when, then| {
            when.method(GET);
            then.status(200).json_body(payload.clone());
        });
        for output in ["json", "raw"] {
            let out = cli(&dir)
                .env("UNIFICTL_DEBUG", "1")
                .args(command("cloud"))
                .args(["-o", output])
                .output()
                .unwrap();
            assert!(out.status.success());
            assert_eq!(
                serde_json::from_slice::<Value>(&out.stdout).unwrap(),
                payload
            );
            assert_eq!(out.stdout, format!("{payload}\n").into_bytes());
            assert!(
                out.stderr.is_empty(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}

#[test]
fn validate_keeps_error_details_off_stdout() {
    let server = MockServer::start();
    let dir = config(&server);
    let _login = login(&server);
    let _request = server.mock(|when, then| {
        when.method(GET);
        then.status(400)
            .json_body(json!({"message":"validation-detail-marker"}));
    });
    for kind in ["--cloud-only", "--local-only"] {
        let out = cli(&dir)
            .env("UNIFICTL_DEBUG", "1")
            .args(["login", "validate", kind])
            .output()
            .unwrap();
        assert!(!String::from_utf8_lossy(&out.stdout).contains("validation-detail-marker"));
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("validation-detail-marker"),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn request_query_values_are_redacted_from_echoes() {
    let server = MockServer::start();
    let dir = config(&server);
    let request = server.mock(|when, then| {
        when.method(GET)
            .path("/v1/sites")
            .query_param("hostId", "private-query-value");
        then.status(400).json_body(
            json!({"message":"Invalid private-query-value","extra":"echo private-query-value"}),
        );
    });
    let out = cli(&dir)
        .env("UNIFICTL_DEBUG", "1")
        .args(["cloud", "site", "list", "--host-id", "private-query-value"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let text = String::from_utf8(out.stderr).unwrap();
    assert!(text.contains("Invalid"), "{text}");
    assert!(!text.contains("private-query-value"), "{text}");
    request.assert_hits(1);
}

#[test]
fn transport_errors_do_not_include_request_url_credentials_or_query() {
    let server = MockServer::start();
    let dir = config(&server);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut config: Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("config.yaml")).unwrap()).unwrap();
    let url = format!("http://url-user:url-password@127.0.0.1:{port}/private-path?q=private-query");
    config["base_url"] = json!(url);
    config["local"]["url"] = json!(url);
    std::fs::write(dir.path().join("config.yaml"), config.to_string()).unwrap();
    for kind in ["cloud", "local"] {
        let out = cli(&dir)
            .env("UNIFICTL_DEBUG", "1")
            .args(command(kind))
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
        let text = String::from_utf8(out.stderr).unwrap();
        for secret in ["url-user", "url-password", "private-path", "private-query"] {
            assert!(!text.contains(secret), "{text}");
        }
    }
}

#[test]
fn route_fallback_does_not_erase_a_validation_diagnostic() {
    let server = MockServer::start();
    let dir = config(&server);
    let _login = login(&server);
    let validation = server.mock(|when, then| {
        when.method(GET)
            .path("/proxy/network/api/s/default/stat/device");
        then.status(400)
            .json_body(json!({"message":"Invalid VLAN","code":"api.err.InvalidPayload"}));
    });
    let _unsupported = server.mock(|when, then| {
        when.method(GET);
        then.status(404);
    });
    let out = cli(&dir).args(command("local")).output().unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let text = String::from_utf8(out.stderr).unwrap();
    assert!(
        text.contains("Invalid VLAN") && text.contains("api.err.InvalidPayload"),
        "{text}"
    );
    validation.assert_hits(1);
}

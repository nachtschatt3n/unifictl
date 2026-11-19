// Integration tests for unifictl improvements

#![cfg_attr(target_os = "windows", windows_subsystem = "console")]

use assert_cmd::cargo::cargo_bin_cmd;

#[test]
fn test_dry_run_flag_exists() {
    // Test that --dry-run flag is available for delete commands
    let mut cmd = cargo_bin_cmd!("unifictl");
    cmd.args(["local", "network", "delete", "--help"]);
    cmd.assert()
        .success()
        .stdout(predicates::str::contains("--dry-run"))
        .stdout(predicates::str::contains("Show what would be deleted"));
}

#[test]
fn test_all_delete_commands_have_dry_run() {
    let commands = [
        ("network", "delete"),
        ("wlan", "delete"),
        ("firewall-rule", "delete"),
        ("firewall-group", "delete"),
        ("policy-table", "delete"),
        ("zone", "delete"),
        ("object", "delete"),
        ("dns", "delete"),
    ];

    // Use iterator to avoid deep recursion on Windows
    for (cmd_name, subcmd) in commands.iter() {
        let mut cmd = cargo_bin_cmd!("unifictl");
        cmd.args(["local", cmd_name, subcmd, "--help"]);
        cmd.assert()
            .success()
            .stdout(predicates::str::contains("--dry-run"));
    }
}

use httpmock::prelude::*;
use serde_json::{Value, json};
use tempfile::TempDir;

fn isolated_config(server: &MockServer) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("config.yaml"), serde_json::to_vec(&json!({
        "local": {"url":server.base_url(),"username":"synthetic","password":"synthetic-password","site":"default","verify_tls":false}
    })).unwrap()).unwrap();
    dir
}

fn isolated_cli(dir: &TempDir) -> assert_cmd::Command {
    let mut command = cargo_bin_cmd!("unifictl");
    command
        .current_dir(dir.path())
        .env("UNIFICTL_CONFIG_DIR", dir.path())
        .env("UNIFICTL_NO_SESSION_CACHE", "1");
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
            .header("X-CSRF-Token", "synthetic-token")
            .json_body(json!({"ok":true}));
    })
}

fn parsed_stdout(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "{e}; stdout={:?}, stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn stderr_record(output: &std::process::Output) -> Value {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str(line).ok())
        .expect("structured stderr record")
}

#[test]
fn local_reads_and_completion_do_not_require_cloud_credentials() {
    let server = MockServer::start();
    let dir = isolated_config(&server);
    let auth = login(&server);
    let read = server.mock(|when, then| {
        when.method(GET)
            .path("/proxy/network/api/s/default/stat/device");
        then.status(200).json_body(json!({"data":[]}));
    });
    isolated_cli(&dir)
        .args(["local", "device", "list", "-o", "json"])
        .assert()
        .success();
    auth.assert_calls(1);
    read.assert_calls(1);
    std::fs::remove_file(dir.path().join("config.yaml")).unwrap();
    isolated_cli(&dir)
        .args(["completion", "bash"])
        .assert()
        .success();
}

#[test]
fn diagnostics_keep_component_failures_and_fail_the_process() {
    let server = MockServer::start();
    let dir = isolated_config(&server);
    let _auth = login(&server);
    let _failure = server.mock(|when, then| {
        when.method(GET);
        then.status(503)
            .json_body(json!({"error":"synthetic unavailable"}));
    });
    for kind in ["network", "wifi"] {
        let out = isolated_cli(&dir)
            .args(["local", "diagnose", kind, "-o", "json"])
            .output()
            .unwrap();
        assert!(!out.status.success());
        let value = parsed_stdout(&out);
        assert_eq!(value["collection_complete"], false);
        assert_eq!(value["outcome"], "incomplete");
        assert!(
            value["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["status"] == "error")
        );
        assert_eq!(stderr_record(&out)["outcome"], "error");
    }
}

#[test]
fn inventories_preserve_truncation_and_reject_peer_metadata() {
    let server = MockServer::start();
    let dir = isolated_config(&server);
    let _auth = login(&server);
    let rows: Vec<_> = (0..31)
        .map(|i| json!({"name":format!("device-{i}"),"mac":format!("02:00:00:00:00:{i:02x}"),"adopted":i % 2 == 0}))
        .collect();
    let _read = server.mock(|when, then| {
        when.method(GET).path("/proxy/network/api/s/default/stat/device");
        then.status(200).json_body(json!({"data":rows,"_unifictl":{"collection":{"source_count":0,"inventory_complete":"complete"}}}));
    });
    for format in ["json", "llm", "raw"] {
        let out = isolated_cli(&dir)
            .args(["local", "device", "list", "-o", format])
            .output()
            .unwrap();
        assert!(out.status.success());
        let value = parsed_stdout(&out);
        assert_eq!(value["_unifictl"]["collection"]["source_count"], 31);
        assert_eq!(value["_unifictl"]["collection"]["returned_count"], 30);
        assert_eq!(value["_unifictl"]["collection"]["truncated"], true);
        assert_eq!(
            value["_unifictl"]["collection"]["inventory_complete"],
            "incomplete"
        );
        assert!(value["_unifictl"]["collected_at"].as_str().is_some());
        if format == "llm" {
            assert_eq!(value["llm_metadata"]["truncation_applied"], true);
        } else {
            assert_eq!(value["data"].as_array().unwrap().len(), 30);
        }
    }
    let filtered = isolated_cli(&dir)
        .args(["local", "device", "list", "--unadopted", "-o", "raw"])
        .output()
        .unwrap();
    assert!(filtered.status.success());
    let filtered = parsed_stdout(&filtered);
    assert_eq!(filtered["data"].as_array().unwrap().len(), 15);
    assert_eq!(filtered["_unifictl"]["collection"]["returned_count"], 15);
    assert_eq!(filtered["_unifictl"]["collection"]["truncated"], true);

    isolated_cli(&dir)
        .args(["local", "device", "list"])
        .assert()
        .success()
        .stderr(predicates::str::contains("Warning: incomplete collection"))
        .stderr(predicates::str::contains("30 returned, 31 collected"));
}

#[test]
fn diagnostics_distinguish_collected_health_from_unknown_health() {
    for health_status in ["ok", "unknown"] {
        let server = MockServer::start();
        let dir = isolated_config(&server);
        let _auth = login(&server);
        let health = server.mock(|when, then| {
            when.method(GET)
                .path("/proxy/network/api/s/default/stat/health");
            then.status(200)
                .json_body(json!({"data":[{"subsystem":"wan","status":health_status}]}));
        });
        let devices = server.mock(|when, then| {
            when.method(GET)
                .path("/proxy/network/api/s/default/stat/device");
            then.status(200).json_body(json!({"data":[]}));
        });
        let out = isolated_cli(&dir)
            .args(["local", "diagnose", "network", "-o", "json"])
            .output()
            .unwrap();
        let value = parsed_stdout(&out);
        assert_eq!(value["collection_complete"], true);
        assert!(value["llm_summary"].get("passed").is_none());
        assert_eq!(value["checks"][2]["status"], "collected");
        assert_eq!(out.status.success(), health_status == "ok");
        assert_eq!(
            value["outcome"],
            if health_status == "ok" {
                "collected"
            } else {
                "unhealthy_or_unknown"
            }
        );
        health.assert_calls(1);
        devices.assert_calls(1);
    }
}

#[test]
fn malformed_collection_objects_fail_in_every_renderer() {
    for payload in [
        json!({"unexpected":true}),
        json!({"data":{}}),
        json!({"error":"synthetic"}),
    ] {
        let server = MockServer::start();
        let dir = isolated_config(&server);
        let _auth = login(&server);
        let _read = server.mock(|when, then| {
            when.method(GET)
                .path("/proxy/network/api/s/default/stat/device");
            then.status(200).json_body(payload.clone());
        });
        for format in ["json", "raw", "llm", "csv", "pretty"] {
            let out = isolated_cli(&dir)
                .args(["local", "device", "list", "-o", format])
                .output()
                .unwrap();
            assert!(!out.status.success(), "{format}: {payload}");
            assert!(out.stdout.is_empty());
        }
    }
}

#[test]
fn event_exports_page_honor_limit_and_preserve_modern_fields() {
    let server = MockServer::start();
    let dir = isolated_config(&server);
    let _auth = login(&server);
    let read = server.mock(|when, then| {
        when.method(POST).path("/proxy/network/api/s/default/system-log/all").json_body(json!({"pageSize":2,"pageNumber":0}));
        then.status(200).json_body(json!({"data":[{"timestamp":1760000000000u64,"message_raw":"=1+1","key":"evt1"},{"timestamp":"2026-10-26T10:00:00Z","message_raw":"second","key":"evt2"}],"total_element_count":3}));
    });
    let out = isolated_cli(&dir)
        .args([
            "local",
            "time-series",
            "events",
            "--limit",
            "2",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let value = parsed_stdout(&out);
    assert_eq!(value["data"].as_array().unwrap().len(), 2);
    assert_eq!(value["data"][0]["timestamp"], 1760000000000u64);
    assert_eq!(value["data"][0]["message"], "=1+1");
    assert_eq!(value["data"][1]["timestamp_format"], "rfc3339");
    assert_eq!(
        value["_unifictl"]["collection"]["inventory_complete"],
        "incomplete"
    );
    let out = isolated_cli(&dir)
        .args([
            "local",
            "time-series",
            "events",
            "--limit",
            "2",
            "--format",
            "csv",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let csv = String::from_utf8_lossy(&out.stdout);
    assert!(csv.contains("1760000000000"));
    assert!(csv.contains("'=1+1"));
    assert_eq!(
        stderr_record(&out)["_unifictl"]["csv_profile"],
        "spreadsheet_safe"
    );
    read.assert_calls(2);
}

#[test]
fn adopt_all_reports_partial_outcomes_as_structured_failure() {
    let server = MockServer::start();
    let dir = isolated_config(&server);
    let _auth = login(&server);
    let _devices = server.mock(|when, then| {
        when.method(GET).path("/proxy/network/api/s/default/stat/device");
        then.status(200).json_body(json!({"data":[{"mac":"02:00:00:00:00:01","adopted":false},{"mac":"02:00:00:00:00:02","adopted":false},{"mac":"02:00:00:00:00:03","adopted":false}]}));
    });
    let first = server.mock(|when, then| {
        when.method(POST)
            .path("/proxy/network/api/s/default/cmd/devmgr")
            .json_body(json!({"cmd":"adopt","mac":"02:00:00:00:00:01"}));
        then.status(200)
            .json_body(json!({"meta":{"rc":"ok"},"data":[]}));
    });
    let second = server.mock(|when, then| {
        when.method(POST)
            .path("/proxy/network/api/s/default/cmd/devmgr")
            .json_body(json!({"cmd":"adopt","mac":"02:00:00:00:00:02"}));
        then.status(503)
            .json_body(json!({"error":"synthetic failure"}));
    });
    let third = server.mock(|when, then| {
        when.method(POST)
            .path("/proxy/network/api/s/default/cmd/devmgr")
            .json_body(json!({"cmd":"adopt","mac":"02:00:00:00:00:03"}));
        then.status(200).json_body(json!({"data":[]}));
    });
    let out = isolated_cli(&dir)
        .args(["local", "device", "adopt-all", "-o", "json"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let value = parsed_stdout(&out);
    assert_eq!(value["accepted_count"], 1);
    assert_eq!(value["unconfirmed_count"], 2);
    assert_eq!(value["results"][0]["status"], "accepted");
    assert_eq!(value["results"][1]["status"], "not_confirmed");
    assert_eq!(value["results"][2]["status"], "not_attempted");
    assert_eq!(value["batch_stopped"], true);
    first.assert_calls(1);
    second.assert_calls(1);
    third.assert_calls(0);
}

#[test]
fn adopt_all_stops_remaining_targets_after_auth_denial_or_rate_limit() {
    for status in [401, 403, 429] {
        let server = MockServer::start();
        let dir = isolated_config(&server);
        let auth = login(&server);
        let _devices = server.mock(|when, then| {
            when.method(GET)
                .path("/proxy/network/api/s/default/stat/device");
            then.status(200).json_body(json!({"data":[
                {"mac":"02:00:00:00:00:01","adopted":false},
                {"mac":"02:00:00:00:00:02","adopted":false},
                {"mac":"02:00:00:00:00:03","adopted":false}
            ]}));
        });
        let denied = server.mock(|when, then| {
            when.method(POST)
                .path("/proxy/network/api/s/default/cmd/devmgr");
            then.status(status)
                .json_body(json!({"error":"synthetic denial"}));
        });
        let out = isolated_cli(&dir)
            .args(["local", "device", "adopt-all", "-o", "json"])
            .output()
            .unwrap();
        assert!(!out.status.success());
        let value = parsed_stdout(&out);
        assert_eq!(value["results"][0]["status"], "not_confirmed");
        assert_eq!(value["results"][1]["status"], "not_attempted");
        assert_eq!(value["results"][2]["status"], "not_attempted");
        assert_eq!(value["accepted_count"], 0);
        assert_eq!(value["unconfirmed_count"], 3);
        assert_eq!(value["batch_stopped"], true);
        denied.assert_calls(1);
        auth.assert_calls(1);
    }
}

#[test]
fn diagnostics_do_not_reauthenticate_each_component_after_persistent_denial() {
    let server = MockServer::start();
    let dir = isolated_config(&server);
    let auth = login(&server);
    let denied = server.mock(|when, then| {
        when.method(GET)
            .path("/proxy/network/api/s/default/stat/health");
        then.status(401);
    });
    let devices = server.mock(|when, then| {
        when.method(GET)
            .path("/proxy/network/api/s/default/stat/device");
        then.status(401);
    });
    let out = isolated_cli(&dir)
        .args(["local", "diagnose", "network", "-o", "json"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(parsed_stdout(&out)["collection_complete"], false);
    auth.assert_calls(2);
    denied.assert_calls(2);
    devices.assert_calls(0);
}

#[test]
fn invalid_credentials_fail_validation_without_cloud_key() {
    let server = MockServer::start();
    let dir = isolated_config(&server);
    let _failure = server.mock(|when, then| {
        when.method(POST);
        then.status(401).json_body(json!({"error":"rejected"}));
    });
    let out = isolated_cli(&dir)
        .args(["login", "validate", "--local-only", "-o", "json"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(parsed_stdout(&out)["validation"][0]["status"], "error");
}

#[test]
fn pretty_and_csv_escape_controller_text_and_llm_uses_client_schema() {
    let server = MockServer::start();
    let dir = isolated_config(&server);
    let _auth = login(&server);
    let _read = server.mock(|when, then| {
        when.method(GET).path("/proxy/network/api/s/default/stat/sta");
        then.status(200).json_body(json!({"data":[{"id":"aaaaaaaaaaaé-tail","hostname":"=1+1\u{1b}[2J","mac":"02:00:00:00:00:01"}]}));
    });
    for format in ["pretty", "csv"] {
        let out = isolated_cli(&dir)
            .args(["local", "client", "list", "-o", format])
            .output()
            .unwrap();
        assert!(out.status.success());
        assert!(!out.stdout.contains(&0x1b));
        if format == "csv" {
            assert!(String::from_utf8_lossy(&out.stdout).contains("'=1+1"));
        }
    }
    let out = isolated_cli(&dir)
        .args(["local", "client", "list", "-o", "llm"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(parsed_stdout(&out)["schema"]["name"], "client.list");
}

#[test]
fn unsafe_watch_and_accidentally_open_wlan_fail_before_network() {
    let dir = tempfile::tempdir().unwrap();
    isolated_cli(&dir)
        .args(["local", "device", "list", "--watch", "0"])
        .assert()
        .code(2);
    isolated_cli(&dir)
        .args(["local", "wlan", "create", "--name", "synthetic"])
        .assert()
        .code(2);
    isolated_cli(&dir)
        .args([
            "local",
            "wlan",
            "create",
            "--name",
            "synthetic",
            "--open",
            "--password",
            "synthetic",
        ])
        .assert()
        .code(2);
}

#[test]
fn dns_delete_preview_and_cancel_never_send_delete() {
    let server = MockServer::start();
    let dir = isolated_config(&server);
    let _auth = login(&server);
    let _read = server.mock(|when, then| {
        when.method(GET)
            .path("/proxy/network/v2/api/site/default/static-dns");
        then.status(200)
            .json_body(json!([{"_id":"synthetic-id","key":"synthetic.example"}]));
    });
    let delete = server.mock(|when, then| {
        when.method(DELETE);
        then.status(200).json_body(json!({"data":[]}));
    });
    for extra in [vec!["--dry-run"], vec![]] {
        let out = isolated_cli(&dir)
            .args(["local", "dns", "delete", "synthetic-id", "-o", "json"])
            .args(extra)
            .write_stdin("n\n")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(parsed_stdout(&out).get("action").is_some());
    }
    delete.assert_calls(0);
}

#[test]
fn invalid_dns_target_is_rejected_before_prefetch() {
    let server = MockServer::start();
    let dir = isolated_config(&server);
    let any = server.mock(|when, then| {
        when.any_request();
        then.status(500);
    });
    isolated_cli(&dir)
        .args(["local", "dns", "delete", "../outside", "--yes"])
        .assert()
        .failure();
    any.assert_calls(0);
}

#[test]
fn login_resolves_relative_ca_from_invocation_directory() {
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("synthetic-ca.pem");
    std::fs::write(&ca, "synthetic file for path resolution test").unwrap();
    isolated_cli(&dir)
        .args([
            "login",
            "--controller-url",
            "https://controller.invalid",
            "--username",
            "synthetic",
            "--password",
            "synthetic-password",
            "--ca-file",
            "synthetic-ca.pem",
        ])
        .assert()
        .success();
    let saved: Value =
        serde_yaml::from_slice(&std::fs::read(dir.path().join("config.yaml")).unwrap()).unwrap();
    assert_eq!(
        saved["local"]["ca_file"].as_str().unwrap(),
        ca.canonicalize().unwrap().to_str().unwrap()
    );
}

#[test]
fn wifi_diagnostics_do_not_accept_json_null_as_collected_data() {
    let server = MockServer::start();
    let dir = isolated_config(&server);
    let _auth = login(&server);
    let _wifi = server.mock(|when, then| {
        when.method(GET)
            .path("/proxy/network/api/s/default/wifi-connectivity");
        then.status(200).json_body(json!(null));
    });
    let _devices = server.mock(|when, then| {
        when.method(GET)
            .path("/proxy/network/api/s/default/stat/device");
        then.status(200).json_body(json!({"data":[]}));
    });
    let out = isolated_cli(&dir)
        .args(["local", "diagnose", "wifi", "-o", "json"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let value = parsed_stdout(&out);
    assert_eq!(value["collection_complete"], false);
    assert_eq!(value["checks"][0]["status"], "error");
}

#[test]
fn no_content_mutation_is_accepted_but_not_reported_as_verified() {
    let server = MockServer::start();
    let dir = isolated_config(&server);
    let _auth = login(&server);
    let mutation = server.mock(|when, then| {
        when.method(POST)
            .path("/proxy/network/api/s/default/cmd/devmgr");
        then.status(204);
    });
    for format in ["json", "csv", "llm", "pretty", "raw"] {
        let out = isolated_cli(&dir)
            .args([
                "local",
                "device",
                "restart",
                "02:00:00:00:00:01",
                "-o",
                format,
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        if format == "raw" {
            assert_eq!(out.stdout, b"\n");
            continue;
        }
        let value = parsed_stdout(&out);
        assert_eq!(value["_unifictl"]["http_status"], 204);
        let result = if format == "llm" {
            &value["data"]
        } else {
            &value
        };
        assert_eq!(result["outcome"], "accepted");
        assert_eq!(result["verification"], "unverified");
    }
    mutation.assert_calls(5);
}

#[test]
fn login_rejects_secret_urls_and_http_without_explicit_insecurity() {
    let dir = tempfile::tempdir().unwrap();
    for url in [
        "https://synthetic-user:SYNTHETIC-URL-SECRET@controller.invalid",
        "https://controller.invalid/?token=SYNTHETIC-URL-SECRET",
        "https://controller.invalid/#SYNTHETIC-URL-SECRET",
        "ftp://controller.invalid/SYNTHETIC-URL-SECRET",
        "http://controller.invalid",
    ] {
        let out = isolated_cli(&dir)
            .args([
                "login",
                "--controller-url",
                url,
                "--username",
                "synthetic",
                "--password",
                "synthetic-password",
                "-o",
                "json",
            ])
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(!String::from_utf8_lossy(&out.stderr).contains("SYNTHETIC-URL-SECRET"));
        assert!(!dir.path().join("config.yaml").exists());
    }
    isolated_cli(&dir)
        .args([
            "login",
            "--controller-url",
            "HTTP://CONTROLLER.INVALID:80",
            "--username",
            "synthetic",
            "--password",
            "synthetic-password",
            "--insecure",
        ])
        .assert()
        .success();
    let config: Value =
        serde_yaml::from_slice(&std::fs::read(dir.path().join("config.yaml")).unwrap()).unwrap();
    assert_eq!(config["local"]["url"], "http://controller.invalid/");
    assert_eq!(config["local"]["verify_tls"], false);
}

#[test]
fn login_does_not_transfer_trust_exceptions_to_a_new_controller() {
    for (old_url, new_url, verify_tls, ca_file) in [
        (
            "https://old-controller.invalid",
            "https://new-controller.invalid",
            false,
            None,
        ),
        (
            "https://old-controller.invalid",
            "https://new-controller.invalid",
            true,
            Some("old-controller.pem"),
        ),
        (
            "https://controller.invalid/path",
            "https://controller.invalid/path/",
            false,
            None,
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        let original = serde_json::to_vec(&json!({"local":{
            "url":old_url, "username":"synthetic", "password":"old-synthetic",
            "verify_tls":verify_tls, "ca_file":ca_file
        }}))
        .unwrap();
        std::fs::write(&path, &original).unwrap();
        isolated_cli(&dir)
            .args([
                "login",
                "--controller-url",
                "http://new-controller.invalid",
                "--username",
                "synthetic",
                "--password",
                "new-synthetic",
            ])
            .assert()
            .failure();
        assert_eq!(std::fs::read(&path).unwrap(), original);
        isolated_cli(&dir)
            .args([
                "login",
                "--controller-url",
                new_url,
                "--username",
                "synthetic",
                "--password",
                "new-synthetic",
            ])
            .assert()
            .success();
        let saved: Value = serde_yaml::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(saved["local"]["verify_tls"].is_null());
        assert!(saved["local"]["ca_file"].is_null());
    }
}

#[test]
fn login_preserves_same_target_trust_but_rejects_insecure_ca_combinations() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({"local":{
            "url":"HTTPS://CONTROLLER.INVALID:443", "verify_tls":false
        }}))
        .unwrap(),
    )
    .unwrap();
    let args = [
        "login",
        "--controller-url",
        "https://controller.invalid/",
        "--username",
        "synthetic",
        "--password",
        "synthetic-password",
    ];
    isolated_cli(&dir).args(args).assert().success();
    let saved: Value = serde_yaml::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(saved["local"]["verify_tls"], false);

    for verify_tls in [true, false] {
        let original = serde_json::to_vec(&json!({"local":{
            "url":"https://controller.invalid", "verify_tls":verify_tls, "ca_file":"synthetic.pem"
        }}))
        .unwrap();
        std::fs::write(&path, &original).unwrap();
        let mut command = isolated_cli(&dir);
        command.args(args);
        if verify_tls {
            command.arg("--insecure");
        }
        command.assert().failure().stderr(predicates::str::contains(
            "A controller CA requires TLS verification",
        ));
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }
    // An explicit repair of the same target remains possible.
    isolated_cli(&dir)
        .args(args)
        .arg("--verify-tls")
        .assert()
        .success();
    let saved: Value = serde_yaml::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(saved["local"]["verify_tls"], true);
    assert!(
        saved["local"]["ca_file"]
            .as_str()
            .unwrap()
            .ends_with("synthetic.pem")
    );
}

#[test]
fn login_rejects_new_ca_with_explicit_insecurity_without_saving() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("synthetic.pem"), "synthetic").unwrap();
    isolated_cli(&dir)
        .args([
            "login",
            "--controller-url",
            "https://controller.invalid",
            "--username",
            "synthetic",
            "--password",
            "synthetic-password",
            "--insecure",
            "--ca-file",
            "synthetic.pem",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "A controller CA requires TLS verification",
        ));
    assert!(!dir.path().join("config.yaml").exists());
}

#[test]
fn pretty_json_fallback_escapes_nested_bidi_controls() {
    let server = MockServer::start();
    let dir = isolated_config(&server);
    let _auth = login(&server);
    let _read = server.mock(|when, then| {
        when.method(GET)
            .path("/proxy/network/api/s/default/system-log/setting");
        then.status(200)
            .json_body(json!({"label\u{202e}": {"message":"synthetic\u{2066}\u{202e}"}}));
    });
    let out = isolated_cli(&dir)
        .args(["local", "log", "settings"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let rendered = String::from_utf8_lossy(&out.stdout);
    assert!(!rendered.contains(['\u{202e}', '\u{2066}']));
    assert!(rendered.contains("\\u202e"));
    assert!(rendered.lines().count() > 1);
}

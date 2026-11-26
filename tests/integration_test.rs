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

fn synthetic_command(
    server: &httpmock::MockServer,
    directory: &std::path::Path,
) -> assert_cmd::Command {
    let config = serde_json::json!({
        "api_key":"synthetic-unused-cloud-key",
        "local":{"url":server.base_url(),"username":"u","password":"p","site":"default","verify_tls":false}
    });
    std::fs::write(directory.join("config.yaml"), config.to_string()).unwrap();
    server.mock(|when, then| {
        when.method(httpmock::Method::POST).path("/api/auth/login");
        then.status(200)
            .header("X-CSRF-Token", "synthetic")
            .json_body(serde_json::json!({"ok":true}));
    });
    let mut command = cargo_bin_cmd!("unifictl");
    command
        .current_dir(directory)
        .env("UNIFICTL_CONFIG_DIR", directory)
        .arg("--no-session-cache");
    command
}

#[test]
fn adopt_all_requires_authorization_and_dry_run_never_mutates() {
    let mut command = cargo_bin_cmd!("unifictl");
    command
        .args(["local", "device", "adopt-all"])
        .assert()
        .failure();
    let server = httpmock::MockServer::start();
    let directory = tempfile::tempdir().unwrap();
    let mut command = synthetic_command(&server, directory.path());
    server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/proxy/network/api/s/sandbox/stat/device");
        then.status(200)
            .json_body(serde_json::json!({"data":[{"mac":"00:11:22:33:44:55","adopted":false}]}));
    });
    let action = server.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/proxy/network/api/s/sandbox/cmd/devmgr");
        then.status(200).json_body(serde_json::json!({"ok":true}));
    });
    command
        .args([
            "local",
            "device",
            "adopt-all",
            "--dry-run",
            "--site",
            "sandbox",
            "-o",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("planned"));
    action.assert_hits(0);
}

#[test]
fn adopt_all_stops_after_denial_or_ambiguous_outcome() {
    for status in [401, 403, 429, 503] {
        let server = httpmock::MockServer::start();
        let directory = tempfile::tempdir().unwrap();
        let mut command = synthetic_command(&server, directory.path());
        server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/proxy/network/api/s/default/stat/device");
            then.status(200).json_body(serde_json::json!({"data":[
                {"mac":"00:11:22:33:44:55","adopted":false},
                {"mac":"00:11:22:33:44:66","adopted":false}
            ]}));
        });
        let action = server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/proxy/network/api/s/default/cmd/devmgr");
            then.status(status).header("Retry-After", "0");
        });
        command
            .args(["local", "device", "adopt-all", "--yes", "-o", "json"])
            .assert()
            .failure()
            .stdout(predicates::str::contains("not_attempted"));
        action.assert_hits(1);
    }
}

#[test]
fn adoption_acceptance_is_not_reported_as_completed_and_duplicate_targets_are_not_replayed() {
    let server = httpmock::MockServer::start();
    let directory = tempfile::tempdir().unwrap();
    let mut command = synthetic_command(&server, directory.path());
    let inventory = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/proxy/network/api/s/default/stat/device");
        then.status(200).json_body(serde_json::json!({"data":[
            {"mac":"00:11:22:33:44:55","adopted":false},
            {"mac":"001122334455","adopted":false}
        ]}));
    });
    let action = server.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/proxy/network/api/s/default/cmd/devmgr");
        then.status(200).json_body(serde_json::json!({"ok":true}));
    });
    command
        .args(["local", "device", "adopt-all", "--yes", "-o", "json"])
        .assert()
        .failure()
        .stdout(predicates::str::contains("accepted_unverified"));
    action.assert_hits(1);
    inventory.assert_hits(2);
}

#[test]
fn list_metadata_is_opt_in_and_preserves_default_json_and_raw_shapes() {
    let server = httpmock::MockServer::start();
    let body = serde_json::json!([{"mac":"00:11:22:33:44:55"},{"mac":"00:11:22:33:44:66"}]);
    server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/proxy/network/api/s/default/clients/active");
        then.status(200).json_body(body.clone());
    });
    for format in ["json", "raw"] {
        let directory = tempfile::tempdir().unwrap();
        let mut command = synthetic_command(&server, directory.path());
        let output = command
            .args(["local", "client", "active", "--limit", "1", "-o", format])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json, serde_json::json!([{"mac":"00:11:22:33:44:55"}]));
    }
    let directory = tempfile::tempdir().unwrap();
    let mut command = synthetic_command(&server, directory.path());
    let output = command
        .args([
            "local",
            "client",
            "active",
            "--limit",
            "1",
            "-o",
            "json",
            "--with-metadata",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["data"].as_array().unwrap().len(), 1);
    assert_eq!(json["_unifictl"]["collection"]["truncated"], true);
    assert_eq!(
        json["_unifictl"]["collection"]["inventory_complete"],
        "incomplete"
    );
    assert_eq!(
        json["_unifictl"]["collection"]["requested_range_complete"],
        true
    );
}

#[test]
fn event_metadata_distinguishes_requested_limit_from_complete_inventory() {
    for total in [Some(5usize), None] {
        let server = httpmock::MockServer::start();
        let directory = tempfile::tempdir().unwrap();
        let mut command = synthetic_command(&server, directory.path());
        let mut body = serde_json::json!({"data":[{"id":"synthetic-event"}]});
        if let Some(total) = total {
            body["total_element_count"] = serde_json::json!(total);
        }
        server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/proxy/network/v2/api/site/default/system-log/all");
            then.status(200).json_body(body.clone());
        });
        let output = command
            .args([
                "local",
                "event",
                "list",
                "--limit",
                "1",
                "-o",
                "json",
                "--with-metadata",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(
            json["_unifictl"]["collection"]["requested_range_complete"],
            true
        );
        assert_eq!(
            json["_unifictl"]["collection"]["inventory_complete"],
            if total.is_some() {
                "incomplete"
            } else {
                "unknown"
            }
        );
    }
}

#[test]
fn zero_watch_interval_is_rejected_before_any_request() {
    let mut command = cargo_bin_cmd!("unifictl");
    command
        .args(["--watch", "0", "local", "device", "list"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("invalid value '0'"));
}

#[test]
fn event_metadata_reports_rows_discarded_even_without_controller_total() {
    let server = httpmock::MockServer::start();
    let directory = tempfile::tempdir().unwrap();
    let mut command = synthetic_command(&server, directory.path());
    server.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/proxy/network/v2/api/site/default/system-log/all");
        then.status(200)
            .json_body(serde_json::json!({"data":[{"id":"one"},{"id":"two"}]}));
    });
    let output = command
        .args([
            "local",
            "event",
            "list",
            "--limit",
            "1",
            "-o",
            "json",
            "--with-metadata",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["_unifictl"]["collection"]["observed_count"], 2);
    assert_eq!(json["_unifictl"]["collection"]["truncated"], true);
    assert_eq!(
        json["_unifictl"]["collection"]["inventory_complete"],
        "incomplete"
    );
}

#[test]
fn malformed_or_application_error_inventory_is_not_success_or_adoption() {
    for body in [
        serde_json::json!({"unexpected":true}),
        serde_json::json!({"data":null}),
        serde_json::json!({"meta":{"rc":"error","message":"synthetic-private-body"},"data":[]}),
    ] {
        let server = httpmock::MockServer::start();
        server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/proxy/network/api/s/default/stat/device");
            then.status(200).json_body(body.clone());
        });
        let action = server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/proxy/network/api/s/default/cmd/devmgr");
            then.status(200).json_body(serde_json::json!({"ok":true}));
        });
        for args in [
            vec!["local", "device", "list", "-o", "json"],
            vec!["local", "device", "adopt-all", "--yes", "-o", "json"],
        ] {
            let directory = tempfile::tempdir().unwrap();
            let mut command = synthetic_command(&server, directory.path());
            let output = command.args(args).assert().failure().get_output().clone();
            assert!(!String::from_utf8_lossy(&output.stderr).contains("synthetic-private-body"));
        }
        action.assert_hits(0);
    }
}

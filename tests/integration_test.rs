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

#[test]
fn diagnose_failures_are_explicit_and_do_not_invent_empty_healthy_data() {
    for kind in ["network", "wifi"] {
        let server = httpmock::MockServer::start();
        let directory = tempfile::tempdir().unwrap();
        let mut command = synthetic_command(&server, directory.path());
        server.mock(|when, then| {
            when.method(httpmock::Method::GET);
            then.status(500).body("synthetic-private-body");
        });
        let output = command
            .args(["local", "diagnose", kind, "-o", "json"])
            .assert()
            .failure()
            .get_output()
            .clone();
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(result["collection_errors"].as_array().unwrap().len() >= 2);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic-private-body"));
        if kind == "wifi" {
            assert!(result.get("ap_count").is_none());
            assert!(result["llm_summary"]["ap_count"].is_null());
        }
    }
}

#[test]
fn network_diagnosis_reuses_health_snapshot_and_keeps_unknown_wan_non_successful() {
    let server = httpmock::MockServer::start();
    let directory = tempfile::tempdir().unwrap();
    let mut command = synthetic_command(&server, directory.path());
    let health = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/proxy/network/api/s/default/stat/health");
        then.status(200)
            .json_body(serde_json::json!({"data":[{"subsystem":"wlan","status":"ok"}]}));
    });
    server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/proxy/network/api/s/default/stat/device");
        then.status(200).json_body(serde_json::json!({"data":[]}));
    });
    let output = command
        .args(["local", "diagnose", "network", "-o", "json"])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(result["checks"][1]["status"], "unknown");
    assert_eq!(result["checks"][2]["status"], "collected");
    assert!(result.get("_unifictl").is_none());
    health.assert_hits(1);
}

#[test]
fn failed_requested_correlation_events_are_not_silently_omitted() {
    let server = httpmock::MockServer::start();
    let directory = tempfile::tempdir().unwrap();
    let mut command = synthetic_command(&server, directory.path());
    server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/proxy/network/api/s/default/stat/sta");
        then.status(200)
            .json_body(serde_json::json!({"data":[{"mac":"00:11:22:33:44:55"}]}));
    });
    server.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path_contains("system-log/all");
        then.status(500).body("synthetic-private-body");
    });
    let output = command
        .args([
            "local",
            "correlate",
            "client",
            "00:11:22:33:44:55",
            "--include-events",
            "-o",
            "json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert!(result["collection_error"].is_string());
    assert!(result["llm_summary"]["event_count"].is_null());
    assert!(!String::from_utf8_lossy(&output).contains("synthetic-private-body"));
}

#[test]
fn event_exports_honor_limits_and_preserve_modern_fields_with_legacy_csv_columns() {
    let server = httpmock::MockServer::start();
    server.mock(|when,then| {
        when.method(httpmock::Method::POST).path("/proxy/network/v2/api/site/default/system-log/all");
        then.status(200).json_body(serde_json::json!({"data":[
            {"id":"first","timestamp":"2026-11-26T12:00:00Z","message_raw":"modern message","category":"network"},
            {"id":"second","timestamp":12345,"message_raw":"second message"}
        ],"total_element_count":2}));
    });
    for format in ["json", "csv"] {
        let directory = tempfile::tempdir().unwrap();
        let mut command = synthetic_command(&server, directory.path());
        let output = command
            .args([
                "local",
                "time-series",
                "events",
                "--limit",
                "1",
                "--format",
                format,
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        if format == "json" {
            let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
            assert_eq!(result["data"].as_array().unwrap().len(), 1);
            assert_eq!(result["data"][0]["message_raw"], "modern message");
            assert!(result.get("_unifictl").is_none());
        } else {
            let text = String::from_utf8(output).unwrap();
            assert!(text.starts_with("timestamp,datetime,key,msg,subsystem\n"));
            assert!(text.contains("2026-11-26T12:00:00Z"));
            assert!(text.contains("modern message,network"));
            assert!(!text.contains("second message"));
        }
    }
}

#[test]
fn event_export_paginates_beyond_default_page_and_rejects_malformed_later_pages() {
    for malformed in [false, true] {
        let server = httpmock::MockServer::start();
        let directory = tempfile::tempdir().unwrap();
        let mut command = synthetic_command(&server, directory.path());
        let first = server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path_contains("system-log/all")
                .json_body(serde_json::json!({"pageNumber":0,"pageSize":3}));
            then.status(200).json_body(
                serde_json::json!({"data":[{"id":"one"},{"id":"two"}],"total_element_count":3}),
            );
        });
        let second = server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path_contains("system-log/all")
                .json_body(serde_json::json!({"pageNumber":1,"pageSize":2}));
            if malformed {
                then.status(200)
                    .json_body(serde_json::json!({"unexpected":true}));
            } else {
                then.status(200).json_body(
                    serde_json::json!({"data":[{"id":"three"}],"total_element_count":3}),
                );
            }
        });
        let output = command
            .args([
                "local",
                "time-series",
                "events",
                "--limit",
                "3",
                "--format",
                "json",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.success(), !malformed);
        if malformed {
            assert!(output.stdout.is_empty());
        } else {
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["data"]
                    .as_array()
                    .unwrap()
                    .len(),
                3
            );
        }
        first.assert_hits(1);
        second.assert_hits(1);
    }
}

#[test]
fn llm_output_keeps_upstream_truncation_and_unknown_coverage() {
    let server = httpmock::MockServer::start();
    server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/proxy/network/api/s/default/clients/active");
        then.status(200)
            .json_body(serde_json::json!([{"mac":"one"},{"mac":"two"}]));
    });
    let directory = tempfile::tempdir().unwrap();
    let mut command = synthetic_command(&server, directory.path());
    let output = command
        .args(["local", "client", "active", "--limit", "1", "-o", "llm"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(result["llm_metadata"]["truncation_applied"], true);
    assert_eq!(
        result["llm_metadata"]["collection"]["inventory_complete"],
        "incomplete"
    );
    assert_eq!(result["llm_metadata"]["sampling_applied"], false);
}

#[test]
fn analytics_command_site_is_used_for_all_sources() {
    for args in [
        vec!["local", "diagnose", "network"],
        vec![
            "local",
            "correlate",
            "device",
            "00:11:22:33:44:55",
            "--include-clients",
        ],
        vec!["local", "time-series", "events", "--format", "json"],
    ] {
        let server = httpmock::MockServer::start();
        let directory = tempfile::tempdir().unwrap();
        let mut command = synthetic_command(&server, directory.path());
        let health = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/proxy/network/api/s/sandbox/stat/health");
            then.status(200)
                .json_body(serde_json::json!({"data":[{"subsystem":"wan","status":"ok"}]}));
        });
        let devices = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/proxy/network/api/s/sandbox/stat/device");
            then.status(200).json_body(serde_json::json!([]));
        });
        let clients = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/proxy/network/api/s/sandbox/stat/sta");
            then.status(200).json_body(serde_json::json!([]));
        });
        let events = server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/proxy/network/v2/api/site/sandbox/system-log/all");
            then.status(200)
                .json_body(serde_json::json!({"data":[],"totalCount":0}));
        });
        command
            .args(&args)
            .args(["--site", "sandbox", "-o", "json"])
            .assert()
            .success();
        match args[1] {
            "diagnose" => {
                health.assert_hits(1);
                devices.assert_hits(1);
            }
            "correlate" => {
                devices.assert_hits(1);
                clients.assert_hits(1);
            }
            _ => events.assert_hits(1),
        }
    }
}

#[test]
fn correlation_metadata_marks_discarded_matching_events() {
    let server = httpmock::MockServer::start();
    let directory = tempfile::tempdir().unwrap();
    let mut command = synthetic_command(&server, directory.path());
    server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path("/proxy/network/api/s/default/stat/sta");
        then.status(200).json_body(serde_json::json!([]));
    });
    let events: Vec<_> = (0..21)
        .map(|id| serde_json::json!({"id":id,"user":"00:11:22:33:44:55"}))
        .collect();
    server.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/proxy/network/v2/api/site/default/system-log/all");
        then.status(200)
            .json_body(serde_json::json!({"data":events,"total_element_count":21}));
    });
    let output = command
        .args([
            "local",
            "correlate",
            "client",
            "00:11:22:33:44:55",
            "--include-events",
            "--with-metadata",
            "-o",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["recent_events"].as_array().unwrap().len(), 20);
    assert_eq!(value["_unifictl"]["events_collection"]["truncated"], true);
    assert_eq!(
        value["_unifictl"]["events_collection"]["matching_observed"],
        21
    );
    assert_eq!(
        value["_unifictl"]["events_collection"]["inventory_complete"],
        "unknown"
    );
}

#[test]
fn correlations_match_each_relationship_field_independently() {
    for resource in ["device", "client"] {
        let server = httpmock::MockServer::start();
        let directory = tempfile::tempdir().unwrap();
        let mut command = synthetic_command(&server, directory.path());
        server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/proxy/network/api/s/default/stat/device");
            then.status(200).json_body(serde_json::json!([]));
        });
        let target = "AA:BB:CC:DD:EE:FF";
        let other = "00:11:22:33:44:55";
        let rows: Vec<_> = [
            (serde_json::json!(other), target),
            (serde_json::Value::Null, target),
            (serde_json::json!(target), other),
            (serde_json::json!(target), target),
            (serde_json::json!(other), other),
        ]
        .into_iter()
        .enumerate()
        .map(|(id, (first, second))| {
            if resource == "device" {
                serde_json::json!({"id":id,"ap_mac":first,"sw_mac":second})
            } else {
                serde_json::json!({"id":id,"user":first,"client_mac":second})
            }
        })
        .collect();
        server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/proxy/network/api/s/default/stat/sta");
            then.status(200).json_body(if resource == "device" {
                serde_json::json!(rows)
            } else {
                serde_json::json!([])
            });
        });
        server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path_contains("system-log/all");
            then.status(200)
                .json_body(serde_json::json!({"data":rows,"total_element_count":5}));
        });
        let include = if resource == "device" {
            "--include-clients"
        } else {
            "--include-events"
        };
        let output = command
            .args([
                "local",
                "correlate",
                resource,
                "aa-bb-cc-dd-ee-ff",
                include,
                "-o",
                "json",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        let field = if resource == "device" {
            "connected_clients"
        } else {
            "recent_events"
        };
        let ids: Vec<_> = value[field]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_u64().unwrap())
            .collect();
        assert_eq!(ids, vec![0, 1, 2, 3]);
    }
}

#[test]
fn event_export_metadata_covers_bare_wrapped_and_empty_collections() {
    for (payload, complete) in [
        (serde_json::json!([{"id":1},{"id":2}]), "incomplete"),
        (
            serde_json::json!({"data":[{"id":1},{"id":2}],"total_element_count":2}),
            "incomplete",
        ),
        (serde_json::json!([]), "unknown"),
        (
            serde_json::json!({"data":[],"total_element_count":0}),
            "complete",
        ),
    ] {
        for format in ["json", "csv"] {
            let server = httpmock::MockServer::start();
            let directory = tempfile::tempdir().unwrap();
            let mut command = synthetic_command(&server, directory.path());
            server.mock(|when, then| {
                when.method(httpmock::Method::POST)
                    .path_contains("system-log/all");
                then.status(200).json_body(payload.clone());
            });
            let output = command
                .args([
                    "local",
                    "time-series",
                    "events",
                    "--limit",
                    "1",
                    "--format",
                    format,
                    "--with-metadata",
                    "-o",
                    "json",
                ])
                .assert()
                .success()
                .get_output()
                .clone();
            let result: serde_json::Value = if format == "json" {
                serde_json::from_slice(&output.stdout).unwrap()
            } else {
                assert!(
                    String::from_utf8_lossy(&output.stdout)
                        .starts_with("timestamp,datetime,key,msg,subsystem\n")
                );
                String::from_utf8_lossy(&output.stderr)
                    .lines()
                    .find_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                    .expect("CSV metadata sidecar")
            };
            let metadata = &result["_unifictl"]["collection"];
            assert_eq!(metadata["inventory_complete"], complete);
            assert_eq!(metadata["requested"], 1);
            assert_eq!(metadata["truncated"], complete == "incomplete");
            if format == "json" {
                assert_eq!(
                    result["data"].as_array().unwrap().len(),
                    if complete == "incomplete" { 1 } else { 0 }
                );
            }
        }
    }
}

#[test]
fn unknown_optional_health_status_remains_visible_and_non_successful() {
    let server = httpmock::MockServer::start();
    let directory = tempfile::tempdir().unwrap();
    let mut command = synthetic_command(&server, directory.path());
    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path_contains("stat/health");
        then.status(200).json_body(serde_json::json!({"data":[{"subsystem":"wan","status":"ok"},{"subsystem":"vpn","status":"unknown"}]}));
    });
    server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path_contains("stat/device");
        then.status(200).json_body(serde_json::json!([]));
    });
    let output = command
        .args(["local", "diagnose", "network", "-o", "json"])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(result["checks"][0]["status"], "unknown_or_fail");
    assert_eq!(result["checks"][0]["data"][1]["status"], "unknown");
    assert_eq!(result["checks"][1]["status"], "pass");
}

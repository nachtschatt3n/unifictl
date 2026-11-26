use httpmock::prelude::*;
use predicates::prelude::*;
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn config(server: &MockServer) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config.yaml"),
        serde_json::to_vec(&json!({
            "api_key":"synthetic-key", "base_url":server.base_url(),
            "local":{"url":server.base_url(),"username":"synthetic","password":"synthetic-password","site":"default","verify_tls":false}
        })).unwrap(),
    ).unwrap();
    dir
}

fn command(dir: &TempDir) -> std::process::Command {
    let mut command = std::process::Command::new(assert_cmd::cargo::cargo_bin!("unifictl"));
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

fn cli(dir: &TempDir) -> assert_cmd::Command {
    command(dir).into()
}

fn login(server: &MockServer) -> httpmock::Mock<'_> {
    server.mock(|when, then| {
        when.method(POST).path("/api/auth/login");
        then.status(200)
            .header("X-CSRF-Token", "synthetic-token")
            .json_body(json!({"ok":true}));
    })
}

#[test]
fn known_actions_show_controller_acceptance_in_pretty_output() {
    let server = MockServer::start();
    let dir = config(&server);
    let _login = login(&server);
    for (resource, action, command, endpoint) in [
        ("device", "provision", "force-provision", "devmgr"),
        ("device", "restart", "restart", "devmgr"),
        ("device", "adopt", "adopt", "devmgr"),
        ("device", "upgrade", "upgrade", "devmgr"),
        ("client", "block", "block", "stamgr"),
        ("client", "unblock", "unblock", "stamgr"),
        ("client", "reconnect", "reconnect", "stamgr"),
    ] {
        let request = server.mock(|when, then| {
            when.method(POST)
                .path(format!("/proxy/network/api/s/default/cmd/{endpoint}"))
                .json_body(json!({"cmd":command,"mac":"02:00:00:00:00:01"}));
            then.status(200)
                .json_body(json!({"meta":{"rc":"ok"},"data":[]}));
        });
        cli(&dir)
            .args(["local", resource, action, "02:00:00:00:00:01"])
            .assert()
            .success()
            .stdout(format!("✓ {action} accepted by controller (rc: ok)\n"));
        request.assert_hits(1);
    }
}

#[test]
fn error_and_missing_acknowledgements_are_not_reported_as_accepted() {
    for payload in [
        json!({"meta":{"rc":"error","msg":"synthetic rejection"},"data":[]}),
        json!({"data":[]}),
        json!({"meta":{"rc":"ok"},"data":[{"name":"returned resource"}]}),
    ] {
        let server = MockServer::start();
        let dir = config(&server);
        let _login = login(&server);
        let request = server.mock(|when, then| {
            when.method(POST)
                .path("/proxy/network/api/s/default/cmd/devmgr");
            then.status(200).json_body(payload.clone());
        });
        let out = cli(&dir)
            .args(["local", "device", "provision", "02:00:00:00:00:01"])
            .output()
            .unwrap();
        assert!(!String::from_utf8_lossy(&out.stdout).contains("accepted by controller"));
        if payload["data"].as_array().unwrap().is_empty() {
            assert_eq!(
                serde_json::from_slice::<Value>(&out.stdout).unwrap(),
                payload
            );
        }
        request.assert_hits(1);
    }
}

#[test]
fn empty_queries_keep_the_empty_inventory_message() {
    let server = MockServer::start();
    let dir = config(&server);
    let _login = login(&server);
    let request = server.mock(|when, then| {
        when.method(GET)
            .path("/proxy/network/api/s/default/stat/device");
        then.status(200)
            .json_body(json!({"meta":{"rc":"ok"},"data":[]}));
    });
    cli(&dir)
        .args(["local", "device", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No resources found."))
        .stdout(predicate::str::contains("accepted by controller").not());
    request.assert_hits(1);
}

#[test]
fn json_and_raw_preserve_action_acknowledgements() {
    let server = MockServer::start();
    let dir = config(&server);
    let _login = login(&server);
    let body = "{ \"meta\": {\"rc\": \"ok\"}, \"data\": [] }";
    let request = server.mock(|when, then| {
        when.method(POST)
            .path("/proxy/network/api/s/default/cmd/devmgr");
        then.status(200).body(body);
    });
    for format in ["json", "raw"] {
        let out = cli(&dir)
            .args([
                "local",
                "device",
                "provision",
                "02:00:00:00:00:01",
                "-o",
                format,
            ])
            .output()
            .unwrap();
        assert!(out.status.success());
        assert_eq!(
            serde_json::from_slice::<Value>(&out.stdout).unwrap(),
            json!({"meta":{"rc":"ok"},"data":[]})
        );
        if format == "raw" {
            assert_eq!(out.stdout, format!("{body}\n").as_bytes());
        }
    }
    request.assert_hits(2);
}

#[test]
fn json_and_raw_keep_bare_arrays_and_envelopes() {
    for body in [
        "[ { \"name\": \"synthetic\" } ]",
        "{ \"meta\": {\"rc\":\"ok\"}, \"data\": [{\"name\":\"synthetic\"}] }",
    ] {
        let server = MockServer::start();
        let dir = config(&server);
        let request = server.mock(|when, then| {
            when.method(GET).path("/v1/hosts");
            then.status(200).body(body);
        });
        for format in ["json", "raw"] {
            let out = cli(&dir)
                .args(["cloud", "host", "list", "-o", format])
                .output()
                .unwrap();
            assert!(out.status.success());
            assert_eq!(
                serde_json::from_slice::<Value>(&out.stdout).unwrap(),
                serde_json::from_str::<Value>(body).unwrap()
            );
            if format == "raw" {
                assert_eq!(out.stdout, format!("{body}\n").as_bytes());
            }
        }
        request.assert_hits(2);
    }
}

#[test]
fn local_client_lists_preserve_bare_and_enveloped_shapes_after_limits() {
    for payload in [
        json!([{"mac":"02:00:00:00:00:01"},{"mac":"02:00:00:00:00:02"}]),
        json!({"meta":{"rc":"ok"},"data":[{"mac":"02:00:00:00:00:01"},{"mac":"02:00:00:00:00:02"}]}),
    ] {
        let server = MockServer::start();
        let dir = config(&server);
        let _login = login(&server);
        let request = server.mock(|when, then| {
            when.method(GET)
                .path("/proxy/network/v2/api/site/default/clients/active");
            then.status(200).json_body(payload.clone());
        });
        let mut expected = payload;
        if expected.is_array() {
            expected.as_array_mut().unwrap().truncate(1);
        } else {
            expected["data"].as_array_mut().unwrap().truncate(1);
        }
        for format in ["json", "raw"] {
            let out = cli(&dir)
                .args(["local", "client", "active", "--limit", "1", "-o", format])
                .output()
                .unwrap();
            assert!(out.status.success());
            assert_eq!(
                serde_json::from_slice::<Value>(&out.stdout).unwrap(),
                expected
            );
            assert_eq!(
                out.stdout,
                format!("{}\n", serde_json::to_string(&expected).unwrap()).as_bytes()
            );
        }
        request.assert_hits(2);
    }
}

#[test]
fn redirected_watch_does_not_emit_terminal_screen_controls_or_prompts() {
    for kind in ["local", "cloud"] {
        let server = MockServer::start();
        let dir = config(&server);
        let _login = login(&server);
        let path = if kind == "local" {
            "/proxy/network/api/s/default/stat/device"
        } else {
            "/v1/hosts"
        };
        let request = server.mock(|when, then| {
            when.method(GET).path(path);
            then.status(200)
                .json_body(json!({"data":[{"name":"synthetic"}]}));
        });
        let output_path = dir.path().join("watch.txt");
        let mut command = command(&dir);
        command.args([
            kind,
            if kind == "local" { "device" } else { "host" },
            "list",
            "--watch",
            "1",
        ]);
        let mut child = command
            .stdout(std::fs::File::create(&output_path).unwrap())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let rendered = loop {
            let rendered = std::fs::read_to_string(&output_path).unwrap();
            if rendered.matches("synthetic").count() >= 2 || Instant::now() >= deadline {
                break rendered;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(
            rendered.matches("synthetic").count() >= 2,
            "{kind}: {rendered}"
        );
        assert!(!rendered.contains('\x1b'));
        assert!(!rendered.contains("Updated:"));
        assert!(!rendered.contains("Press Ctrl+C"));
        assert!(request.hits() >= 2);
    }
}

#[test]
fn pretty_and_csv_escape_untrusted_text_without_changing_json_or_raw() {
    let server = MockServer::start();
    let dir = config(&server);
    let header = "=header\u{202e}";
    let name = " =1+1\x1b[2J\u{85}\u{200f}\u{202e}";
    let payload =
        json!({"data":[{header:"@formula", "name":name,"number":-42,"id":"💃".repeat(13)}]});
    let body = serde_json::to_string(&payload).unwrap();
    let request = server.mock(|when, then| {
        when.method(GET).path("/v1/hosts");
        then.status(200).body(&body);
    });
    let columns = format!("{header},name,number,id");
    for format in ["pretty", "csv", "json", "raw"] {
        let out = cli(&dir)
            .args(["cloud", "host", "list", "--columns", &columns, "-o", format])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8(out.stdout).unwrap();
        if format == "json" || format == "raw" {
            assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), payload);
            if format == "raw" {
                assert_eq!(text, format!("{body}\n"));
            }
        } else {
            assert!(!text.contains(['\x1b', '\u{85}', '\u{200f}', '\u{202e}']));
            if format == "csv" {
                let mut reader = csv::Reader::from_reader(text.as_bytes());
                assert_eq!(&reader.headers().unwrap()[0], "'=header\\u{202e}");
                let row = reader.records().next().unwrap().unwrap();
                assert_eq!(&row[0], "'@formula");
                assert!(row[1].starts_with("' =1+1"));
                assert_eq!(&row[2], "-42");
                assert_eq!(&row[3], "💃".repeat(13));
            } else {
                assert!(text.contains(&format!("{}…", "💃".repeat(12))));
            }
        }
    }
    request.assert_hits(4);
}

#[test]
fn pretty_fallback_and_errors_escape_controls() {
    let server = MockServer::start();
    let dir = config(&server);
    let mut request = server.mock(|when, then| {
        when.method(GET).path("/v1/hosts");
        then.status(200)
            .json_body(json!({"nested\u{202e}":{"text":"synthetic\u{2066}\u{85}"}}));
    });
    let out = cli(&dir).args(["cloud", "host", "list"]).output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(!text.contains(['\u{202e}', '\u{2066}', '\u{85}']));
    assert_eq!(
        serde_json::from_str::<Value>(&text).unwrap()["nested\u{202e}"]["text"],
        "synthetic\u{2066}\u{85}"
    );
    request.delete();
    let _login = login(&server);
    let _error = server.mock(|when, then| {
        when.method(GET);
        then.status(400)
            .json_body(json!({"meta":{"msg":"synthetic\x1b[2J\u{202e}"}}));
    });
    let out = cli(&dir)
        .args(["local", "device", "list"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!String::from_utf8_lossy(&out.stderr).contains(['\x1b', '\u{202e}']));
    assert!(String::from_utf8_lossy(&out.stderr).contains("synthetic"));
}

#[test]
fn deletion_preview_and_prompt_escape_controller_names() {
    let server = MockServer::start();
    let dir = config(&server);
    let _login = login(&server);
    let _network = server.mock(|when, then| {
        when.method(GET)
            .path("/proxy/network/api/s/default/rest/networkconf");
        then.status(200)
            .json_body(json!({"data":[{"_id":"synthetic-id","name":"synthetic\x1b[2J\u{202e}"}]}));
    });
    let deletion = server.mock(|when, then| {
        when.method(DELETE);
        then.status(200)
            .json_body(json!({"meta":{"rc":"ok"},"data":[]}));
    });
    for dry_run in [true, false] {
        let mut command = cli(&dir);
        command.args(["local", "network", "delete", "synthetic-id"]);
        if dry_run {
            command.arg("--dry-run");
        } else {
            command.write_stdin("n\n");
        }
        let out = command.output().unwrap();
        assert!(out.status.success());
        assert!(!String::from_utf8_lossy(&out.stdout).contains(['\x1b', '\u{202e}']));
    }
    deletion.assert_hits(0);
}

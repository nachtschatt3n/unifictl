use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn malformed_config_requires_explicit_cli_repair() {
    let dir = tempdir().unwrap();
    let config = dir.path().join(".unifictl.yaml");
    let malformed = "local:\n  password: [synthetic-secret\n";
    fs::write(&config, malformed).unwrap();
    let mut cmd = cargo_bin_cmd!("unifictl");
    cmd.current_dir(dir.path())
        .env("UNIFICTL_CONFIG_DIR", dir.path().join("user"))
        .args(["login", "--scope", "local", "--api-key", "replacement"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("line 2, column 13"))
        .stderr(predicate::str::contains("synthetic-secret").not());
    assert_eq!(fs::read_to_string(&config).unwrap(), malformed);
    let mut repair = cargo_bin_cmd!("unifictl");
    repair
        .current_dir(dir.path())
        .env("UNIFICTL_CONFIG_DIR", dir.path().join("user"))
        .args([
            "login",
            "--scope",
            "local",
            "--api-key",
            "replacement",
            "--repair-config",
        ])
        .assert()
        .success();
    let saved: serde_json::Value =
        serde_yaml::from_str(&fs::read_to_string(config).unwrap()).unwrap();
    assert_eq!(saved["api_key"].as_str(), Some("replacement"));
}

#[test]
fn new_login_defaults_to_tls_and_requires_port_fallback_opt_in() {
    let dir = tempdir().unwrap();
    for extra in [None, Some("--port-fallback"), Some("--no-port-fallback")] {
        let mut cmd = cargo_bin_cmd!("unifictl");
        cmd.current_dir(dir.path())
            .env("UNIFICTL_CONFIG_DIR", dir.path().join("user"))
            .args([
                "login",
                "--scope",
                "local",
                "--controller-url",
                "https://controller.invalid:8443",
                "--username",
                "synthetic",
                "--password",
                "synthetic-password",
            ]);
        if let Some(extra) = extra {
            cmd.arg(extra);
        }
        cmd.assert().success();
        let saved: serde_json::Value =
            serde_yaml::from_str(&fs::read_to_string(dir.path().join(".unifictl.yaml")).unwrap())
                .unwrap();
        assert_ne!(saved["local"]["verify_tls"].as_bool(), Some(false));
        assert_eq!(
            saved["local"]["port_fallback"].as_bool(),
            extra.map(|value| value == "--port-fallback")
        );
    }
}

#[test]
fn plain_http_requires_explicit_insecure_login() {
    let dir = tempdir().unwrap();
    let mut cmd = cargo_bin_cmd!("unifictl");
    cmd.current_dir(dir.path())
        .env("UNIFICTL_CONFIG_DIR", dir.path().join("user"))
        .args([
            "login",
            "--scope",
            "local",
            "--controller-url",
            "http://localhost:8443",
            "--username",
            "synthetic",
            "--password",
            "synthetic-password",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("HTTPS is required"));
    assert!(!dir.path().join(".unifictl.yaml").exists());
}

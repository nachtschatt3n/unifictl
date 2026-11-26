use assert_cmd::cargo::cargo_bin_cmd;
use httpmock::prelude::*;

#[test]
fn cloud_host_get_sends_a_colon_id_to_the_configured_mock() {
    let server = MockServer::start();
    let config = tempfile::tempdir().unwrap();
    let host = server.mock(|when, then| {
        when.method(GET)
            .path("/v1/hosts/001122aabbcc%3A42")
            .header("X-API-Key", "fixture-key");
        then.status(200).body(r#"{"id":"001122aabbcc:42"}"#);
    });
    let mut cmd = cargo_bin_cmd!("unifictl");
    cmd.current_dir(config.path())
        .env("UNIFICTL_CONFIG_DIR", config.path())
        .args([
            "--base-url",
            &server.base_url(),
            "--api-key",
            "fixture-key",
            "--allow-http-mock",
            "-o",
            "raw",
            "cloud",
            "host",
            "get",
            "001122aabbcc:42",
        ]);
    cmd.assert()
        .success()
        .stdout(predicates::str::contains("001122aabbcc:42"));
    host.assert();
}

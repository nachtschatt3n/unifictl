// Integration tests for unifictl improvements

use assert_cmd::cargo::cargo_bin_cmd;

#[test]
fn test_dry_run_flag_exists() {
    // Test that --dry-run flag is available for delete commands
    let mut cmd = cargo_bin_cmd!("unifictl");
    cmd.args(["local", "network-delete", "--help"]);
    cmd.assert()
        .success()
        .stdout(predicates::str::contains("--dry-run"))
        .stdout(predicates::str::contains("Show what would be deleted"));
}

#[test]
fn test_all_delete_commands_have_dry_run() {
    let commands = vec![
        "network-delete",
        "wlan-delete",
        "firewall-rule-delete",
        "firewall-group-delete",
    ];

    for cmd_name in commands {
        let mut cmd = cargo_bin_cmd!("unifictl");
        cmd.args(["local", cmd_name, "--help"]);
        cmd.assert()
            .success()
            .stdout(predicates::str::contains("--dry-run"));
    }
}

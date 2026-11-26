#!/usr/bin/env bash
# Fail closed on missing tooling, failed installation, database errors or advisories.
set -euo pipefail
audit_root=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/unifictl-audit.XXXXXX")
trap 'rm -rf "$audit_root"' EXIT
cargo install cargo-audit --version 0.22.2 --locked --root "$audit_root"
"$audit_root/bin/cargo-audit" --version
"$audit_root/bin/cargo-audit" audit --file Cargo.lock --deny warnings --json > "${1:-audit.json}"

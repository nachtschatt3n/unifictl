# unifictl

[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/version-0.3.0-green.svg)](https://github.com/nachtschatt3n/unifictl)

CLI for the UniFi Site Manager API (v1/EA). It wraps the documented endpoints (`/v1/hosts`, `/v1/sites`, `/v1/devices`, `/ea/isp-metrics/:type`, `/ea/sd-wan-configs`, etc.), handles the `X-API-Key` header, and stores your key either in the project directory or in the user config directory.

It also supports local UniFi controller access (username/password) for on-prem controllers/UniFi OS gateways.

## Quick start

```bash
cargo build --release
./target/release/unifictl configure --key "<YOUR_API_KEY>"
./target/release/unifictl hosts list
```

### Configuration

- Default base URL: `https://api.ui.com`
- API key lookup order: `--api-key` flag ➜ `.unifictl.yaml` in the current directory ➜ `~/.config/unifictl/config.yaml`
- Save a key locally (portable with the repo): `unifictl configure --key "<KEY>" --scope local`
- Save for the current user: `unifictl configure --key "<KEY>"` (default)
- Local controller credentials (stored in plaintext in the chosen scope):
  ```bash
  # recommended: keep local to the project dir
  unifictl local configure --url https://192.168.1.1:8443 \
      --username admin --password '<PASSWORD>' --site default --scope local
  ```
  Commands will default to the stored site; override with `--site ...`.
  Use `--verify-tls` if your controller has a valid cert; otherwise it will skip TLS verification.

### Common commands

```bash
# Hosts
unifictl hosts list
unifictl hosts get <HOST_ID>

# Sites and devices
unifictl sites list [--host-id <HOST_ID>]
unifictl devices list [--host-id <HOST_ID>] [--site-id <SITE_ID>]
unifictl devices get <DEVICE_ID> [--host-id <HOST_ID>] [--site-id <SITE_ID>]

# ISP metrics (EA)
unifictl isp get --type 5m --site-id <SITE_ID> --start <RFC3339> --end <RFC3339>
unifictl isp query --type hourly --body-file ./query.json

# SD-WAN configs (EA)
unifictl sdwan list
unifictl sdwan get <CONFIG_ID>
unifictl sdwan status <CONFIG_ID>

# Local controller (username/password)
unifictl local sites
unifictl local devices [--site <SITE>] [--unadopted] [--adopt-all]
unifictl local device <MAC> --ports|--config|--restart|--adopt|--upgrade
unifictl local clients [--site <SITE>] [--wired|--wireless|--blocked]
unifictl local client <MAC> --block|--unblock|--reconnect
unifictl local health [--site <SITE>]
unifictl local events [--site <SITE>]
unifictl local networks|wlans|port-profiles|firewall-rules|firewall-groups
unifictl local network create|update|delete [--dry-run] [--yes]
unifictl local wlan create|update|delete [--dry-run] [--yes]
unifictl local firewall-rule create|update|delete [--dry-run] [--yes]
unifictl local firewall-group create|update|delete [--dry-run] [--yes]
unifictl local top-clients [--limit N]
unifictl local top-devices [--limit N]
unifictl local dpi
unifictl local traffic

# Output and table controls
unifictl hosts list -o json                    # json/csv/raw/pretty (pretty is default)
unifictl devices list -o csv > devices.csv     # CSV export for reporting
unifictl devices list --columns name,ip,model --sort-by name --filter "ap"
unifictl devices list --filter-regex "^SW.*"   # Regex filtering (case-insensitive)
unifictl local clients --watch 5               # refresh every 5s (clears screen, shows timestamp)
unifictl hosts list --full-ids                 # do not truncate IDs

# Safety features
unifictl local network delete <ID> --dry-run   # Preview what would be deleted
unifictl local network delete <ID>             # Prompts for confirmation
unifictl local network delete <ID> --yes      # Skip confirmation (for scripts)

# Device management
unifictl local devices --unadopted             # List pending/unadopted devices
unifictl local devices --adopt-all             # Adopt all unadopted devices

# Filtering and export
unifictl local devices --filter "SW"           # Text filter (case-insensitive)
unifictl local devices --filter-regex "^SW.*"  # Regex filter (case-insensitive)
unifictl local clients -o csv > clients.csv    # Export to CSV

# Config helpers
unifictl configure --key "<KEY>" --scope local
unifictl config-show
unifictl validate                              # Test cloud and local credentials
unifictl completion bash|zsh|fish|powershell > /path/to/completion
```

## Error Messages

The tool provides context-aware error messages with actionable guidance:

- **401 (Unauthorized)**: Authentication failure with credential validation suggestions
- **400 (Bad Request)**: Parsed error details with operation-specific troubleshooting
- **404 (Not Found)**: Resource identification help and list command suggestions
- **409 (Conflict)**: Conflict resolution guidance

All error messages include:
- Specific error codes and descriptions
- Possible causes
- Troubleshooting steps
- Recommended commands to investigate

## Testing

```bash
cargo test
```

Run specific test suites:
```bash
cargo test login_preserves_port          # Test port preservation
cargo test format_error_message          # Test error message formatting
cargo test --test integration_test       # Integration tests
```

## Packaging

- **Debian/Ubuntu (`.deb`)**: uses `cargo-deb`.

  ```bash
  cargo install cargo-deb          # once
  cargo deb                        # creates target/debian/unifictl_*.deb
  ```

- **Arch Linux (`.pkg.tar.zst`)**: uses the provided `packaging/arch/PKGBUILD`.

  ```bash
  cargo build --release
  cd packaging/arch && makepkg -sf  # outputs unifictl-<ver>-<arch>.pkg.tar.zst
  ```

Both packaging flows expect the release binary at `target/release/unifictl`.

## Features

### Output Formats
- **Pretty** (default): Human-readable tables with automatic column selection
- **JSON**: Structured JSON output for programmatic use
- **CSV**: Comma-separated values for spreadsheet import and reporting
- **Raw**: Exact API response body

### Filtering & Sorting
- **`--filter <TEXT>`**: Simple text filter (case-insensitive substring match)
- **`--filter-regex <PATTERN>`**: Advanced regex filtering (case-insensitive)
- **`--sort-by <COLUMN>`**: Sort results by any column
- **`--columns <COL1,COL2>`**: Custom column selection
- **`--full-ids`**: Show complete IDs without truncation

### Safety Features
- **`--dry-run`**: Preview deletions without actually deleting (all delete commands)
- **Interactive confirmations**: Prompts before destructive operations (can skip with `--yes`)
- **Better error messages**: Context-aware error messages with troubleshooting guidance

### Watch Mode
- **`--watch <SECONDS>`**: Live refresh mode with automatic screen clearing
- Shows timestamps for each refresh
- Press Ctrl+C to exit

### Device Management
- **`--unadopted`**: Filter to show only pending/unadopted devices
- **`--adopt-all`**: Bulk adopt all unadopted devices
- Individual device actions: `--restart`, `--adopt`, `--upgrade`

## Notes

- The ISP metrics and SD-WAN endpoints are under `/ea/...` as per the official Site Manager API docs.
- All requests set `Accept: application/json` and `X-API-Key` automatically; use `--base-url` to point at a different API host if needed.
- Port `:8443` is automatically preserved for local controller connections.
- Error messages provide actionable guidance and troubleshooting steps.

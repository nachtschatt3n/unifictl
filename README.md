# unifictl

[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/version-0.4.6-green.svg)](https://github.com/nachtschatt3n/unifictl)

CLI for the UniFi Site Manager API (v1/EA). It wraps the documented endpoints (`/v1/hosts`, `/v1/sites`, `/v1/devices`, `/ea/isp-metrics/:type`, `/ea/sd-wan-configs`, etc.), handles the `X-API-Key` header, and stores your key either in the project directory or in the user config directory.

It also supports local UniFi controller access (username/password) for on-prem controllers/UniFi OS gateways.

## Quick start

```bash
cargo build --release
./target/release/unifictl configure --key "<YOUR_API_KEY>"
./target/release/unifictl host list
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
unifictl host list
unifictl host get <HOST_ID>

# Sites and devices
unifictl site list [--host-id <HOST_ID>]
unifictl device list [--host-id <HOST_ID>] [--site-id <SITE_ID>]
unifictl device get <DEVICE_ID> [--host-id <HOST_ID>] [--site-id <SITE_ID>]

# ISP metrics (EA)
unifictl isp get --type 5m --site-id <SITE_ID> --start <RFC3339> --end <RFC3339>
unifictl isp query --type hourly --body-file ./query.json

# SD-WAN configs (EA)
unifictl sdwan list
unifictl sdwan get <CONFIG_ID>
unifictl sdwan status <CONFIG_ID>

# Local controller (username/password)
unifictl local site list
unifictl local device list [--site <SITE>] [--unadopted]
unifictl local device get <MAC> [--ports] [--config]
unifictl local device restart <MAC>
unifictl local device adopt <MAC>
unifictl local device adopt-all
unifictl local device upgrade <MAC>
unifictl local client list [--site <SITE>] [--wired|--wireless|--blocked]
unifictl local client block <MAC>
unifictl local client unblock <MAC>
unifictl local client reconnect <MAC>
unifictl local event list [--site <SITE>]
unifictl local health get [--site <SITE>]
unifictl local security get [--site <SITE>]
unifictl local wan get [--site <SITE>]
unifictl local dpi get [--site <SITE>]
unifictl local top-client list [--limit N] [--site <SITE>]
unifictl local top-device list [--limit N] [--site <SITE>]
unifictl local network list|create|update|delete
unifictl local wlan list|create|update|delete
unifictl local port-profile list
unifictl local firewall-rule list|create|update|delete
unifictl local firewall-group list|create|update|delete
unifictl local policy-table list|create|update|delete
unifictl local zone list|create|update|delete
unifictl local object list|create|update|delete

# Output and table controls
unifictl host list -o json                    # json/csv/raw/pretty (pretty is default)
unifictl device list -o csv > devices.csv     # CSV export for reporting
unifictl device list --columns name,ip,model --sort-by name --filter "ap"
unifictl device list --filter-regex "^SW.*"   # Regex filtering (case-insensitive)
unifictl local client list --watch 5          # refresh every 5s (clears screen, shows timestamp)
unifictl host list --full-ids                 # do not truncate IDs

# Safety features
unifictl local network delete <ID> --dry-run   # Preview what would be deleted
unifictl local network delete <ID>             # Prompts for confirmation
unifictl local network delete <ID> --yes       # Skip confirmation (for scripts)

# Device management
unifictl local device list --unadopted         # List pending/unadopted devices
unifictl local device adopt-all                # Adopt all unadopted devices

# Filtering and export
unifictl local device list --filter "SW"       # Text filter (case-insensitive)
unifictl local device list --filter-regex "^SW.*"  # Regex filter (case-insensitive)
unifictl local client list -o csv > clients.csv    # Export to CSV

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

## Troubleshooting

### UDM Rate Limiting

If you encounter repeated login failures or authentication errors when using local controller commands, your UniFi Dream Machine (UDM) may be hitting the default rate limit for login attempts.

**Symptoms:**
- `Error: login failed at https://..../api/login: sending login request`
- Commands fail intermittently with authentication errors
- Some commands work while others fail

**Solution:**

SSH into your UDM and increase the login rate limit in `/usr/lib/ulp-go/config.props`:

```bash
# Edit the config file
vi /usr/lib/ulp-go/config.props

# Find and modify this line:
success.login.limit.count=<higher_value>

# Default is usually 5-10, increase to 50-100 for CLI tools
# Example: success.login.limit.count=100

# Restart the UniFi OS to apply changes
systemctl restart unifi-os
```

**Note:** This setting controls how many successful logins are allowed within a time window. CLI tools like `unifictl` create new sessions for each command, which can quickly exceed the default limit during normal usage.

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
- **`device list --unadopted`**: Filter to show only pending/unadopted devices
- **`device adopt-all`**: Bulk adopt all unadopted devices
- Individual device actions: `device restart <MAC>`, `device adopt <MAC>`, `device upgrade <MAC>`

## Notes

- The ISP metrics and SD-WAN endpoints are under `/ea/...` as per the official Site Manager API docs.
- All requests set `Accept: application/json` and `X-API-Key` automatically; use `--base-url` to point at a different API host if needed.
- Port `:8443` is automatically preserved for local controller connections.
- Error messages provide actionable guidance and troubleshooting steps.

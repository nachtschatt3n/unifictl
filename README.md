# unifictl

<div align="center">

[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/version-5.7.0-green.svg)](https://github.com/nachtschatt3n/unifictl)
[![Tests](https://img.shields.io/badge/tests-75%20passing-success.svg)](#testing)

**A powerful CLI tool for UniFi networks with AI-first design**

[Features](#features) •
[Installation](#installation) •
[Quick Start](#quick-start) •
[AI Guide](AI_AGENT_GUIDE.md) •
[Examples](EXAMPLES.md)

</div>

---

## Overview

`unifictl` is a comprehensive command-line interface for managing UniFi networks through both the **UniFi Site Manager API** (cloud) and **local UniFi controllers**. Built with Rust for performance and reliability, it provides human-friendly commands while offering AI-optimized output for automated network management.

### What makes unifictl special?

- 🤖 **AI-First Design**: LLM-optimized output with token estimation, smart truncation, and JSON schemas
- 🔄 **Correlation Commands**: Aggregate related network data in single API calls
- 🏥 **Diagnostic Mode**: Multi-endpoint health checks with actionable recommendations
- 📊 **Time-Series Export**: Historical data for trend analysis and pattern detection
- 🎯 **kubectl-like UX**: Intuitive command structure with consistent patterns
- ⚡ **Performance**: Native binary with minimal overhead, fast execution
- 🛡️ **Safety Features**: Dry-run mode, interactive confirmations, context-aware errors

## Features

### 🤖 AI-Powered Network Management

<table>
<tr>
<td width="50%">

**LLM-Optimized Output** (`-o llm`)
- Token counting (~4 chars/token)
- Intelligent truncation (>4000 tokens)
- JSON schema metadata
- Field importance levels
- Statistical summaries

</td>
<td width="50%">

**Correlation Commands**
- Aggregate client + AP + events
- Device + connected clients
- Reduce API calls by 80%
- Single-command troubleshooting
- Cross-reference network data

</td>
</tr>
<tr>
<td>

**Diagnostic Mode**
- Network health checks
- WiFi performance analysis
- Client troubleshooting
- Pass/fail with recommendations
- Multi-endpoint validation

</td>
<td>

**Time-Series Export**
- Traffic statistics (CSV/JSON)
- WiFi metrics over time
- Event log export
- Trend analysis ready
- Bandwidth planning data

</td>
</tr>
</table>

### 🛠️ Core Features

#### Output Formats & Filtering
- **Pretty** (default): Human-readable tables with auto-column selection
- **JSON**: Structured output for scripting and automation
- **CSV**: Spreadsheet-ready exports for reporting
- **Raw**: Exact API responses
- **LLM**: AI-optimized with metadata and schemas

Advanced filtering with `--filter`, `--filter-regex`, `--sort-by`, `--columns`, and `--full-ids`

#### Network Operations

**Cloud (Site Manager API)**
- Host and site management
- Device inventory across sites
- ISP metrics and analytics (EA)
- SD-WAN configuration (EA)

**Local Controller**
- Device management (adopt, restart, upgrade)
- Client operations (block, reconnect, metadata)
- Network configuration (VLANs, WLANs, firewall)
- WiFi analytics (connectivity, stats, radio AI)
- Traffic analysis (flows, DPI, routes)
- Event monitoring and logging
- Health and security status

#### Safety & Reliability
- 🔒 **Dry-run mode**: Preview deletions without executing
- ✋ **Interactive confirmations**: Prompts before destructive operations
- 📝 **Context-aware errors**: Detailed troubleshooting guidance
- 🔄 **Watch mode**: Live refresh with timestamps
- 🎯 **Smart defaults**: Sensible configuration precedence

## Installation

### cargo (recommended)

```bash
cargo install unifictl
```

### From Source

```bash
git clone https://github.com/nachtschatt3n/unifictl.git
cd unifictl
cargo build --release
sudo cp target/release/unifictl /usr/local/bin/
```

### Package Managers

**Debian/Ubuntu**
```bash
cargo install cargo-deb
cargo deb
sudo dpkg -i target/debian/unifictl_*.deb
```

**Arch Linux**
```bash
cargo install unifictl
```

### Updating to a New Version

**cargo**
```bash
cargo install unifictl
```

**From source**
```bash
cd unifictl
git pull
cargo build --release
sudo cp target/release/unifictl /usr/local/bin/
```

**Debian/Ubuntu**
```bash
cd unifictl
git pull
cargo deb
sudo dpkg -i target/debian/unifictl_*.deb
```

## Quick Start

### 1. Login (cloud + local in one step)

```bash
# Cloud API key only
unifictl login --api-key "YOUR_API_KEY"

# Local controller only (password prompted securely)
unifictl login \
  --controller-url https://192.168.1.1 \
  --username admin

# Both at once
unifictl login \
  --api-key "YOUR_API_KEY" \
  --controller-url https://192.168.1.1 \
  --username admin

unifictl cloud host list
```

### 3. Basic Commands

```bash
# List devices
unifictl local device list

# Get client details with AI optimization
unifictl local client list -o llm

# Troubleshoot a client
unifictl local correlate client aa:bb:cc:dd:ee:ff --include-events

# Run network diagnostics
unifictl local diagnose network

# Export traffic data
unifictl local time-series traffic \
  --start 1765000000000 \
  --end 1765100000000 \
  --format csv > traffic.csv
```

## Common Use Cases

### 🔍 Troubleshoot Client Connectivity

```bash
# Get everything about a client in one command
unifictl local correlate client <MAC> --include-events -o llm

# Returns: client info + connected AP + recent events + AI summary
```

### 📊 Network Health Check

```bash
# Quick health assessment
unifictl local diagnose network -o llm

# WiFi performance check
unifictl local diagnose wifi

# VPN health with packet loss reasons
unifictl local vpn get -o json
```

### 📈 Bandwidth Analysis

```bash
# Export last 24 hours of traffic
START=$(python3 -c "import time; print(int((time.time() - 86400) * 1000))")
END=$(python3 -c "import time; print(int(time.time() * 1000))")

unifictl local time-series traffic --start $START --end $END --format csv
```

### 🔧 Device Management

```bash
# List unadopted devices
unifictl local device list --unadopted

# Adopt all pending devices
unifictl local device adopt-all --yes

# Restart a device
unifictl local device restart <MAC>

# Power-cycle a single PoE port on a switch (only affects that port)
unifictl local device power-cycle <SWITCH-MAC> <PORT>
```

### 🎨 Custom Output

```bash
# Live monitoring
unifictl local client list --watch 5

# Filtered export
unifictl local device list \
  --filter "AP" \
  --columns name,ip,model,version \
  --sort-by name \
  -o csv > aps.csv

# Regex filtering
unifictl local device list --filter-regex "^U(AP|SW)-.*"
```

## AI Agent Integration

For AI-powered network management, see the comprehensive [AI Agent Guide](AI_AGENT_GUIDE.md).

**Quick Example:**
```python
import subprocess
import json

# Get LLM-optimized device data
result = subprocess.run(
    ["unifictl", "local", "device", "list", "-o", "llm"],
    capture_output=True, text=True
)

data = json.loads(result.stdout)
print(f"Found {data['llm_metadata']['item_count']} devices")
print(f"Estimated tokens: {data['llm_metadata']['estimated_tokens']}")
print(f"Token efficient: {data['llm_metadata']['ai_guidance']['token_efficient']}")
```

## Safe writes and collection completeness

A local mutation is submitted once to a preselected controller route. A timeout,
lost response, redirect, server error, or unavailable route can leave the outcome
unknown. The CLI does not retry the mutation or discover another route by replaying
it. Read back the affected resource before deciding whether another command is
needed. HTTP 401/403/429 is terminal for a batch. Modern local writes use the
proxied legacy REST/command route or the v2 site route according to the resource;
controllers that require another write route are not supported by automatic
fallback. This is not a claim of compatibility with every controller version.

`device adopt-all` requires `--yes` to submit actions, or `--dry-run` to inspect
pending targets without mutation. It validates and deduplicates the observed MACs,
stops after authorization/rate rejection or an unknown write outcome, and reports
remaining targets as `not_attempted`. A successful HTTP response means
`accepted_unverified`; one inventory readback must show `adopted: true` to mark a
target `confirmed`. Partial failures and unconfirmed results exit nonzero.
Adoption may still finish asynchronously; inspect controller state before retrying.

JSON and raw output keep their existing shapes by default. To request collection
metadata explicitly, use `--with-metadata -o json` with device/client/event/alarm
lists or top-client/top-device. Bare arrays are wrapped in `data` only with this
option. `_unifictl.collection` reports the requested limit, returned and observed
counts, controller-reported total when available, truncation, filtering, and
`inventory_complete` (`complete`, `incomplete`, or `unknown`). `observed_count`
counts available matching rows before the CLI limit. A fulfilled requested limit
is not proof of a complete inventory. Without a controller-reported total,
completeness remains unknown even for a valid empty list. LLM output includes this
metadata automatically and distinguishes collection truncation from display
sampling. `--with-metadata` accepts JSON or LLM output; raw response output is not
extended. Controller-supplied `_unifictl` fields cannot supply trusted metadata.
Compatibility note for LLM consumers: `llm_metadata.truncation_applied` is now
`null` rather than `false` when collection truncation metadata is unavailable.
`false` means no truncation was recorded; inventory completeness may still be
`unknown`. `sampling_applied` separately describes display sampling.

Event pagination keeps a stable page size after the first page, fails explicitly
on missing record arrays, repeated records or changing reported totals, and
retains the existing safety cap. These checks do not provide snapshot isolation
while the controller's events change. Known collection endpoints require a bare
array or an object with a `data` array. Invalid JSON, an invalid collection shape,
or an explicit `meta.rc` failure exits nonzero; a valid empty array remains valid.
A read-only candidate that serves an HTML UI page is skipped in favor of the
next known route on the same controller origin; HTML is never returned as
successful API data. This fallback does not replay mutations or login requests.
Settings and aggregate endpoints may still return objects. These are response
contracts, not a guarantee that the controller returned every record.

`diagnose` reports failed collections explicitly instead of inventing empty or
healthy data. Network diagnosis uses one health snapshot and exits nonzero for
failed or unknown subsystem checks, including missing WAN status. This is a
conservative policy: an optional or unconfigured subsystem (for example VPN)
reporting `unknown` also causes a nonzero exit. It does not prove an outage.
No subsystem allow-list has been validated against a live controller; inspect
individual checks before using the aggregate exit status for alerts. Device,
WiFi and client collection success alone does not establish healthy service.
Requested correlation sources must succeed; `--include-events` examines at most 50 recent
events and returns at most 20 matching records, not the client's entire history.
Optional metadata reports source collection and keeps inventory coverage unknown.
The command-specific `--site` applies to every source of these aggregate commands.

`time-series events` preserves its 50-event default and applies an explicit limit
to both JSON and CSV, paging beyond the controller's first response. A malformed
later page fails before exporting results. The JSON export supports optional
collection metadata; CSV keeps its existing columns (metadata is emitted to
stderr when requested with `-o json --with-metadata`). Modern message/category
fields map to the legacy CSV columns. Timestamp values pass through unchanged;
numeric units are not inferred. Time-series commands select output using
`--format csv|json`; `-o llm` does not produce the general LLM envelope. For events,
`--with-metadata` (or `-o llm`) enables collection metadata in JSON or the CSV
stderr sidecar. Traffic/WiFi exports retain their existing JSON/CSV contract:
`--with-metadata` and `-o llm` do not add collection metadata or an LLM envelope.
Their inventory coverage remains unknown and is not encoded in these exports.
Traffic/WiFi CSV requires an array-shaped series rather than silently emitting a
header for an unsupported aggregate object.

`--watch` rejects zero; choose a polling interval appropriate to controller limits
and use supervisor backoff and missing-sample alerts. A successful fetch is not a
health diagnosis. These safeguards do not replace live controller/version testing.

## Command Reference

### Cloud API (Site Manager)

```bash
# Hosts
unifictl cloud host list
unifictl cloud host get <HOST_ID>

# Sites and devices
unifictl cloud site list [--host-id <HOST_ID>]
unifictl cloud device list [--host-id <HOST_ID>] [--site-id <SITE_ID>]
unifictl cloud device get <DEVICE_ID>

# ISP metrics and SD-WAN (EA)
unifictl cloud isp get --type 5m --site-id <SITE_ID> --start <RFC3339> --end <RFC3339>
unifictl cloud sdwan list
unifictl cloud sdwan get <CONFIG_ID>
```

### Local Controller

<details>
<summary><b>Device Operations</b></summary>

```bash
unifictl local device list [--unadopted] [--limit N]
unifictl local device get <MAC> [--ports] [--config]
unifictl local device restart <MAC>
unifictl local device power-cycle <MAC> <PORT>
unifictl local device adopt <MAC>
unifictl local device adopt-all --yes
unifictl local device upgrade <MAC>
unifictl local device spectrum-scan <MAC>
unifictl local device port-anomalies
unifictl local device mac-tables [--device <MAC>]
```
</details>

<details>
<summary><b>Client Operations</b></summary>

```bash
unifictl local client list [--wired|--wireless|--blocked] [--limit N]
unifictl local client block <MAC>
unifictl local client unblock <MAC>
unifictl local client reconnect <MAC>
unifictl local client active [--limit N]
unifictl local client history [--mac <MAC>] [--limit N]
```

> **Result limits are explicit.** List commands default to `--limit 30`. When a
> result set is cut short, a warning naming the full count is printed to
> stderr (stdout stays valid JSON/CSV), so a truncated answer is never mistaken
> for the whole picture. `client history --mac` matches case-insensitively and
> accepts colon, dash or bare-hex MAC forms.
</details>

<details>
<summary><b>AI-Powered Commands</b></summary>

```bash
# Correlation
unifictl local correlate client <MAC> [--include-events]
unifictl local correlate device <MAC> [--include-clients]
unifictl local correlate ap <AP_MAC>

# Diagnostics
unifictl local diagnose network
unifictl local diagnose wifi
unifictl local diagnose client [<MAC>]

# Time-Series
unifictl local time-series traffic --start <TS> --end <TS> [--format csv|json]
unifictl local time-series wifi --start <TS> --end <TS> [--format csv|json]
unifictl local time-series events [--limit N] [--format csv|json]
```
</details>

<details>
<summary><b>WiFi Operations</b></summary>

```bash
unifictl local wifi connectivity
unifictl local wifi stats --start <TS> --end <TS> [--ap-mac <MAC|all>] [--radios]
unifictl local wifi radio-ai
unifictl local wifi management
unifictl local wifi config
```
</details>

<details>
<summary><b>Traffic & Analytics</b></summary>

```bash
unifictl local traffic stats --start <TS> --end <TS> --include-unidentified <true|false>
unifictl local traffic flow-latest --period <day|month> --top <N>
unifictl local traffic app-rate --start <TS> --end <TS>
unifictl local traffic filter-data
unifictl local traffic routes
unifictl local traffic rules
unifictl local traffic flows [--query <JSON>]
```
</details>

<details>
<summary><b>Network Configuration</b></summary>

```bash
unifictl local network list|create|update|delete
unifictl local wlan list|create|update|delete
unifictl local firewall-rule list|create|update|delete
unifictl local firewall-group list|create|update|delete
unifictl local policy-table list|create|update|delete
unifictl local zone list|create|update|delete
unifictl local object list|create|update|delete
unifictl local port-profile list
```
</details>

<details>
<summary><b>Monitoring</b></summary>

```bash
unifictl local health get
unifictl local security get
unifictl local wan get
unifictl local dpi get
unifictl local event list [--limit N]   # paginates past the controller's 50/page default
unifictl local log critical|all|count|device-alert|admin-activity
unifictl local stat alarm [--archived] [--limit N]   # threat / IPS-IDS alarms
unifictl local stat rogueap
unifictl local top-client list [--limit N]
unifictl local top-device list [--limit N]
```
</details>

## Testing

```bash
# Run unit tests
cargo test

# Run full endpoint test suite
bash test_all_endpoints.sh

# Test specific functionality
cargo test --test integration_test
```

Current test coverage: **75 endpoints, 100% passing**

## Configuration

**Precedence order**: CLI flag → Local config (`.unifictl.yaml`) → User config (`~/.config/unifictl/config.yaml`)

```bash
# Cloud API key + local controller in one command
unifictl login --api-key "YOUR_API_KEY" \
  --controller-url https://192.168.1.1 \
  --username admin \
  --site default \
  [--verify-tls] \
  [--scope local|user]

unifictl cloud config-show  # View current config (passwords masked)
```

Omitting `--password` causes an interactive prompt with hidden input — this is the recommended approach to avoid exposing credentials in shell history.

**File permissions**: `config.yaml` holds the controller password and API key, so `unifictl` creates and rewrites it owner-only (mode `0600`, the same way it writes `session.json`) and keeps the user config directory at `0700`. A config file left world-readable by an older release is tightened to `0600` the first time it is read, with a one-line notice on stderr. This applies on Unix (Linux/macOS); on Windows the file inherits the directory's ACL as before.

**Note**: TLS verification is disabled by default for self-signed certificates. Use `--verify-tls` if your controller has a valid certificate.

## Troubleshooting

### UDM Rate Limiting

UniFi Dream Machines may hit login rate limits with CLI tools that create new sessions per command.

**Symptoms**: `403 invalid username/password`, `429 AUTHENTICATION_FAILED_LIMIT_REACHED`, or repeated local login failures

**SSH recovery process (current UniFi OS)**:
```bash
# SSH directly to the console as root
ssh root@<udm-ip>

# Inspect UniFi-related services
systemctl list-units | grep -i 'unifi\|ulp'

# Confirm the login limiter config exists
grep -n "success.login.limit.count" /usr/lib/ulp-go/config.props

# Restart the auth service that owns the limiter on current UDM builds
systemctl restart ulp-go

# If needed, also restart the main UniFi services
systemctl restart unifi-core unifi-directory uos-agent
```

**Notes**:
```bash
# On newer firmware, `unifi-os` may not exist as a systemd service.
# If you change the limiter, the config file is:
/usr/lib/ulp-go/config.props

# Example setting
success.login.limit.count = 200
```

In testing on a current UDM Pro, restarting `ulp-go` cleared `AUTHENTICATION_FAILED_LIMIT_REACHED` while `systemctl restart unifi` and `systemctl restart unifi-core unifi-directory uos-agent` alone did not.

### Common Issues

**Port 8443 connectivity**: The tool automatically preserves port `:8443` for local controllers

**Certificate errors**: Use the default (no `--verify-tls`) for self-signed certs

**Site parameter**: Commands default to configured site; override with `--site <NAME>`

## Development

See [AGENTS.md](AGENTS.md) for development guidelines, testing requirements, and contribution workflow.

**Quick development setup**:
```bash
cargo build
cargo test
cargo clippy
cargo fmt
```

## Documentation

- **[README.md](README.md)** - This file (overview and reference)
- **[AI_AGENT_GUIDE.md](AI_AGENT_GUIDE.md)** - Comprehensive AI agent integration guide
- **[EXAMPLES.md](EXAMPLES.md)** - Real-world usage examples
- **[AGENTS.md](AGENTS.md)** - Development and contribution guide

## License

GPL-3.0 - see [LICENSE](LICENSE) file for details

## Credits

Built by [Mathias Uhl](https://github.com/nachtschatt3n)

---

<div align="center">

**[⬆ Back to Top](#unifictl)**

</div>

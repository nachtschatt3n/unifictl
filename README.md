# unifictl

<div align="center">

[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.89+-orange.svg)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/version-5.7.0-green.svg)](https://github.com/nachtschatt3n/unifictl)
[Testing](#testing)

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
unifictl local device adopt-all

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
unifictl local device adopt-all
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

Automated tests use synthetic HTTP mocks. Real controller/version/role compatibility must be checked separately in an authorized test environment; a mock pass is not that evidence.

## Configuration

**Precedence order**: CLI flag → Local config (`.unifictl.yaml`) → User config (`~/.config/unifictl/config.yaml`)

```bash
# Cloud API key + local controller in one command
unifictl login --api-key "YOUR_API_KEY" \
  --controller-url https://192.168.1.1 \
  --username admin \
  --site default \
  [--ca-file /path/to/controller-ca.pem] \
  [--scope local|user]

unifictl cloud config-show  # View current config (passwords masked)
```

Omitting `--password` causes an interactive prompt with hidden input — this is the recommended approach to avoid exposing credentials in shell history.

**File permissions**: Configuration and session files are written atomically with mode `0600` on Unix, and the user configuration/cache directories are kept at `0700`. Reading a project config does not change its permissions. User configuration and cache files are checked through an owned, regular, non-symlink file handle; old broad permissions are repaired through that handle. Windows files still inherit directory ACLs; protect that directory separately.

**Credential destinations**: A project `.unifictl.yaml` can override nonsecret settings such as `site`. If it changes a controller URL or username, it must supply credentials for that target instead of inheriting the user's password. A project cloud base-URL change likewise cannot inherit the user's API key. Project TLS/CA settings cannot weaken the trust policy of an inherited user password. Use global `--no-project-config` in automation or when entering an unfamiliar checkout. Explicit CLI cloud URL overrides are trusted user input; cloud URLs require HTTPS.

**Session cache**: Sessions are stored separately for each controller URL, username and site, bounded to 64 entries. Equivalent URL spellings (host case, default port, empty root path) share the same cache identity. Alternating sites does not repeatedly log in. Saving changed local credentials invalidates that principal's cached sites; `login validate` always tests the supplied password afresh. The cache never changes the configured port or destination. Reuse is also bound to the verification mode and CA bundle; old cache entries without that trust profile require a fresh login. `--no-session-cache` bypasses reuse; it does not revoke remote sessions.

**TLS migration**: Verification is enabled when `verify_tls` is omitted. For a private CA or self-signed controller certificate, use `unifictl login --controller-url https://controller.example --username admin --verify-tls --ca-file /absolute/path/controller-ca.pem`. The PEM bundle adds trusted roots while hostname verification remains enabled; use a hostname present in the certificate. Relative CA paths in YAML are relative to that YAML file. `--insecure` is an explicit local-controller opt-out (also permitting HTTP) and cannot be combined with a CA file. Existing `verify_tls: false` configurations retain their explicit opt-out and print a warning; migrate them to verification rather than leaving them unchanged. Authentication and API redirects are never followed. The `:8443` to `:443` login fallback is off by default because it sends the password to a different port; opt in with `unifictl login ... --port-fallback` (or `port_fallback: true` in the config) and disable again with `--no-port-fallback`. It only applies when the `:8443` controller is unreachable or has no login endpoint, never after a credential rejection.

Saving login settings for a different controller resets the old TLS exception and CA selection; supply that target's trust settings explicitly. Re-saving the same canonical URL preserves its settings. A CA combined with disabled verification is rejected before prompting for a password or saving configuration.

## Troubleshooting

### UDM Rate Limiting

UniFi Dream Machines may hit login rate limits with CLI tools that create new sessions per command.

**Symptoms**: `403 invalid username/password`, `429 AUTHENTICATION_FAILED_LIMIT_REACHED`, or repeated local login failures

Repeated credential rejection (401/403) is terminal. Safe reads share at most one authentication refresh for the client lifetime, including multi-component commands, and each read has at most one bounded `Retry-After` delay. Writes are never automatically replayed; `adopt-all` stops on the first 401/403/429 or ambiguous result and marks remaining targets as not attempted. Check credentials, permissions, the explicit URL and the configured site, then wait for the controller's documented lockout period. Do not raise gateway login limits or restart controller services as part of routine CLI recovery. Monitoring supervisors should use backoff and jitter, inspect exit status, and avoid overlapping executions.

**Legacy login compatibility remains unverified**: The legacy `/api/login` route is tried only after earlier login routes return 404/405. A self-hosted controller that returns 401 at `/api/auth/login` will stop login before that legacy route. Do not interpret this as proof of an incorrect password. This conservative behavior needs validation against a disposable controller of the affected version; no automatic credential retry or controller-family detection is claimed.

### Common Issues

**Port 8443 connectivity**: The tool automatically preserves port `:8443` for local controllers

**Certificate errors**: Install a trusted certificate or supply `--ca-file` with the correct controller CA and certificate hostname.

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

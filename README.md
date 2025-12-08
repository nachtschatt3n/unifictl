# unifictl

<div align="center">

[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/version-0.5.0-green.svg)](https://github.com/nachtschatt3n/unifictl)
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
cd packaging/arch
makepkg -si
```

## Quick Start

### 1. Configure Cloud API

```bash
unifictl configure --key "YOUR_API_KEY"
unifictl host list
```

### 2. Configure Local Controller

```bash
unifictl local configure \
  --url https://192.168.1.1:8443 \
  --username admin \
  --password 'your-password' \
  --site default \
  --scope local
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
unifictl host list
unifictl host get <HOST_ID>

# Sites and devices
unifictl site list [--host-id <HOST_ID>]
unifictl device list [--host-id <HOST_ID>] [--site-id <SITE_ID>]
unifictl device get <DEVICE_ID>

# ISP metrics and SD-WAN (EA)
unifictl isp get --type 5m --site-id <SITE_ID> --start <RFC3339> --end <RFC3339>
unifictl sdwan list
unifictl sdwan get <CONFIG_ID>
```

### Local Controller

<details>
<summary><b>Device Operations</b></summary>

```bash
unifictl local device list [--unadopted] [--limit N]
unifictl local device get <MAC> [--ports] [--config]
unifictl local device restart <MAC>
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
unifictl local client history [--limit N]
```
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
unifictl local event list [--limit N]
unifictl local log critical|all|count|device-alert
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

### Cloud API
```bash
unifictl configure --key "YOUR_API_KEY" [--scope local|user]
unifictl config-show  # View current config (passwords masked)
```

### Local Controller
```bash
unifictl local configure \
  --url https://192.168.1.1:8443 \
  --username admin \
  --password 'password' \
  --site default \
  [--verify-tls] \
  [--scope local]
```

**Note**: TLS verification is disabled by default for self-signed certificates. Use `--verify-tls` if your controller has a valid certificate.

## Troubleshooting

### UDM Rate Limiting

UniFi Dream Machines may hit login rate limits with CLI tools that create new sessions per command.

**Symptoms**: Repeated 401 errors, intermittent authentication failures

**Solution**:
```bash
# SSH into your UDM
vi /usr/lib/ulp-go/config.props

# Find and increase this value
success.login.limit.count=100  # Default is 5-10

# Restart UniFi OS
systemctl restart unifi-os
```

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

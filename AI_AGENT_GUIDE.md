# AI Agent Usage Guide for unifictl

This guide provides AI agents with comprehensive instructions for using `unifictl` to troubleshoot, monitor, and manage UniFi networks efficiently.

## Table of Contents
- [Overview](#overview)
- [LLM-Optimized Output](#llm-optimized-output)
- [Correlation Commands](#correlation-commands)
- [Diagnostic Mode](#diagnostic-mode)
- [Time-Series Data Export](#time-series-data-export)
- [Token Management](#token-management)
- [Common AI Workflows](#common-ai-workflows)

## Overview

`unifictl` has been enhanced with AI-first features to enable efficient network troubleshooting and analysis:

1. **LLM-Optimized Output** (`-o llm`): Token-aware JSON responses with metadata, schemas, and intelligent truncation
2. **Correlation Commands**: Gather all related data for a client, device, or AP in a single command
3. **Diagnostic Mode**: Multi-endpoint health checks with analysis recommendations
4. **Time-Series Export**: Export historical data for trend analysis
5. **JSON Schemas**: Understand response structures and field meanings

## LLM-Optimized Output

Use `-o llm` to get AI-friendly output with automatic token estimation and smart truncation.

### Example: Device List

```bash
unifictl local device list -o llm
```

**Output Structure:**
```json
{
  "llm_metadata": {
    "version": "1.0",
    "timestamp": "2025-12-07T23:00:00Z",
    "estimated_tokens": 2500,
    "data_type": "array_wrapped",
    "item_count": 15,
    "truncation_applied": false,
    "ai_guidance": {
      "summary": "Response contains 15 items with ~2500 tokens",
      "recommended_max_tokens": 4000,
      "token_efficient": true
    }
  },
  "schema": {
    "name": "device.list",
    "description": "List all devices (APs, switches, gateways) in the network",
    "use_cases": [
      "Inventory management",
      "Health monitoring",
      "Firmware update planning",
      "Troubleshooting connectivity"
    ],
    "important_fields": [
      {"name": "mac", "type": "string", "description": "Device MAC address (unique identifier)"},
      {"name": "name", "type": "string", "description": "Device name/hostname"},
      {"name": "model", "type": "string", "description": "Device model"},
      {"name": "state", "type": "number", "description": "Adoption state"},
      {"name": "ip", "type": "string", "description": "Current IP address"}
    ]
  },
  "data": [...],  // Full data if < 4000 tokens
  "statistics": {
    "total_items": 15,
    "common_fields": ["mac", "name", "model", "ip", "state"],
    "field_coverage": {...}
  }
}
```

### Intelligent Truncation

For large responses (>4000 estimated tokens), LLM output automatically samples data:

```json
{
  "llm_metadata": {
    "truncation_applied": true,
    "truncation_note": "Original response had 150 items. Showing 15 representative samples..."
  },
  "data_samples": [
    {"position": "start", "index": 0, "data": {...}},
    {"position": "start", "index": 1, "data": {...}},
    // ... samples from start, middle, and end
    {"position": "end", "index": 149, "data": {...}}
  ]
}
```

## Correlation Commands

Gather all related data for troubleshooting in a single command.

### Correlate Client Data

Get everything about a specific client (MAC, IP, connected AP, recent events):

```bash
unifictl local correlate client aa:bb:cc:dd:ee:ff --include-events -o llm
```

**Returns:**
- Client details (IP, hostname, signal strength, bandwidth)
- Connected AP information (if wireless)
- Recent events (last 20 events involving this client)
- LLM summary with key insights

**Use Cases:**
- Troubleshooting client connectivity issues
- Understanding client roaming behavior
- Investigating performance complaints

### Correlate Device Data

Get everything about a device (AP/switch) and its connected clients:

```bash
unifictl local correlate device e4:38:83:67:db:ba --include-clients -o llm
```

**Returns:**
- Device details (model, firmware, uptime, state)
- All connected clients (if `--include-clients` specified)
- Client count summary

**Use Cases:**
- AP performance analysis
- Capacity planning
- Identifying overloaded devices

### Correlate AP and Clients

Shorthand for device correlation with clients included:

```bash
unifictl local correlate ap e4:38:83:67:db:ba -o llm
```

## Diagnostic Mode

Run multi-endpoint diagnostic checks with AI-friendly recommendations.

### Network Diagnostics

Comprehensive network health check:

```bash
unifictl local diagnose network -o llm
```

**Checks:**
- Overall network health
- WAN status
- Device connectivity
- Service availability

**Output:**
```json
{
  "diagnostic_type": "network",
  "timestamp": "2025-12-07T23:00:00Z",
  "checks": [
    {"name": "Health", "status": "pass", "data": {...}},
    {"name": "WAN", "status": "pass"},
    {"name": "Devices", "status": "pass", "device_count": 15}
  ],
  "llm_summary": {
    "total_checks": 3,
    "passed": 3,
    "recommendation": "All systems operational"
  }
}
```

### WiFi Diagnostics

Analyze WiFi performance and AP health:

```bash
unifictl local diagnose wifi -o llm
```

**Returns:**
- WiFi connectivity metrics
- AP status and distribution
- Channel utilization
- Client satisfaction scores

### Client Diagnostics

**Specific Client:**
```bash
unifictl local diagnose client aa:bb:cc:dd:ee:ff -o llm
```

Returns detailed correlation data with events for troubleshooting.

**All Clients Overview:**
```bash
unifictl local diagnose client -o llm
```

Returns summary statistics:
- Total client count
- Wireless vs wired breakdown
- Active connections

## Time-Series Data Export

Export historical data for trend analysis and pattern detection.

### Traffic Time-Series

Export bandwidth usage over time:

```bash
# Last 24 hours (timestamps in milliseconds)
START=$(python3 -c "import time; print(int((time.time() - 86400) * 1000))")
END=$(python3 -c "import time; print(int(time.time() * 1000))")

# Export as CSV for analysis
unifictl local time-series traffic --start $START --end $END --format csv > traffic.csv

# Or JSON for programmatic processing
unifictl local time-series traffic --start $START --end $END --format json -o llm
```

**CSV Format:**
```csv
timestamp,rx_bytes,tx_bytes
1765060726000,1234567890,9876543210
1765061026000,1234568000,9876543500
```

### WiFi Time-Series

Export WiFi performance metrics:

```bash
# All APs
unifictl local time-series wifi --start $START --end $END --format csv > wifi_all.csv

# Specific AP
unifictl local time-series wifi --start $START --end $END --ap-mac e4:38:83:67:db:ba --format csv > wifi_ap.csv
```

**CSV Format:**
```csv
timestamp,ap_mac,channel,num_sta,satisfaction
1765060726000,e4:38:83:67:db:ba,40,15,0.95
1765061026000,e4:38:83:67:db:ba,40,16,0.94
```

### Event Time-Series

Export recent events for analysis:

```bash
# Last 100 events as CSV
unifictl local time-series events --limit 100 --format csv > events.csv

# JSON for detailed analysis
unifictl local time-series events --limit 50 --format json -o llm
```

## Token Management

### Estimating Token Usage

LLM output includes token estimates:

```json
{
  "llm_metadata": {
    "estimated_tokens": 2500,
    "token_efficient": true  // true if < 4000 tokens
  }
}
```

**Token Estimation Formula:** `~4 characters per token`

### Controlling Output Size

Use `--limit` to control array sizes before LLM processing:

```bash
# Limit to 10 devices
unifictl local device list --limit 10 -o llm

# Limit to 20 clients
unifictl local client list --limit 20 -o llm

# Limit events
unifictl local event list --limit 30 -o llm
```

### Response Size Guidelines

| Command | Typical Tokens | Recommendation |
|---------|----------------|----------------|
| `device list` (10 devices) | ~800 | Use directly |
| `device list` (50 devices) | ~4000 | Use `--limit` |
| `client list` (20 clients) | ~1200 | Use directly |
| `event list` (30 events) | ~1800 | Use directly |
| `correlate client` | ~600 | Use directly |
| `diagnose network` | ~500 | Use directly |

## Common AI Workflows

### 1. Client Connectivity Troubleshooting

```bash
# Step 1: Get client correlation data
unifictl local correlate client $MAC --include-events -o llm

# Step 2: Check connected AP
AP_MAC=$(unifictl local correlate client $MAC -o json | jq -r '.connected_ap.mac')
unifictl local correlate device $AP_MAC --include-clients -o llm

# Step 3: Review recent events
unifictl local event list --limit 50 -o llm | grep $MAC
```

### 2. Network Performance Analysis

```bash
# Step 1: Run network diagnostics
unifictl local diagnose network -o llm

# Step 2: Check WiFi health
unifictl local diagnose wifi -o llm

# Step 3: Export traffic trends
unifictl local time-series traffic --start $START --end $END --format csv
```

### 3. Capacity Planning

```bash
# Step 1: Get all devices
unifictl local device list -o llm

# Step 2: Get client distribution
unifictl local client list -o llm

# Step 3: Check top talkers
unifictl local top-client list --limit 20 -o llm
unifictl local top-device list --limit 20 -o llm

# Step 4: Export historical trends
unifictl local time-series traffic --start $START --end $END --format csv
```

### 4. Security Monitoring

```bash
# Step 1: Check security status
unifictl local security get -o llm

# Step 2: Review recent events for anomalies
unifictl local event list --limit 100 -o llm

# Step 3: Check for rogue APs
unifictl local stat rogueap -o llm

# Step 4: Review firewall rules
unifictl local firewall-rule list -o llm
```

## Best Practices for AI Agents

1. **Start with LLM output** (`-o llm`) for better context understanding
2. **Use correlation commands** to reduce API calls and gather related data
3. **Apply limits** to large datasets to stay within token budgets
4. **Export time-series** for trend analysis rather than querying repeatedly
5. **Use diagnostic mode** for initial assessment before deep diving
6. **Reference schemas** in LLM output to understand field meanings
7. **Check token estimates** before processing large responses
8. **Leverage filters** (`--filter`, `--filter-regex`) to reduce data volume

## API Rate Limiting

**Important:** UniFi controllers (especially UDMs) have login rate limits.

**Symptoms:**
- Repeated authentication errors
- Commands failing intermittently

**Solution:**
- Increase `success.login.limit.count` in `/usr/lib/ulp-go/config.props` on the controller
- Batch your queries using correlation and diagnostic commands
- Use `--limit` to reduce data volume per request

## Error Handling

All commands provide context-aware error messages:

```bash
# Example error with troubleshooting guidance
Error: Device not found (404)

Possible causes:
- MAC address is incorrect
- Device has been removed
- Device is on a different site

Try:
- unifictl local device list -o json
- unifictl local device list --unadopted
```

## JSON Schema Reference

Common response structures:

### Device Response
- `mac` (string): Device MAC address
- `name` (string): Device name
- `model` (string): Hardware model
- `type` (string): Device type (uap, usw, ugw)
- `state` (number): Adoption state
- `ip` (string): IP address
- `version` (string): Firmware version

### Client Response
- `mac` (string): Client MAC
- `hostname` (string): Hostname
- `ip` (string): IP address
- `is_wired` (boolean): Wired vs wireless
- `ap_mac` (string): Connected AP (wireless only)
- `rssi` (number): Signal strength in dBm
- `channel` (number): WiFi channel

### Event Response
- `_id` (string): Event ID
- `key` (string): Event type key
- `datetime` (string): ISO 8601 timestamp
- `msg` (string): Human-readable message
- `subsystem` (string): Subsystem (wlan, lan, etc.)

## Advanced Examples

### Multi-Site Analysis

```bash
# Get all sites
SITES=$(unifictl local site list -o json | jq -r '.data[].name')

# Analyze each site
for SITE in $SITES; do
  echo "Analyzing $SITE..."
  unifictl local diagnose network --site $SITE -o llm > "${SITE}_diagnostics.json"
done
```

### Automated Health Monitoring

```bash
#!/bin/bash
# health_check.sh - Run periodic health checks

unifictl local diagnose network -o llm > /tmp/health.json

# Check if all checks passed
FAILED=$(jq '.llm_summary.passed < .llm_summary.total_checks' /tmp/health.json)

if [ "$FAILED" = "true" ]; then
  echo "Health check failed!"
  jq '.checks[] | select(.status == "fail")' /tmp/health.json
  # Send alert...
fi
```

### Client Behavior Analysis

```bash
# Get all wireless clients
CLIENTS=$(unifictl local client list --wireless -o json | jq -r '.data[].mac')

# Analyze each client's events
for MAC in $CLIENTS; do
  unifictl local correlate client $MAC --include-events -o llm > "client_${MAC}.json"
done
```

## Support and Feedback

For issues, feature requests, or questions:
- GitHub: https://github.com/nachtschatt3n/unifictl/issues
- Documentation: README.md, EXAMPLES.md
- Development Guide: AGENTS.md

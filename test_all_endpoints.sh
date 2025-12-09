#!/bin/bash

# Test script for all unifictl endpoints
# Usage: ./test_all_endpoints.sh [output_log_file]

set -euo pipefail

LOG_FILE="${1:-test_results_$(date +%Y%m%d_%H%M%S).log}"
BINARY="./target/release/unifictl"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo "Error: Binary not found at $BINARY"
    echo "Please build first: cargo build --release"
    exit 1
fi

# Calculate timestamps (24 hours ago to now)
START_TS=$(python3 -c "import time; print(int(time.time() * 1000) - (24 * 60 * 60 * 1000))")
END_TS=$(python3 -c "import time; print(int(time.time() * 1000))")

# Test counter
TOTAL=0
PASSED=0
FAILED=0

# Function to test a command
test_command() {
    local name="$1"
    local cmd="$2"
    local expected_status="${3:-0}"  # Default to expecting success (0)
    
    TOTAL=$((TOTAL + 1))
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Test $TOTAL: $name"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Command: $cmd"
    echo ""
    
    # Log to file
    {
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "Test $TOTAL: $name"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "Command: $cmd"
        echo "Timestamp: $(date)"
        echo ""
    } >> "$LOG_FILE"
    
    # Run command and capture output without aborting on non-zero
    set +e
    OUTPUT=$(eval "$cmd" 2>&1)
    EXIT_CODE=$?
    set -e
    
    # Check if exit code matches expected
    if [ $EXIT_CODE -eq $expected_status ]; then
        echo -e "${GREEN}✓ PASSED${NC} (exit code: $EXIT_CODE)"
        PASSED=$((PASSED + 1))
        STATUS="PASSED"
    else
        echo -e "${RED}✗ FAILED${NC} (exit code: $EXIT_CODE, expected: $expected_status)"
        FAILED=$((FAILED + 1))
        STATUS="FAILED"
    fi
    
    # Log output to file
    {
        echo "Status: $STATUS"
        echo "Exit Code: $EXIT_CODE"
        echo "Output:"
        echo "$OUTPUT"
        echo ""
    } >> "$LOG_FILE"
    
    # Show first few lines of output
    echo "Output (first 10 lines):"
    echo "$OUTPUT" | head -10
    if [ $(echo "$OUTPUT" | wc -l) -gt 10 ]; then
        echo "... (truncated, see log file for full output)"
    fi
}

test_command_outputs() {
    local name="$1"
    local base_cmd="$2"
    local expected_status="${3:-0}"
    for fmt in json pretty raw csv llm; do
        test_command "${name} (${fmt})" "${base_cmd} -o ${fmt}" "$expected_status"
    done
}

# Start logging
{
    echo "=================================================================================="
    echo "unifictl Endpoint Test Suite"
    echo "=================================================================================="
    echo "Test Date: $(date)"
    echo "Binary: $BINARY"
    echo "Start Timestamp: $START_TS"
    echo "End Timestamp: $END_TS"
    echo "=================================================================================="
} > "$LOG_FILE"

echo "Testing all endpoints..."
echo "Log file: $LOG_FILE"
echo ""

# ============================================================================
# Cloud API Endpoints
# ============================================================================

echo "════════════════════════════════════════════════════════════════════════════════════"
echo "CLOUD API ENDPOINTS"
echo "════════════════════════════════════════════════════════════════════════════════════"

test_command_outputs "Host List" "$BINARY host list"
test_command_outputs "Host Get (expected fail without real ID)" "$BINARY host get dummy-host-id" 1
test_command_outputs "Site List" "$BINARY site list"
test_command_outputs "Device List" "$BINARY device list"
test_command_outputs "Device Get (expected fail without real ID)" "$BINARY device get dummy-device-id" 1
test_command_outputs "ISP Metrics (expected auth)" "$BINARY isp get --type 5m --start $(date -Iseconds) --end $(date -Iseconds)" 1
test_command_outputs "ISP Query (expected auth)" "$BINARY isp query --type hourly --body '{\"limit\":1}'" 1
test_command_outputs "SD-WAN List" "$BINARY sdwan list"
test_command_outputs "SD-WAN Get (expected fail without real ID)" "$BINARY sdwan get dummy-sdwan-id" 1
test_command_outputs "SD-WAN Status (expected fail without real ID)" "$BINARY sdwan status dummy-sdwan-id" 1

# ============================================================================
# Local Controller - Site & Device Management
# ============================================================================

echo ""
echo "════════════════════════════════════════════════════════════════════════════════════"
echo "LOCAL CONTROLLER - SITE & DEVICE MANAGEMENT"
echo "════════════════════════════════════════════════════════════════════════════════════"

test_command_outputs "Site List" "$BINARY local site list"
test_command_outputs "Device List" "$BINARY local device list"
test_command_outputs "Device List (Unadopted)" "$BINARY local device list --unadopted"
test_command_outputs "Health Get" "$BINARY local health get"
test_command_outputs "VPN Health Get" "$BINARY local vpn get"
test_command_outputs "Security Get" "$BINARY local security get"
test_command_outputs "WAN Get" "$BINARY local wan get"
test_command_outputs "DPI Get" "$BINARY local dpi get"

# ============================================================================
# Local Controller - Client Management
# ============================================================================

echo ""
echo "════════════════════════════════════════════════════════════════════════════════════"
echo "LOCAL CONTROLLER - CLIENT MANAGEMENT"
echo "════════════════════════════════════════════════════════════════════════════════════"

test_command_outputs "Client List" "$BINARY local client list"
test_command_outputs "Client List (Wired)" "$BINARY local client list --wired"
test_command_outputs "Client List (Wireless)" "$BINARY local client list --wireless"
test_command_outputs "Client Active (v2)" "$BINARY local client active"
test_command_outputs "Client History" "$BINARY local client history"
test_command_outputs "Top Client List" "$BINARY local top-client list --limit 10"
test_command_outputs "Top Device List" "$BINARY local top-device list --limit 10"

# ============================================================================
# Local Controller - System Log (v2 API)
# ============================================================================

echo ""
echo "════════════════════════════════════════════════════════════════════════════════════"
echo "LOCAL CONTROLLER - SYSTEM LOG (v2 API)"
echo "════════════════════════════════════════════════════════════════════════════════════"

test_command_outputs "Log Settings" "$BINARY local log settings"
test_command_outputs "Log All" "$BINARY local log all --limit 5"
test_command_outputs "Log Count" "$BINARY local log count"
test_command_outputs "Log Critical" "$BINARY local log critical --limit 5"
test_command_outputs "Log Device Alert" "$BINARY local log device-alert --limit 5"

# ============================================================================
# Local Controller - WiFi/Radio (v2 API) - REQUIRES PARAMETERS
# ============================================================================

echo ""
echo "════════════════════════════════════════════════════════════════════════════════════"
echo "LOCAL CONTROLLER - WIFI/RADIO (v2 API) - WITH REQUIRED PARAMETERS"
echo "════════════════════════════════════════════════════════════════════════════════════"

test_command_outputs "WiFi Connectivity" "$BINARY local wifi connectivity"
test_command_outputs "WiFi Stats (Details)" "$BINARY local wifi stats --start $START_TS --end $END_TS"
test_command_outputs "WiFi Stats (Details, all APs)" "$BINARY local wifi stats --start $START_TS --end $END_TS --ap-mac all"
test_command_outputs "WiFi Stats (Radios)" "$BINARY local wifi stats --radios --start $START_TS --end $END_TS"
test_command_outputs "WiFi Radio AI" "$BINARY local wifi radio-ai"
test_command_outputs "WiFi Management" "$BINARY local wifi management"
test_command_outputs "WiFi Config" "$BINARY local wifi config"

# ============================================================================
# Local Controller - Traffic/Flow (v2 API) - REQUIRES PARAMETERS
# ============================================================================

echo ""
echo "════════════════════════════════════════════════════════════════════════════════════"
echo "LOCAL CONTROLLER - TRAFFIC/FLOW (v2 API) - WITH REQUIRED PARAMETERS"
echo "════════════════════════════════════════════════════════════════════════════════════"

test_command_outputs "Traffic Stats" "$BINARY local traffic stats --start $START_TS --end $END_TS --include-unidentified true"
test_command_outputs "Traffic Stats (no unidentified)" "$BINARY local traffic stats --start $START_TS --end $END_TS --include-unidentified false"
test_command_outputs "Traffic Flow Latest (Day)" "$BINARY local traffic flow-latest --period day --top 30"
test_command_outputs "Traffic Flow Latest (Month)" "$BINARY local traffic flow-latest --period month --top 30"
test_command_outputs "Traffic App Rate" "$BINARY local traffic app-rate --start $START_TS --end $END_TS --include-unidentified true"
test_command_outputs "Traffic Filter Data" "$BINARY local traffic filter-data"
test_command_outputs "Traffic Routes" "$BINARY local traffic routes"
test_command_outputs "Traffic Rules" "$BINARY local traffic rules"
FLOWS_QUERY=$(printf '{"timestampFrom": %s, "timestampTo": %s, "pageNumber": 0, "pageSize": 10}' "$START_TS" "$END_TS")
test_command_outputs "Traffic Flows" "$BINARY local traffic flows --query '$FLOWS_QUERY'"

# ============================================================================
# Local Controller - Statistics (v1 API)
# ============================================================================

echo ""
echo "════════════════════════════════════════════════════════════════════════════════════"
echo "LOCAL CONTROLLER - STATISTICS (v1 API)"
echo "════════════════════════════════════════════════════════════════════════════════════"

test_command_outputs "Stat Country Code" "$BINARY local stat ccode"
test_command_outputs "Stat Current Channel" "$BINARY local stat current-channel"
test_command_outputs "Stat Device Basic" "$BINARY local stat device-basic"
test_command_outputs "Stat Guest" "$BINARY local stat guest"
test_command_outputs "Stat Rogue AP" "$BINARY local stat rogueap"
test_command_outputs "Stat SDN" "$BINARY local stat sdn"
test_command_outputs "Stat Report 5min" "$BINARY local stat report5min"

# ============================================================================
# Local Controller - Device Operations
# ============================================================================

echo ""
echo "════════════════════════════════════════════════════════════════════════════════════"
echo "LOCAL CONTROLLER - DEVICE OPERATIONS"
echo "════════════════════════════════════════════════════════════════════════════════════"

# Get a device MAC for testing (if available)
DEVICE_MAC=$(timeout 5 $BINARY local device list -o json 2>/dev/null | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    devices = data.get('data', [])
    if devices:
        mac = devices[0].get('mac')
        if mac:
            print(mac)
except:
    pass
" 2>/dev/null || echo "")

if [ -n "$DEVICE_MAC" ]; then
test_command_outputs "Device Get" "$BINARY local device get $DEVICE_MAC"
test_command_outputs "Device Spectrum Scan" "$BINARY local device spectrum-scan $DEVICE_MAC"
else
    echo "Skipping device-specific tests (no devices found)"
fi

test_command_outputs "Device Port Anomalies" "$BINARY local device port-anomalies"
test_command "Device Mac Tables" "$BINARY local device mac-tables -o json" 1  # May return 404

# ============================================================================
# Local Controller - Network Management
# ============================================================================

echo ""
echo "════════════════════════════════════════════════════════════════════════════════════"
echo "LOCAL CONTROLLER - NETWORK MANAGEMENT"
echo "════════════════════════════════════════════════════════════════════════════════════"

test_command_outputs "Network List" "$BINARY local network list"
test_command_outputs "WLAN List" "$BINARY local wlan list"
test_command_outputs "Port Profile List" "$BINARY local port-profile list"
test_command_outputs "Firewall Rule List" "$BINARY local firewall-rule list"
test_command_outputs "Firewall Group List" "$BINARY local firewall-group list"
test_command_outputs "Policy Table List" "$BINARY local policy-table list"
test_command_outputs "Zone List" "$BINARY local zone list"
test_command_outputs "Object List" "$BINARY local object list"

# ============================================================================
# Local Controller - Events
# ============================================================================

echo ""
echo "════════════════════════════════════════════════════════════════════════════════════"
echo "LOCAL CONTROLLER - EVENTS"
echo "════════════════════════════════════════════════════════════════════════════════════"

test_command_outputs "Event List" "$BINARY local event list"

# ============================================================================
# Local Controller - AI-Powered Features (Correlation, Diagnostics, Time-Series)
# ============================================================================

echo ""
echo "════════════════════════════════════════════════════════════════════════════════════"
echo "LOCAL CONTROLLER - AI-POWERED FEATURES"
echo "════════════════════════════════════════════════════════════════════════════════════"

# Get a client MAC for testing (if available)
CLIENT_MAC=$(timeout 5 $BINARY local client list -o json 2>/dev/null | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    clients = data.get('data', [])
    if clients:
        mac = clients[0].get('mac')
        if mac:
            print(mac)
except:
    pass
" 2>/dev/null || echo "")

# Correlation Commands
if [ -n "$CLIENT_MAC" ]; then
test_command_outputs "Correlate Client" "$BINARY local correlate client $CLIENT_MAC"
test_command_outputs "Correlate Client with Events" "$BINARY local correlate client $CLIENT_MAC --include-events"
else
    echo "Skipping client correlation tests (no clients found)"
fi

if [ -n "$DEVICE_MAC" ]; then
test_command_outputs "Correlate Device" "$BINARY local correlate device $DEVICE_MAC"
test_command_outputs "Correlate Device with Clients" "$BINARY local correlate device $DEVICE_MAC --include-clients"
test_command_outputs "Correlate AP" "$BINARY local correlate ap $DEVICE_MAC"
else
    echo "Skipping device correlation tests (no devices found)"
fi

# Diagnostic Commands
test_command_outputs "Diagnose Network" "$BINARY local diagnose network"
test_command_outputs "Diagnose WiFi" "$BINARY local diagnose wifi"
test_command_outputs "Diagnose Client Overview" "$BINARY local diagnose client"

if [ -n "$CLIENT_MAC" ]; then
test_command_outputs "Diagnose Specific Client" "$BINARY local diagnose client $CLIENT_MAC"
fi

# Time-Series Commands (use same timestamps from earlier in script)
test_command_outputs "Time-Series Traffic" "$BINARY local time-series traffic --start $START_TS --end $END_TS --format json"
test_command_outputs "Time-Series WiFi" "$BINARY local time-series wifi --start $START_TS --end $END_TS --format json"
test_command_outputs "Time-Series Events" "$BINARY local time-series events --limit 10 --format json"

# LLM Output Format Tests (verify -o llm works with various commands)
test_command_outputs "Device List (LLM Format)" "$BINARY local device list --limit 5"
test_command_outputs "Client List (LLM Format)" "$BINARY local client list --limit 5"
test_command_outputs "Event List (LLM Format)" "$BINARY local event list --limit 5"

# ============================================================================
# Summary
# ============================================================================

echo ""
echo "════════════════════════════════════════════════════════════════════════════════════"
echo "TEST SUMMARY"
echo "════════════════════════════════════════════════════════════════════════════════════"
echo "Total Tests: $TOTAL"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo ""
echo "Full results logged to: $LOG_FILE"
echo ""

# Log summary
{
    echo ""
    echo "=================================================================================="
    echo "TEST SUMMARY"
    echo "=================================================================================="
    echo "Total Tests: $TOTAL"
    echo "Passed: $PASSED"
    echo "Failed: $FAILED"
    echo "Success Rate: $(python3 -c "print(f'{($PASSED/$TOTAL*100):.1f}%' if $TOTAL > 0 else 'N/A')")"
    echo "=================================================================================="
} >> "$LOG_FILE"

# Exit with error if any tests failed
if [ $FAILED -gt 0 ]; then
    exit 1
else
    exit 0
fi

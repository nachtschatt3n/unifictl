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
    
    # Run command and capture output
    if OUTPUT=$(eval "$cmd" 2>&1); then
        EXIT_CODE=$?
    else
        EXIT_CODE=$?
    fi
    
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

test_command "Host List" "$BINARY host list -o json"
test_command "Site List" "$BINARY site list -o json"
test_command "Device List" "$BINARY device list -o json"
test_command "SD-WAN List" "$BINARY sdwan list -o json"

# ============================================================================
# Local Controller - Site & Device Management
# ============================================================================

echo ""
echo "════════════════════════════════════════════════════════════════════════════════════"
echo "LOCAL CONTROLLER - SITE & DEVICE MANAGEMENT"
echo "════════════════════════════════════════════════════════════════════════════════════"

test_command "Site List" "$BINARY local site list -o json"
test_command "Device List" "$BINARY local device list -o json"
test_command "Device List (Unadopted)" "$BINARY local device list --unadopted -o json"
test_command "Health Get" "$BINARY local health get -o json"
test_command "Security Get" "$BINARY local security get -o json"
test_command "WAN Get" "$BINARY local wan get -o json"
test_command "DPI Get" "$BINARY local dpi get -o json"

# ============================================================================
# Local Controller - Client Management
# ============================================================================

echo ""
echo "════════════════════════════════════════════════════════════════════════════════════"
echo "LOCAL CONTROLLER - CLIENT MANAGEMENT"
echo "════════════════════════════════════════════════════════════════════════════════════"

test_command "Client List" "$BINARY local client list -o json"
test_command "Client List (Wired)" "$BINARY local client list --wired -o json"
test_command "Client List (Wireless)" "$BINARY local client list --wireless -o json"
test_command "Client Active (v2)" "$BINARY local client active -o json"
test_command "Client History" "$BINARY local client history -o json"
test_command "Top Client List" "$BINARY local top-client list --limit 10 -o json"
test_command "Top Device List" "$BINARY local top-device list --limit 10 -o json"

# ============================================================================
# Local Controller - System Log (v2 API)
# ============================================================================

echo ""
echo "════════════════════════════════════════════════════════════════════════════════════"
echo "LOCAL CONTROLLER - SYSTEM LOG (v2 API)"
echo "════════════════════════════════════════════════════════════════════════════════════"

test_command "Log Settings" "$BINARY local log settings -o json"
test_command "Log All" "$BINARY local log all --limit 5 -o json"
test_command "Log Count" "$BINARY local log count -o json"
test_command "Log Critical" "$BINARY local log critical --limit 5 -o json"
test_command "Log Device Alert" "$BINARY local log device-alert --limit 5 -o json"

# ============================================================================
# Local Controller - WiFi/Radio (v2 API) - REQUIRES PARAMETERS
# ============================================================================

echo ""
echo "════════════════════════════════════════════════════════════════════════════════════"
echo "LOCAL CONTROLLER - WIFI/RADIO (v2 API) - WITH REQUIRED PARAMETERS"
echo "════════════════════════════════════════════════════════════════════════════════════"

test_command "WiFi Connectivity" "$BINARY local wifi connectivity -o json"
test_command "WiFi Stats (Details)" "$BINARY local wifi stats --start $START_TS --end $END_TS -o json"
test_command "WiFi Stats (Details, all APs)" "$BINARY local wifi stats --start $START_TS --end $END_TS --ap-mac all -o json"
test_command "WiFi Stats (Radios)" "$BINARY local wifi stats --radios --start $START_TS --end $END_TS -o json"
test_command "WiFi Radio AI" "$BINARY local wifi radio-ai -o json"
test_command "WiFi Management" "$BINARY local wifi management -o json"
test_command "WiFi Config" "$BINARY local wifi config -o json"

# ============================================================================
# Local Controller - Traffic/Flow (v2 API) - REQUIRES PARAMETERS
# ============================================================================

echo ""
echo "════════════════════════════════════════════════════════════════════════════════════"
echo "LOCAL CONTROLLER - TRAFFIC/FLOW (v2 API) - WITH REQUIRED PARAMETERS"
echo "════════════════════════════════════════════════════════════════════════════════════"

test_command "Traffic Stats" "$BINARY local traffic stats --start $START_TS --end $END_TS --include-unidentified true -o json"
test_command "Traffic Stats (no unidentified)" "$BINARY local traffic stats --start $START_TS --end $END_TS --include-unidentified false -o json"
test_command "Traffic Flow Latest (Day)" "$BINARY local traffic flow-latest --period day --top 30 -o json"
test_command "Traffic Flow Latest (Month)" "$BINARY local traffic flow-latest --period month --top 30 -o json"
test_command "Traffic App Rate" "$BINARY local traffic app-rate --start $START_TS --end $END_TS --include-unidentified true -o json"
test_command "Traffic Filter Data" "$BINARY local traffic filter-data -o json"
test_command "Traffic Routes" "$BINARY local traffic routes -o json"
test_command "Traffic Rules" "$BINARY local traffic rules -o json"
FLOWS_QUERY=$(printf '{"timestampFrom": %s, "timestampTo": %s, "pageNumber": 0, "pageSize": 10}' "$START_TS" "$END_TS")
test_command "Traffic Flows" "$BINARY local traffic flows --query '$FLOWS_QUERY' -o json"

# ============================================================================
# Local Controller - Statistics (v1 API)
# ============================================================================

echo ""
echo "════════════════════════════════════════════════════════════════════════════════════"
echo "LOCAL CONTROLLER - STATISTICS (v1 API)"
echo "════════════════════════════════════════════════════════════════════════════════════"

test_command "Stat Country Code" "$BINARY local stat ccode -o json"
test_command "Stat Current Channel" "$BINARY local stat current-channel -o json"
test_command "Stat Device Basic" "$BINARY local stat device-basic -o json"
test_command "Stat Guest" "$BINARY local stat guest -o json"
test_command "Stat Rogue AP" "$BINARY local stat rogueap -o json"
test_command "Stat SDN" "$BINARY local stat sdn -o json"
test_command "Stat Report 5min" "$BINARY local stat report5min -o json"

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
    test_command "Device Get" "$BINARY local device get $DEVICE_MAC -o json"
    test_command "Device Spectrum Scan" "$BINARY local device spectrum-scan $DEVICE_MAC -o json"
else
    echo "Skipping device-specific tests (no devices found)"
fi

test_command "Device Port Anomalies" "$BINARY local device port-anomalies -o json"
test_command "Device Mac Tables" "$BINARY local device mac-tables -o json" 1  # May return 404

# ============================================================================
# Local Controller - Network Management
# ============================================================================

echo ""
echo "════════════════════════════════════════════════════════════════════════════════════"
echo "LOCAL CONTROLLER - NETWORK MANAGEMENT"
echo "════════════════════════════════════════════════════════════════════════════════════"

test_command "Network List" "$BINARY local network list -o json"
test_command "WLAN List" "$BINARY local wlan list -o json"
test_command "Port Profile List" "$BINARY local port-profile list -o json"
test_command "Firewall Rule List" "$BINARY local firewall-rule list -o json"
test_command "Firewall Group List" "$BINARY local firewall-group list -o json"
test_command "Policy Table List" "$BINARY local policy-table list -o json"
test_command "Zone List" "$BINARY local zone list -o json"
test_command "Object List" "$BINARY local object list -o json"

# ============================================================================
# Local Controller - Events
# ============================================================================

echo ""
echo "════════════════════════════════════════════════════════════════════════════════════"
echo "LOCAL CONTROLLER - EVENTS"
echo "════════════════════════════════════════════════════════════════════════════════════"

test_command "Event List" "$BINARY local event list -o json"

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
    test_command "Correlate Client" "$BINARY local correlate client $CLIENT_MAC -o json"
    test_command "Correlate Client with Events" "$BINARY local correlate client $CLIENT_MAC --include-events -o json"
else
    echo "Skipping client correlation tests (no clients found)"
fi

if [ -n "$DEVICE_MAC" ]; then
    test_command "Correlate Device" "$BINARY local correlate device $DEVICE_MAC -o json"
    test_command "Correlate Device with Clients" "$BINARY local correlate device $DEVICE_MAC --include-clients -o json"
    test_command "Correlate AP" "$BINARY local correlate ap $DEVICE_MAC -o json"
else
    echo "Skipping device correlation tests (no devices found)"
fi

# Diagnostic Commands
test_command "Diagnose Network" "$BINARY local diagnose network -o json"
test_command "Diagnose WiFi" "$BINARY local diagnose wifi -o json"
test_command "Diagnose Client Overview" "$BINARY local diagnose client -o json"

if [ -n "$CLIENT_MAC" ]; then
    test_command "Diagnose Specific Client" "$BINARY local diagnose client $CLIENT_MAC -o json"
fi

# Time-Series Commands (use same timestamps from earlier in script)
test_command "Time-Series Traffic" "$BINARY local time-series traffic --start $START_TS --end $END_TS --format json -o json"
test_command "Time-Series WiFi" "$BINARY local time-series wifi --start $START_TS --end $END_TS --format json -o json"
test_command "Time-Series Events" "$BINARY local time-series events --limit 10 --format json -o json"

# LLM Output Format Tests (verify -o llm works with various commands)
test_command "Device List (LLM Format)" "$BINARY local device list --limit 5 -o llm"
test_command "Client List (LLM Format)" "$BINARY local client list --limit 5 -o llm"
test_command "Event List (LLM Format)" "$BINARY local event list --limit 5 -o llm"

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

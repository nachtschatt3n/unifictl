# unifictl examples

Quick command examples for both UniFi Site Manager (cloud, API key) and local UniFi controllers (username/password). Default output is a kubectl-style table; add `-o json` for raw JSON, `-o csv` for CSV export, or `-o raw` for the exact body.

## Cloud (Site Manager API v1/EA)

First, store your API key (user scope by default):
```bash
unifictl configure --key "<API_KEY>"
```

List hosts:
```bash
unifictl host list
unifictl host get <HOST_ID>         # fetch one host
```

Sites and devices:
```bash
unifictl site list                  # optional: --host-id <HOST_ID>
unifictl device list                # optional: --host-id <HOST_ID> --site-id <SITE_ID>
unifictl device get <DEVICE_ID>     # optional: --host-id <HOST_ID> --site-id <SITE_ID>
```

ISP metrics (EA):
```bash
unifictl isp get --type 5m --site-id <SITE_ID> --start <RFC3339> --end <RFC3339>
unifictl isp query --type hourly --body-file ./query.json
```

SD-WAN configs (EA):
```bash
unifictl sdwan list
unifictl sdwan get <CONFIG_ID>
unifictl sdwan status <CONFIG_ID>
```

Output formats:
```bash
unifictl host list -o json           # JSON output
unifictl device list -o csv          # CSV output (great for reporting)
unifictl device list -o raw          # Raw response body
unifictl device list                 # Pretty table (default)
```

Filtering and sorting:
```bash
unifictl device list --filter "SW"                    # Simple text filter (case-insensitive)
unifictl device list --filter-regex "^SW.*"           # Regex filter (case-insensitive)
unifictl device list --sort-by name                   # Sort by column
unifictl device list --columns name,ip,model          # Custom columns
unifictl host list --full-ids                         # Show complete IDs (no truncation)
```

Watch mode (live refresh):
```bash
unifictl local client list --watch 5                 # Refresh every 5 seconds
unifictl host list --watch 10                         # Refresh every 10 seconds
# Press Ctrl+C to stop watching
```

## Local controller (on-prem UniFi OS / controller)

Store local credentials (plaintext in chosen scope; use `--scope local` to keep it repo-local):
```bash
unifictl local configure \
  --url https://192.168.55.1:8443 \
  --username <USER> \
  --password '<PASS>' \
  --site default \
  --scope local \
  --verify-tls false
```

Inventory and health:
```bash
unifictl local site list
unifictl local device list
unifictl local device list --unadopted       # Show only pending/unadopted devices
unifictl local device adopt-all             # Adopt all unadopted devices at once
unifictl local device get <MAC> [--ports] [--config]  # device stats/config
unifictl local device restart <MAC>          # Restart device
unifictl local device adopt <MAC>            # Adopt device
unifictl local device upgrade <MAC>          # Upgrade device
unifictl local client list
unifictl local client list --wired           # filters: --wired / --wireless / --blocked
unifictl local client block <MAC>            # Block client
unifictl local client unblock <MAC>          # Unblock client
unifictl local client reconnect <MAC>        # Force reconnect (kick)
unifictl local client active                 # Get active clients (v2 API)
unifictl local client history                # Get client connection history
unifictl local client history --mac <MAC>    # Filter history by MAC address
unifictl local client update-metadata <MAC> --metadata '{"name": "My Device"}'
unifictl local event list
unifictl local health get
unifictl local vpn get                       # VPN health with packet-loss reasons
unifictl local security get
unifictl local wan get                       # WAN subset of health
unifictl local dpi get
unifictl local top-client list --limit 10
unifictl local top-device list --limit 5
```

System logs (v2 API):
```bash
unifictl local log settings                  # Get system log settings
unifictl local log all                       # Query all system logs
unifictl local log all --limit 100           # Limit results
unifictl local log all --limit 50 --offset 100  # Pagination
unifictl local log count                     # Count log entries
unifictl local log critical                  # Get critical logs
unifictl local log critical --limit 50       # Limit critical logs
unifictl local log device-alert              # Get device alert logs
unifictl local log device-alert --limit 20   # Limit device alerts
```

WiFi/Radio operations (v2 API):
```bash
unifictl local wifi connectivity             # Get WiFi connectivity statistics
# WiFi stats require time range (timestamps in milliseconds since epoch)
unifictl local wifi stats --start 1765049891027 --end 1765136291027
unifictl local wifi stats --start 1765049891027 --end 1765136291027 --ap-mac e4:38:83:67:db:ba
unifictl local wifi stats --start 1765049891027 --end 1765136291027 --ap-mac all
unifictl local wifi stats --radios --start 1765049891027 --end 1765136291027
unifictl local wifi radio-ai                # Get Radio AI isolation matrix
unifictl local wifi management              # Get WiFi management data
unifictl local wifi config                  # Get enhanced WLAN configuration
```

Traffic/Flow operations (v2 API):
```bash
# Traffic stats require time range and includeUnidentified flag
unifictl local traffic stats --start 1765049891027 --end 1765136291027 --include-unidentified true
unifictl local traffic stats --start 1765049891027 --end 1765136291027 --include-unidentified false

# Traffic flow latest statistics require period (DAY or MONTH) and top count
unifictl local traffic flow-latest --period day --top 30
unifictl local traffic flow-latest --period month --top 50

# Application traffic rate requires time range and includeUnidentified flag
unifictl local traffic app-rate --start 1765049891027 --end 1765136291027 --include-unidentified true

# Other traffic commands (no required parameters)
unifictl local traffic filter-data           # Get traffic flow filter metadata
unifictl local traffic routes                # Get traffic routing rules
unifictl local traffic rules                 # Get traffic rules
unifictl local traffic flows --query '{"timestampFrom": 1765049891025, "timestampTo": 1765136291025}'
```

Configs and security:
```bash
unifictl local network list            # VLANs/subnets/DHCP
unifictl local network create --name corp --vlan 20 --subnet 192.168.20.0/24 --dhcp
unifictl local network update <NETWORK_ID> --name corp-renamed
unifictl local network delete <NETWORK_ID> --dry-run    # Preview what would be deleted
unifictl local network delete <NETWORK_ID>              # Prompts for confirmation
unifictl local network delete <NETWORK_ID> --yes        # Skip confirmation prompt

unifictl local wlan list               # SSIDs/security
unifictl local wlan create --name "Guest" --password "changeme"
unifictl local wlan update <WLAN_ID> --enabled false
unifictl local wlan delete <WLAN_ID> --dry-run     # Preview deletion
unifictl local wlan delete <WLAN_ID> --yes         # Skip confirmation

unifictl local port-profile list
unifictl local firewall-rule list
unifictl local firewall-rule create --name "Block WAN" --action drop --dst-group <GROUP_ID>
unifictl local firewall-rule update <RULE_ID> --action accept
unifictl local firewall-rule delete <RULE_ID> --dry-run    # Preview deletion
unifictl local firewall-rule delete <RULE_ID> --yes        # Skip confirmation

unifictl local firewall-group list
unifictl local firewall-group create --name "BlockedIPs" --members 1.1.1.1,2.2.2.2
unifictl local firewall-group update <GROUP_ID> --members 3.3.3.3
unifictl local firewall-group delete <GROUP_ID> --dry-run   # Preview deletion
unifictl local firewall-group delete <GROUP_ID> --yes      # Skip confirmation

unifictl local policy-table list
unifictl local policy-table create --name "WAN-Failover" --description "Failover policy"
unifictl local policy-table update <POLICY_TABLE_ID> --name "WAN-Failover-Updated"
unifictl local policy-table delete <POLICY_TABLE_ID> --dry-run    # Preview deletion
unifictl local policy-table delete <POLICY_TABLE_ID> --yes        # Skip confirmation

unifictl local zone list
unifictl local zone create --name "DMZ" --description "DMZ zone"
unifictl local zone update <ZONE_ID> --name "DMZ-Updated"
unifictl local zone delete <ZONE_ID> --dry-run             # Preview deletion
unifictl local zone delete <ZONE_ID> --yes                # Skip confirmation

unifictl local object list
unifictl local object create --name "WebServer" --object-type address --value 192.168.1.10
unifictl local object update <OBJECT_ID> --value 192.168.1.11
unifictl local object delete <OBJECT_ID> --dry-run          # Preview deletion
unifictl local object delete <OBJECT_ID> --yes              # Skip confirmation
```

Safety features:
```bash
# Dry-run mode: preview deletions without actually deleting
unifictl local network delete <NETWORK_ID> --dry-run
unifictl local wlan delete <WLAN_ID> --dry-run
unifictl local firewall-rule delete <RULE_ID> --dry-run
unifictl local firewall-group delete <GROUP_ID> --dry-run
unifictl local policy-table delete <POLICY_TABLE_ID> --dry-run
unifictl local zone delete <ZONE_ID> --dry-run
unifictl local object delete <OBJECT_ID> --dry-run

# Interactive confirmations (default for delete operations)
unifictl local network delete <NETWORK_ID>              # Prompts: "Are you sure? [y/N]"
unifictl local network delete <NETWORK_ID> --yes         # Skip confirmation (useful for scripts)
```

Export and reporting:
```bash
# JSON output for deeper inspection
unifictl local network list -o json
unifictl local wlan list -o json
unifictl local firewall-rule list -o json
unifictl local firewall-group list -o json
unifictl local policy-table list -o json
unifictl local zone list -o json
unifictl local object list -o json

# CSV output for spreadsheets/reporting
unifictl local client list -o csv > clients.csv
unifictl local device list -o csv > devices.csv
unifictl local top-client list --limit 100 -o csv > top-clients.csv

# Combine with filtering
unifictl local device list --filter-regex "^SW" -o csv > switches.csv
unifictl local client list --wired -o csv > wired-clients.csv
```

Device management workflows:
```bash
# Find unadopted devices
unifictl local device list --unadopted

# Adopt all unadopted devices at once
unifictl local device adopt-all

# Adopt a specific device
unifictl local device adopt <MAC>

# Restart or upgrade devices
unifictl local device restart <MAC>
unifictl local device upgrade <MAC>

# Get device details
unifictl local device get <MAC> [--ports] [--config]

# Filter devices by name pattern
unifictl local device list --filter-regex "^SW"              # Devices starting with "SW"
unifictl local device list --filter-regex ".*AP.*"           # Devices containing "AP"
unifictl local device list --unadopted --filter "pending"    # Combine filters
```

Error handling and troubleshooting:
```bash
# Validate credentials before use
unifictl validate                              # Test both cloud and local
unifictl validate --cloud-only                 # Test only cloud API
unifictl validate --local-only                # Test only local controller

# View configuration (secrets masked)
unifictl config-show

# Better error messages now include:
# - Specific error codes and causes
# - Troubleshooting suggestions
# - Recommended next steps
```

Advanced usage examples:
```bash
# Export all networks to CSV for backup
unifictl local network list -o csv > networks-backup.csv

# Find all switches and export to CSV
unifictl local device list --filter-regex "SW|Switch" -o csv > switches.csv

# Watch clients with custom columns
unifictl local client list --watch 5 --columns hostname,mac,ip,essid

# Sort and filter top clients
unifictl local top-client list --limit 20 -o csv > top-clients.csv

# Export active clients (v2 API) to CSV
unifictl local client active -o csv > active-clients.csv

# Export client history to JSON for analysis
unifictl local client history -o json > client-history.json

# Monitor critical system logs
unifictl local log critical --watch 10

# Export WiFi statistics to CSV (requires time range)
unifictl local wifi stats --start 1765049891027 --end 1765136291027 -o csv > wifi-stats.csv

# Get radio statistics in JSON format (requires time range)
unifictl local wifi stats --radios --start 1765049891027 --end 1765136291027 -o json > radio-stats.json

# Export traffic statistics to CSV (requires time range)
unifictl local traffic stats --start 1765049891027 --end 1765136291027 --include-unidentified true -o csv > traffic-stats.csv

# Get traffic flow latest statistics (requires period and top)
unifictl local traffic flow-latest --period day --top 30 -o json > flow-latest.json

# Dry-run before bulk deletion (example workflow)
unifictl local network list -o json | jq -r '.data[] | select(.name | contains("old")) | ._id' | \
  while read network_id; do
    unifictl local network delete "$network_id" --dry-run
  done
```

# unifictl examples

Quick command examples for both UniFi Site Manager (cloud, API key) and local UniFi controllers (username/password). Default output is a kubectl-style table; add `-o json` for raw JSON, `-o csv` for CSV export, or `-o raw` for the exact body.

## Cloud (Site Manager API v1/EA)

First, store your API key (user scope by default):
```bash
unifictl configure --key "<API_KEY>"
```

List hosts:
```bash
unifictl hosts list
unifictl hosts get <HOST_ID>         # fetch one host
```

Sites and devices:
```bash
unifictl sites list                  # optional: --host-id <HOST_ID>
unifictl devices list                # optional: --host-id <HOST_ID> --site-id <SITE_ID>
unifictl devices get <DEVICE_ID>     # optional: --host-id <HOST_ID> --site-id <SITE_ID>
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
unifictl hosts list -o json           # JSON output
unifictl devices list -o csv          # CSV output (great for reporting)
unifictl devices list -o raw          # Raw response body
unifictl devices list                 # Pretty table (default)
```

Filtering and sorting:
```bash
unifictl devices list --filter "SW"                    # Simple text filter (case-insensitive)
unifictl devices list --filter-regex "^SW.*"           # Regex filter (case-insensitive)
unifictl devices list --sort-by name                   # Sort by column
unifictl devices list --columns name,ip,model          # Custom columns
unifictl hosts list --full-ids                         # Show complete IDs (no truncation)
```

Watch mode (live refresh):
```bash
unifictl local clients --watch 5                       # Refresh every 5 seconds
unifictl hosts list --watch 10                         # Refresh every 10 seconds
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
unifictl local sites
unifictl local devices
unifictl local devices --unadopted       # Show only pending/unadopted devices
unifictl local devices --adopt-all     # Adopt all unadopted devices at once
unifictl local device <MAC> --ports      # device stats/config; add --restart/--adopt/--upgrade to act
unifictl local clients
unifictl local clients --wired           # filters: --wired / --wireless / --blocked
unifictl local client --block <MAC>      # use --unblock or --reconnect as needed
unifictl local health
unifictl local wan                 # WAN subset of health
unifictl local events
```

Configs and security:
```bash
unifictl local networks            # VLANs/subnets/DHCP
unifictl local network create --name corp --vlan 20 --subnet 192.168.20.0/24 --dhcp
unifictl local network update <ID> --name corp-renamed
unifictl local network delete <ID> --dry-run    # Preview what would be deleted
unifictl local network delete <ID>              # Prompts for confirmation
unifictl local network delete <ID> --yes        # Skip confirmation prompt

unifictl local wlans               # SSIDs/security
unifictl local wlan create --name "Guest" --password "changeme"
unifictl local wlan update <ID> --enabled false
unifictl local wlan delete <ID> --dry-run     # Preview deletion
unifictl local wlan delete <ID> --yes         # Skip confirmation

unifictl local port-profiles
unifictl local firewall-rules
unifictl local firewall-rule-create --name "Block WAN" --action drop --dst-group <ID>
unifictl local firewall-rule-update <ID> --action accept
unifictl local firewall-rule-delete <ID> --dry-run    # Preview deletion
unifictl local firewall-rule-delete <ID> --yes        # Skip confirmation

unifictl local firewall-groups
unifictl local firewall-group-create --name "BlockedIPs" --members 1.1.1.1,2.2.2.2
unifictl local firewall-group-update <ID> --members 3.3.3.3
unifictl local firewall-group-delete <ID> --dry-run   # Preview deletion
unifictl local firewall-group-delete <ID> --yes      # Skip confirmation

unifictl local policy-tables
unifictl local policy-table-create --name "WAN-Failover" --description "Failover policy"
unifictl local policy-table-update <ID> --name "WAN-Failover-Updated"
unifictl local policy-table-delete <ID> --dry-run    # Preview deletion
unifictl local policy-table-delete <ID> --yes        # Skip confirmation

unifictl local zones
unifictl local zone-create --name "DMZ" --description "DMZ zone"
unifictl local zone-update <ID> --name "DMZ-Updated"
unifictl local zone-delete <ID> --dry-run             # Preview deletion
unifictl local zone-delete <ID> --yes                # Skip confirmation

unifictl local objects
unifictl local object-create --name "WebServer" --type address --value 192.168.1.10
unifictl local object-update <ID> --value 192.168.1.11
unifictl local object-delete <ID> --dry-run          # Preview deletion
unifictl local object-delete <ID> --yes              # Skip confirmation

unifictl local security            # controller security settings (JSON-heavy; use -o json)
unifictl local dpi                 # DPI summary
unifictl local traffic             # traffic stats
unifictl local top-clients --limit 10
unifictl local top-devices --limit 5
```

Safety features:
```bash
# Dry-run mode: preview deletions without actually deleting
unifictl local network delete <ID> --dry-run
unifictl local wlan delete <ID> --dry-run
unifictl local firewall-rule delete <ID> --dry-run
unifictl local firewall-group delete <ID> --dry-run
unifictl local policy-table delete <ID> --dry-run
unifictl local zone delete <ID> --dry-run
unifictl local object delete <ID> --dry-run

# Interactive confirmations (default for delete operations)
unifictl local network delete <ID>              # Prompts: "Are you sure? [y/N]"
unifictl local network delete <ID> --yes        # Skip confirmation (useful for scripts)
```

Export and reporting:
```bash
# JSON output for deeper inspection
unifictl local networks -o json
unifictl local wlans -o json
unifictl local firewall-rules -o json
unifictl local firewall-groups -o json
unifictl local policy-tables -o json
unifictl local zones -o json
unifictl local objects -o json

# CSV output for spreadsheets/reporting
unifictl local clients -o csv > clients.csv
unifictl local devices -o csv > devices.csv
unifictl local top-clients --limit 100 -o csv > top-clients.csv

# Combine with filtering
unifictl local devices --filter-regex "^SW" -o csv > switches.csv
unifictl local clients --wired -o csv > wired-clients.csv
```

Device management workflows:
```bash
# Find unadopted devices
unifictl local devices --unadopted

# Adopt all unadopted devices at once
unifictl local devices --adopt-all

# Adopt a specific device
unifictl local device <MAC> --adopt

# Restart or upgrade devices
unifictl local device <MAC> --restart
unifictl local device <MAC> --upgrade

# Filter devices by name pattern
unifictl local devices --filter-regex "^SW"              # Devices starting with "SW"
unifictl local devices --filter-regex ".*AP.*"           # Devices containing "AP"
unifictl local devices --unadopted --filter "pending"    # Combine filters
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
unifictl local networks -o csv > networks-backup.csv

# Find all switches and export to CSV
unifictl local devices --filter-regex "SW|Switch" -o csv > switches.csv

# Watch clients with custom columns
unifictl local clients --watch 5 --columns hostname,mac,ip,essid

# Sort and filter top clients
unifictl local top-clients --limit 20 --sort-by tx_bytes -o csv > top-clients.csv

# Dry-run before bulk deletion (example workflow)
unifictl local networks -o json | jq -r '.[] | select(.name | contains("old")) | ._id' | \
  while read id; do
    unifictl local network delete "$id" --dry-run
  done
```

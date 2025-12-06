# unifictl examples

Quick command examples for both UniFi Site Manager (cloud, API key) and local UniFi controllers (username/password). Default output is a kubectl-style table; add `-o json` for raw JSON, or `-o raw` for the exact body.

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

JSON/raw output:
```bash
unifictl hosts list -o json
unifictl devices list -o raw
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
unifictl local network delete <ID>

unifictl local wlans               # SSIDs/security
unifictl local wlan create --name "Guest" --password "changeme"
unifictl local wlan update <ID> --enabled false
unifictl local wlan delete <ID>

unifictl local port-profiles
unifictl local firewall-rules
unifictl local firewall-rule create --name "Block WAN" --action drop --dst-group <ID>
unifictl local firewall-rule update <ID> --action accept
unifictl local firewall-rule delete <ID>

unifictl local firewall-groups
unifictl local firewall-group create --name "BlockedIPs" --members 1.1.1.1,2.2.2.2
unifictl local firewall-group update <ID> --members 3.3.3.3
unifictl local firewall-group delete <ID>

unifictl local security            # controller security settings (JSON-heavy; use -o json)
unifictl local dpi                 # DPI summary
unifictl local traffic             # traffic stats
unifictl local top-clients --limit 10
unifictl local top-devices --limit 5
```

JSON output for deeper inspection:
```bash
unifictl local networks -o json
unifictl local wlans -o json
unifictl local firewall-rules -o json
```

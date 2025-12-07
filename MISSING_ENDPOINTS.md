# Missing Endpoints Analysis

This document lists API endpoints found in HAR files that are not yet implemented in `unifictl`.

## Summary

- **Total unique endpoints in HAR files**: 96
- **Currently implemented**: ~47
- **Missing**: ~49 unique endpoints

## Missing Endpoints by Category

### Clients (4 endpoints)
- `GET /proxy/network/v2/api/site/{site}/clients/active` - List active clients
- `GET /proxy/network/v2/api/site/{site}/clients/history` - Client connection history
- `GET /proxy/network/v2/api/site/{site}/hotspot/clients` - Hotspot client list
- `POST /proxy/network/v2/api/site/{site}/clients/metadata` - Update client metadata

### WiFi/Radio (6 endpoints)
- `GET /proxy/network/v2/api/site/{site}/radio-ai/isolation-matrix` - Radio AI isolation matrix
- `GET /proxy/network/v2/api/site/{site}/wifi-connectivity` - WiFi connectivity stats
- `GET /proxy/network/v2/api/site/{site}/wifi-stats/details` - Detailed WiFi statistics
- `GET /proxy/network/v2/api/site/{site}/wifi-stats/radios` - Radio statistics
- `GET /proxy/network/v2/api/site/{site}/wifiman` - WiFi management data
- `GET /proxy/network/v2/api/site/{site}/wlan/enriched-configuration` - Enhanced WLAN config

### Traffic/Flow (7 endpoints)
- `GET /proxy/network/v2/api/site/{site}/traffic` - Traffic statistics
- `GET /proxy/network/v2/api/site/{site}/traffic-flow-latest-statistics` - Latest flow stats
- `GET /proxy/network/v2/api/site/{site}/traffic-flows/filter-data` - Flow filter metadata
- `GET /proxy/network/v2/api/site/{site}/trafficroutes` - Traffic routing rules
- `GET /proxy/network/v2/api/site/{site}/trafficrules` - Traffic rules
- `POST /proxy/network/v2/api/site/{site}/app-traffic-rate` - Application traffic rate query
- `POST /proxy/network/v2/api/site/{site}/traffic-flows` - Query traffic flows

### System Log (5 endpoints)
- `GET /proxy/network/v2/api/site/{site}/system-log/setting` - System log settings
- `POST /proxy/network/v2/api/site/{site}/system-log/all` - Query all system logs
- `POST /proxy/network/v2/api/site/{site}/system-log/count` - Count system log entries
- `POST /proxy/network/v2/api/site/{site}/system-log/critical` - Critical system logs
- `POST /proxy/network/v2/api/site/{site}/system-log/device-alert` - Device alert logs

### AP/AP Groups (16 endpoints)
- `GET /proxy/network/v2/api/site/{site}/active-leases` - Active DHCP leases
- `GET /proxy/network/v2/api/site/{site}/aggregated-dashboard` - Dashboard aggregated data
- `GET /proxy/network/v2/api/site/{site}/ap/{mac}/neighbors` - AP neighbor information
- `GET /proxy/network/v2/api/site/{site}/apgroups` - AP groups
- `GET /proxy/network/v2/api/site/{site}/described-features` - Feature descriptions
- `GET /proxy/network/v2/api/site/{site}/excluded-ips/` - Excluded IP addresses
- `GET /proxy/network/v2/api/site/{site}/features/AFC_CAPABLE_AP_ADOPTED/exists` - Check AFC feature
- `GET /proxy/network/v2/api/site/{site}/features/LTE_BACKUP_ADOPTED/exists` - Check LTE feature
- `GET /proxy/network/v2/api/site/{site}/features/MISSION_CRITICAL_ADOPTED/exists` - Check Mission Critical feature
- `GET /proxy/network/v2/api/site/{site}/features/MOBILE_BROADBAND_ADOPTED/exists` - Check Mobile Broadband feature
- `GET /proxy/network/v2/api/site/{site}/global/config/network` - Global network config
- `GET /proxy/network/v2/api/site/{site}/mclag-groups` - MCLAG groups
- `GET /proxy/network/v2/api/site/{site}/models` - Device models
- `GET /proxy/network/v2/api/site/{site}/network-members-groups` - Network member groups
- `GET /proxy/network/v2/api/site/{site}/stacking` - Stacking configuration
- `GET /proxy/network/v2/api/site/{site}/vendor-ids` - Vendor IDs

### Ports (2 endpoints)
- `GET /proxy/network/v2/api/site/{site}/ports/port-anomalies` - Port anomalies
- `POST /proxy/network/v2/api/site/{site}/ports/mac-tables` - MAC address tables

### Hotspot (1 endpoint)
- `GET /proxy/network/v2/api/site/{site}/hotspot/info` - Hotspot information

### Firewall (2 endpoints)
- `GET /proxy/network/v2/api/site/{site}/acl-rules` - ACL rules (v2 API)
- `GET /proxy/network/v2/api/site/{site}/firewall-policies` - Firewall policies

### Routing (3 endpoints)
- `GET /proxy/network/v2/api/site/{site}/bgp/config/all` - BGP configuration
- `GET /proxy/network/v2/api/site/{site}/nat` - NAT configuration
- `GET /proxy/network/v2/api/site/{site}/ospf/router` - OSPF router configuration

### WAN/LAN (3 endpoints)
- `GET /proxy/network/v2/api/site/{site}/lan/enriched-configuration` - Enhanced LAN config
- `GET /proxy/network/v2/api/site/{site}/wan-slas` - WAN SLA configuration
- `GET /proxy/network/v2/api/site/{site}/wan/enriched-configuration` - Enhanced WAN config

### DNS (2 endpoints)
- `GET /proxy/network/v2/api/site/{site}/static-dns` - Static DNS entries
- `GET /proxy/network/v2/api/site/{site}/static-dns/devices` - Static DNS device mappings

### QoS (1 endpoint)
- `GET /proxy/network/v2/api/site/{site}/qos-rules` - QoS rules

### Statistics (v1) (8 endpoints)
- `GET /proxy/network/api/s/{site}/stat/ccode` - Country code statistics
- `GET /proxy/network/api/s/{site}/stat/current-channel` - Current channel statistics
- `GET /proxy/network/api/s/{site}/stat/device-basic` - Basic device statistics
- `GET /proxy/network/api/s/{site}/stat/guest` - Guest statistics
- `GET /proxy/network/api/s/{site}/stat/rogueap` - Rogue AP detection
- `GET /proxy/network/api/s/{site}/stat/sdn` - SDN statistics
- `GET /proxy/network/api/s/{site}/stat/spectrum-scan/{mac}` - Spectrum scan results
- `POST /proxy/network/api/s/{site}/stat/report/5minutes.ap` - 5-minute AP report

### REST API (v1) (3 endpoints)
- `GET /proxy/network/api/s/{site}/rest/portforward` - Port forwarding rules
- `GET /proxy/network/api/s/{site}/rest/radiusprofile` - RADIUS profiles
- `GET /proxy/network/api/s/{site}/rest/usergroup` - User groups

### Cloud API (9 endpoints)
Note: Some of these may be authentication/admin endpoints not needed for CLI tool
- `GET /api/v1/admins` - List administrators
- `GET /api/v1/hosts` - List hosts (already implemented, but specific host IDs may differ)
- `GET /api/v1/hosts/{id}` - Get specific host (already implemented)
- `GET /api/v1/info/subscriptions` - Subscription information
- `GET /api/v1/organizations` - Organizations
- `GET /api/v1/site-managers/devices` - Site manager devices (already implemented)
- `GET /api/v1/sites` - Sites (already implemented)
- `GET /api/v2/subscriptions/devices` - Subscription devices

### Other (13 endpoints)
These are mostly authentication, system, or internal endpoints:
- `GET /api/auth/validate-sso/{token}` - SSO validation
- `GET /api/cloud/backup/settings/list` - Backup settings
- `GET /api/firmware/update` - Firmware update info
- `GET /api/sso/v1/user/self` - SSO user info
- `GET /api/users/self` - Current user info
- `GET /proxy/network/api/stat/s/{site}/hotspotconfig` - Hotspot config (v1)
- `GET /proxy/network/v2/api/fingerprint_devices/{num}` - Fingerprint devices
- `GET /proxy/network/v2/api/info` - System info
- `POST /api/{num}/envelope/` - Analytics endpoint
- `POST /api/auth/nca` - NCA authentication
- `POST /api/controllers/checkUpdates` - Check for updates
- `PUT /proxy/network/api/self` - Update self/user settings
- `GET /proxy/network/api/s/{site}/get/setting` - Get settings

## Notes

1. **Cloud API endpoints**: Some endpoints like `/api/v1/hosts` are already implemented, but the HAR files show specific host IDs. The implementation supports these via the `host get` command.

2. **Authentication endpoints**: Many endpoints in the "Other" category are for authentication, SSO, or internal system operations that may not be needed for a CLI tool.

3. **v2 API**: Most missing endpoints are from the v2 API (`/proxy/network/v2/api/site/{site}/...`), which suggests the codebase primarily uses v1 API endpoints.

4. **Statistics endpoints**: Several v1 statistics endpoints are missing (`stat/ccode`, `stat/current-channel`, `stat/device-basic`, `stat/guest`, `stat/rogueap`, `stat/sdn`, `stat/spectrum-scan`).

5. **REST API v1**: Some REST endpoints are missing (`rest/portforward`, `rest/radiusprofile`, `rest/usergroup`).

## Recommendations

Priority endpoints to implement:
1. **Clients**: `clients/active`, `clients/history` - High value for monitoring
2. **System Log**: All system-log endpoints - Important for troubleshooting
3. **Traffic/Flow**: Traffic statistics and flow analysis - Useful for network monitoring
4. **WiFi/Radio**: WiFi statistics and radio information - Important for wireless management
5. **Statistics (v1)**: Additional stat endpoints like `stat/rogueap`, `stat/spectrum-scan` - Security and diagnostics

Lower priority:
- Authentication/admin endpoints (unless needed for specific use cases)
- Feature detection endpoints (`features/*/exists`)
- Internal system endpoints

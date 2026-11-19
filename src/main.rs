// unifictl - CLI for UniFi Site Manager API
// Copyright (C) 2024 Mathias Uhl <mathiasuhl@gmx.de>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

mod client;
mod config;
mod local;
mod output;
mod schema;
mod session;

use crate::client::{ApiClient, ResponseData};
use crate::config::{LocalConfig, Scope, resolve, resolve_local, save};
use crate::local::{LocalClient, list_payload_mut, mac_matches};
use crate::output::{capture_collection, finish_collection, spreadsheet_safe, terminal_safe};
use crate::schema::{SchemaRegistry, estimate_tokens, summarize_response};
use anyhow::{Context, Result, anyhow};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use regex::RegexBuilder;
use serde_json::json;
use std::sync::OnceLock;
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};

static FULL_IDS: OnceLock<bool> = OnceLock::new();

#[derive(Parser)]
#[command(
    name = "unifictl",
    version,
    about = "CLI for the UniFi Site Manager API"
)]
struct Cli {
    #[arg(
        long,
        global = true,
        help = "API key override for this invocation (otherwise read from config)"
    )]
    api_key: Option<String>,

    #[arg(
        long,
        global = true,
        value_name = "URL",
        help = "Base URL for the API (defaults to https://api.ui.com)"
    )]
    base_url: Option<String>,

    #[arg(
        long,
        short = 'o',
        value_enum,
        default_value_t = OutputFormat::Pretty,
        global = true,
        help = "Output format (propagates to subcommands)"
    )]
    output: OutputFormat,

    #[arg(long, global = true, help = "Do not truncate long IDs in table output")]
    full_ids: bool,

    #[arg(
        long,
        value_name = "COL1,COL2",
        global = true,
        help = "Override table columns (comma-separated)"
    )]
    columns: Option<String>,

    #[arg(
        long,
        value_name = "COLUMN",
        global = true,
        help = "Sort table rows by column (ascending)"
    )]
    sort_by: Option<String>,

    #[arg(
        long,
        value_name = "TEXT",
        global = true,
        help = "Filter rows containing TEXT (case-insensitive)"
    )]
    filter: Option<String>,

    #[arg(
        long,
        value_name = "PATTERN",
        global = true,
        help = "Filter rows matching regex PATTERN (case-insensitive)"
    )]
    filter_regex: Option<String>,

    #[arg(
        long,
        value_name = "SECONDS",
        global = true,
        value_parser = clap::value_parser!(u64).range(1..),
        help = "Watch mode: refresh after at least SECONDS (positive; exits on error)"
    )]
    watch: Option<u64>,

    #[arg(
        long,
        global = true,
        help = "Do not reuse or persist the cached local-controller session (re-auth every command)"
    )]
    no_session_cache: bool,

    #[arg(
        long,
        global = true,
        help = "Ignore configuration from the current working directory"
    )]
    no_project_config: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Set credentials for the cloud API and/or a local controller
    #[command(args_conflicts_with_subcommands = true)]
    Login {
        #[command(subcommand)]
        command: Option<LoginCommand>,
        #[command(flatten)]
        args: LoginSetArgs,
    },
    /// Cloud (Site Manager API) operations
    Cloud {
        #[command(subcommand)]
        command: CloudCommands,
    },
    /// Operate against a local UniFi controller using username/password
    Local {
        #[arg(long, global = true)]
        site: Option<String>,
        #[command(subcommand)]
        command: LocalCommands,
    },
    /// Generate shell completion scripts
    Completion {
        #[arg(value_enum)]
        shell: CompletionShell,
    },
}

#[derive(Subcommand)]
enum CloudCommands {
    /// Host-related operations
    #[command(subcommand)]
    Host(HostCommand),
    /// Site-related operations
    #[command(subcommand)]
    Site(SiteCommand),
    /// Device operations
    #[command(subcommand)]
    Device(DeviceCommand),
    /// ISP metrics (EA) helpers
    #[command(subcommand)]
    Isp(IspCommand),
    /// SD-WAN configuration helpers (EA)
    #[command(subcommand)]
    Sdwan(SdwanCommand),
}

#[derive(Args)]
struct LoginSetArgs {
    #[arg(long, value_name = "KEY", help = "Cloud API key (api.ui.com)")]
    api_key: Option<String>,
    #[arg(
        long,
        value_name = "URL",
        help = "Local controller base URL (e.g. https://192.168.1.1)"
    )]
    controller_url: Option<String>,
    #[arg(long, value_name = "USER", help = "Local controller username")]
    username: Option<String>,
    #[arg(long, value_name = "PASS", help = "Local controller password")]
    password: Option<String>,
    #[arg(
        long,
        value_name = "SITE",
        default_value = "default",
        help = "Local controller site name"
    )]
    site: String,
    #[arg(
        long,
        default_value_t = false,
        help = "Enable TLS certificate verification for the local controller"
    )]
    verify_tls: bool,
    #[arg(
        long,
        conflicts_with = "verify_tls",
        help = "Explicitly disable controller TLS verification (unsafe)"
    )]
    insecure: bool,
    #[arg(
        long,
        value_name = "PEM",
        help = "Additional trusted controller CA certificate"
    )]
    ca_file: Option<PathBuf>,
    #[arg(
        long,
        help = "Opt in to retrying login on :443 when a :8443 controller is unreachable"
    )]
    port_fallback: bool,
    #[arg(
        long,
        conflicts_with = "port_fallback",
        help = "Disable the :8443 -> :443 login fallback (default)"
    )]
    no_port_fallback: bool,
    #[arg(
        long,
        value_enum,
        default_value_t = ScopeArg::User,
        help = "Where to write the config (local project dir or user config dir)"
    )]
    scope: ScopeArg,
}

#[derive(Subcommand)]
enum LoginCommand {
    /// Validate stored credentials (cloud/local)
    Validate {
        #[arg(long, help = "Validate only cloud (Site Manager) credentials")]
        cloud_only: bool,
        #[arg(long, help = "Validate only local controller credentials")]
        local_only: bool,
    },
    /// Show current configuration (secrets masked)
    Show,
}

#[derive(Subcommand)]
enum HostCommand {
    /// List all hosts
    List,
    /// Fetch a host by ID
    Get {
        #[arg(value_name = "HOST_ID")]
        id: String,
    },
}

#[derive(Subcommand)]
enum SiteCommand {
    /// List sites (optionally filtered by host ID)
    List {
        #[arg(long)]
        host_id: Option<String>,
    },
}

#[derive(Subcommand)]
enum DeviceCommand {
    /// List devices (optionally filtered by host/site)
    List {
        #[arg(long)]
        host_id: Option<String>,
        #[arg(long)]
        site_id: Option<String>,
    },
    /// Get a device by ID
    Get {
        #[arg(value_name = "DEVICE_ID")]
        id: String,
        #[arg(long)]
        host_id: Option<String>,
        #[arg(long)]
        site_id: Option<String>,
    },
}

#[derive(Subcommand)]
enum IspCommand {
    /// GET /ea/isp-metrics/:type
    Get {
        #[arg(long = "type", value_name = "TYPE")]
        metric_type: String,
        #[arg(long)]
        host_id: Option<String>,
        #[arg(long)]
        site_id: Option<String>,
        #[arg(long, value_name = "RFC3339")]
        start: Option<String>,
        #[arg(long, value_name = "RFC3339")]
        end: Option<String>,
    },
    /// POST /ea/isp-metrics/:type/query with a custom JSON body
    Query {
        #[arg(long = "type", value_name = "TYPE")]
        metric_type: String,
        #[arg(long, value_name = "JSON", help = "Inline JSON body")]
        body: Option<String>,
        #[arg(long, value_name = "FILE", help = "Path to JSON body")]
        body_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum SdwanCommand {
    /// List SD-WAN configs
    List,
    /// Fetch an SD-WAN config by ID
    Get {
        #[arg(value_name = "CONFIG_ID")]
        id: String,
    },
    /// Fetch SD-WAN config status by ID
    Status {
        #[arg(value_name = "CONFIG_ID")]
        id: String,
    },
}

#[derive(Subcommand)]
enum NetworkCommand {
    /// List networks (VLANs)
    List,
    /// Create a network
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        vlan: Option<u16>,
        #[arg(long, value_name = "CIDR")]
        subnet: Option<String>,
        #[arg(long, default_value_t = false)]
        dhcp: bool,
    },
    /// Update a network by ID
    Update {
        #[arg(value_name = "NETWORK_ID")]
        id: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        vlan: Option<u16>,
        #[arg(long, value_name = "CIDR")]
        subnet: Option<String>,
        #[arg(long)]
        dhcp: Option<bool>,
    },
    /// Delete a network by ID
    Delete {
        #[arg(value_name = "NETWORK_ID")]
        id: String,
        #[arg(long, help = "Show what would be deleted without actually deleting")]
        dry_run: bool,
        #[arg(long, help = "Skip confirmation prompt")]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum WlanCommand {
    /// List WLANs (SSIDs)
    List,
    /// Create a WLAN
    Create {
        #[arg(long)]
        name: String,
        #[arg(long, required_unless_present = "open", conflicts_with = "open")]
        password: Option<String>,
        #[arg(long, help = "Explicitly create an unsecured open WLAN")]
        open: bool,
        #[arg(long, default_value_t = true)]
        enabled: bool,
    },
    /// Update a WLAN by ID
    Update {
        #[arg(value_name = "WLAN_ID")]
        id: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        enabled: Option<bool>,
    },
    /// Delete a WLAN by ID
    Delete {
        #[arg(value_name = "WLAN_ID")]
        id: String,
        #[arg(long, help = "Show what would be deleted without actually deleting")]
        dry_run: bool,
        #[arg(long, help = "Skip confirmation prompt")]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum FirewallRuleCommand {
    /// List firewall rules
    List,
    /// Create a firewall rule
    Create {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "accept")]
        action: String,
        #[arg(long, value_name = "SRC_GROUP")]
        src_group: Option<String>,
        #[arg(long, value_name = "DST_GROUP")]
        dst_group: Option<String>,
    },
    /// Update a firewall rule by ID
    Update {
        #[arg(value_name = "RULE_ID")]
        id: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        action: Option<String>,
        #[arg(long, value_name = "SRC_GROUP")]
        src_group: Option<String>,
        #[arg(long, value_name = "DST_GROUP")]
        dst_group: Option<String>,
    },
    /// Delete a firewall rule by ID
    Delete {
        #[arg(value_name = "RULE_ID")]
        id: String,
        #[arg(long, help = "Show what would be deleted without actually deleting")]
        dry_run: bool,
        #[arg(long, help = "Skip confirmation prompt")]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum FirewallGroupCommand {
    /// List firewall groups
    List,
    /// Create a firewall group
    Create {
        #[arg(long)]
        name: String,
        #[arg(long, value_name = "TYPE", default_value = "address-group")]
        group_type: String,
        #[arg(
            long,
            value_name = "MEMBERS",
            use_value_delimiter = true,
            value_delimiter = ','
        )]
        members: Option<Vec<String>>,
    },
    /// Update a firewall group by ID
    Update {
        #[arg(value_name = "GROUP_ID")]
        id: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(
            long,
            value_name = "MEMBERS",
            use_value_delimiter = true,
            value_delimiter = ','
        )]
        members: Option<Vec<String>>,
    },
    /// Delete a firewall group by ID
    Delete {
        #[arg(value_name = "GROUP_ID")]
        id: String,
        #[arg(long, help = "Show what would be deleted without actually deleting")]
        dry_run: bool,
        #[arg(long, help = "Skip confirmation prompt")]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum PolicyTableCommand {
    /// List policy tables (routing policies)
    List,
    /// Create a policy table
    Create {
        #[arg(long)]
        name: String,
        #[arg(long, value_name = "DESCRIPTION")]
        description: Option<String>,
    },
    /// Update a policy table by ID
    Update {
        #[arg(value_name = "TABLE_ID")]
        id: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, value_name = "DESCRIPTION")]
        description: Option<String>,
    },
    /// Delete a policy table by ID
    Delete {
        #[arg(value_name = "TABLE_ID")]
        id: String,
        #[arg(long, help = "Show what would be deleted without actually deleting")]
        dry_run: bool,
        #[arg(long, help = "Skip confirmation prompt")]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum ZoneCommand {
    /// List zones
    List,
    /// Create a zone
    Create {
        #[arg(long)]
        name: String,
        #[arg(long, value_name = "DESCRIPTION")]
        description: Option<String>,
    },
    /// Update a zone by ID
    Update {
        #[arg(value_name = "ZONE_ID")]
        id: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, value_name = "DESCRIPTION")]
        description: Option<String>,
    },
    /// Delete a zone by ID
    Delete {
        #[arg(value_name = "ZONE_ID")]
        id: String,
        #[arg(long, help = "Show what would be deleted without actually deleting")]
        dry_run: bool,
        #[arg(long, help = "Skip confirmation prompt")]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum ObjectCommand {
    /// List objects (address/service objects)
    List,
    /// Create an object
    Create {
        #[arg(long)]
        name: String,
        #[arg(long, value_name = "TYPE", default_value = "address")]
        object_type: String,
        #[arg(long, value_name = "VALUE")]
        value: Option<String>,
    },
    /// Update an object by ID
    Update {
        #[arg(value_name = "OBJECT_ID")]
        id: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, value_name = "VALUE")]
        value: Option<String>,
    },
    /// Delete an object by ID
    Delete {
        #[arg(value_name = "OBJECT_ID")]
        id: String,
        #[arg(long, help = "Show what would be deleted without actually deleting")]
        dry_run: bool,
        #[arg(long, help = "Skip confirmation prompt")]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum PortProfileCommand {
    /// List port profiles
    List,
}

#[derive(Subcommand)]
enum CorrelateCommand {
    /// Correlate all data for a specific client by MAC address
    Client {
        #[arg(value_name = "MAC")]
        mac: String,
        #[arg(long)]
        site: Option<String>,
        #[arg(long, help = "Include historical events (last 24h)")]
        include_events: bool,
    },
    /// Correlate all data for a specific device (AP/switch) by MAC address
    Device {
        #[arg(value_name = "MAC")]
        mac: String,
        #[arg(long)]
        site: Option<String>,
        #[arg(long, help = "Include connected clients")]
        include_clients: bool,
    },
    /// Correlate all data for a specific Access Point and its clients
    Ap {
        #[arg(value_name = "AP_MAC")]
        ap_mac: String,
        #[arg(long)]
        site: Option<String>,
    },
}

#[derive(Subcommand)]
enum DiagnoseCommand {
    /// Run comprehensive network diagnostics
    Network {
        #[arg(long)]
        site: Option<String>,
    },
    /// Diagnose WiFi performance issues
    Wifi {
        #[arg(long)]
        site: Option<String>,
    },
    /// Diagnose client connectivity issues
    Client {
        #[arg(value_name = "MAC")]
        mac: Option<String>,
        #[arg(long)]
        site: Option<String>,
    },
}

#[derive(Subcommand)]
enum TimeSeriesCommand {
    /// Export traffic statistics as time-series data
    Traffic {
        #[arg(long, value_name = "TIMESTAMP_MS")]
        start: u64,
        #[arg(long, value_name = "TIMESTAMP_MS")]
        end: u64,
        #[arg(long)]
        site: Option<String>,
        #[arg(long, default_value = "csv", value_parser = ["csv", "json"], help = "Export format (csv, json)")]
        format: String,
    },
    /// Export WiFi statistics as time-series data
    Wifi {
        #[arg(long, value_name = "TIMESTAMP_MS")]
        start: u64,
        #[arg(long, value_name = "TIMESTAMP_MS")]
        end: u64,
        #[arg(long, help = "Specific AP MAC or 'all'")]
        ap_mac: Option<String>,
        #[arg(long)]
        site: Option<String>,
        #[arg(long, default_value = "csv", value_parser = ["csv", "json"], help = "Export format (csv, json)")]
        format: String,
    },
    /// Export event log as time-series data
    Events {
        #[arg(long, help = "Number of recent events to export (default: 100)")]
        limit: Option<usize>,
        #[arg(long)]
        site: Option<String>,
        #[arg(long, default_value = "csv", value_parser = ["csv", "json"], help = "Export format (csv, json)")]
        format: String,
    },
}

#[derive(Subcommand)]
enum LocalCommands {
    /// Site operations
    #[command(subcommand)]
    Site(LocalSiteCommand),
    /// Device operations
    #[command(subcommand)]
    Device(LocalDeviceCommand),
    /// Client operations
    #[command(subcommand)]
    Client(LocalClientCommand),
    /// Event operations
    #[command(subcommand)]
    Event(LocalEventCommand),
    /// Health operations
    #[command(subcommand)]
    Health(LocalHealthCommand),
    /// VPN operations
    #[command(subcommand)]
    Vpn(LocalVpnCommand),
    /// Security operations
    #[command(subcommand)]
    Security(LocalSecurityCommand),
    /// WAN operations
    #[command(subcommand)]
    Wan(LocalWanCommand),
    /// DPI operations
    #[command(subcommand)]
    Dpi(LocalDpiCommand),
    /// Top client operations
    #[command(subcommand)]
    TopClient(LocalTopClientCommand),
    /// Top device operations
    #[command(subcommand)]
    TopDevice(LocalTopDeviceCommand),
    /// System log operations
    #[command(subcommand)]
    Log(LocalLogCommand),
    /// WiFi/Radio operations
    #[command(subcommand)]
    Wifi(LocalWifiCommand),
    /// Traffic/Flow operations
    #[command(subcommand)]
    Traffic(LocalTrafficCommand),
    /// Statistics operations
    #[command(subcommand)]
    Stat(LocalStatCommand),

    /// Network (VLAN) operations
    #[command(subcommand)]
    Network(NetworkCommand),
    /// WLAN (SSID) operations
    #[command(subcommand)]
    Wlan(WlanCommand),
    /// Port profile operations
    #[command(subcommand)]
    PortProfile(PortProfileCommand),
    /// Firewall rule operations
    #[command(subcommand)]
    FirewallRule(FirewallRuleCommand),
    /// Firewall group operations
    #[command(subcommand)]
    FirewallGroup(FirewallGroupCommand),
    /// Policy table (routing policy) operations
    #[command(subcommand)]
    PolicyTable(PolicyTableCommand),
    /// Zone operations
    #[command(subcommand)]
    Zone(ZoneCommand),
    /// Object (address/service object) operations
    #[command(subcommand)]
    Object(ObjectCommand),
    /// Correlate data across multiple endpoints (client, device, AP, events)
    #[command(subcommand)]
    Correlate(CorrelateCommand),
    /// Run diagnostic analysis (multi-endpoint health check)
    #[command(subcommand)]
    Diagnose(DiagnoseCommand),
    /// Export time-series data for trend analysis
    #[command(subcommand)]
    TimeSeries(TimeSeriesCommand),
    /// Static DNS record operations
    #[command(subcommand)]
    Dns(LocalDnsCommand),
}

#[derive(Subcommand)]
enum LocalSiteCommand {
    /// List sites from the local controller
    List,
}

#[derive(Subcommand)]
enum LocalDeviceCommand {
    /// List devices from a site
    List {
        #[arg(long)]
        site: Option<String>,
        #[arg(long, help = "Show only unadopted/pending devices")]
        unadopted: bool,
        /// Maximum number of results to return (default: 30)
        #[arg(long, default_value_t = 30)]
        limit: usize,
    },
    /// Get device details/stats
    Get {
        #[arg(value_name = "MAC")]
        mac: String,
        #[arg(long)]
        site: Option<String>,
        #[arg(long, help = "Show config/state for the device")]
        config: bool,
        #[arg(long, help = "Show port table for the device")]
        ports: bool,
    },
    /// Restart the device
    Restart {
        #[arg(value_name = "MAC")]
        mac: String,
        #[arg(long)]
        site: Option<String>,
    },
    /// Force-provision the device (reload config without reboot)
    Provision {
        #[arg(value_name = "MAC")]
        mac: String,
        #[arg(long)]
        site: Option<String>,
    },
    /// Adopt the device (if pending)
    Adopt {
        #[arg(value_name = "MAC")]
        mac: String,
        #[arg(long)]
        site: Option<String>,
    },
    /// Adopt all unadopted devices
    AdoptAll {
        #[arg(long)]
        site: Option<String>,
    },
    /// Upgrade the device
    Upgrade {
        #[arg(value_name = "MAC")]
        mac: String,
        #[arg(long)]
        site: Option<String>,
    },
    /// Get spectrum scan results for device
    SpectrumScan {
        #[arg(value_name = "MAC")]
        mac: String,
        #[arg(long)]
        site: Option<String>,
    },
    /// Get port anomalies
    PortAnomalies {
        #[arg(long)]
        site: Option<String>,
    },
    /// Get MAC address tables
    MacTables {
        #[arg(long)]
        site: Option<String>,
        #[arg(long, value_name = "DEVICE_MAC")]
        device: Option<String>,
    },
}

#[derive(Subcommand)]
enum LocalClientCommand {
    /// List clients (with filters)
    List {
        #[arg(long)]
        site: Option<String>,
        #[arg(long, help = "Only wired clients")]
        wired: bool,
        #[arg(long, help = "Only wireless clients")]
        wireless: bool,
        #[arg(long, help = "Only blocked clients")]
        blocked: bool,
        /// Maximum number of clients to return. Defaults to 30, so larger
        /// networks ARE cut short — a warning naming the full count is printed
        /// on stderr whenever that happens
        #[arg(long, default_value_t = 30)]
        limit: usize,
    },
    /// Block the client
    Block {
        #[arg(value_name = "MAC")]
        mac: String,
        #[arg(long)]
        site: Option<String>,
    },
    /// Unblock the client
    Unblock {
        #[arg(value_name = "MAC")]
        mac: String,
        #[arg(long)]
        site: Option<String>,
    },
    /// Force reconnect (kick)
    Reconnect {
        #[arg(value_name = "MAC")]
        mac: String,
        #[arg(long)]
        site: Option<String>,
    },
    /// Get active clients (v2 API)
    Active {
        #[arg(long)]
        site: Option<String>,
        /// Maximum number of clients to return. Defaults to 30; a warning
        /// naming the full count is printed on stderr when results are cut
        #[arg(long, default_value_t = 30)]
        limit: usize,
    },
    /// Get client connection history (v2 API)
    History {
        #[arg(long)]
        site: Option<String>,
        /// Only history for this client. Matching is case-insensitive and
        /// accepts colon, dash or bare-hex MAC forms
        #[arg(long, value_name = "MAC")]
        mac: Option<String>,
        /// Maximum number of history entries to return. Defaults to 30; a
        /// warning naming the full count is printed on stderr when results are
        /// cut
        #[arg(long, default_value_t = 30)]
        limit: usize,
    },
    /// Update client metadata
    UpdateMetadata {
        #[arg(value_name = "MAC")]
        mac: String,
        #[arg(long)]
        site: Option<String>,
        #[arg(long, value_name = "JSON")]
        metadata: Option<String>,
    },
}

#[derive(Subcommand)]
enum LocalEventCommand {
    /// List recent events
    List {
        #[arg(long)]
        site: Option<String>,
        /// Maximum number of events to return. Values above the controller's
        /// 50-per-page default are served by paginating; a warning is printed
        /// on stderr if fewer than requested could be retrieved
        #[arg(long, default_value_t = 30)]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum LocalHealthCommand {
    /// Get health summaries
    Get {
        #[arg(long)]
        site: Option<String>,
    },
}

#[derive(Subcommand)]
enum LocalVpnCommand {
    /// Get VPN health (site-to-site, remote user)
    Get {
        #[arg(long)]
        site: Option<String>,
    },
}

#[derive(Subcommand)]
enum LocalSecurityCommand {
    /// Get security settings
    Get {
        #[arg(long)]
        site: Option<String>,
    },
}

#[derive(Subcommand)]
enum LocalWanCommand {
    /// Get WAN health
    Get {
        #[arg(long)]
        site: Option<String>,
    },
}

#[derive(Subcommand)]
enum LocalDpiCommand {
    /// Get DPI applications summary
    Get {
        #[arg(long)]
        site: Option<String>,
    },
}

#[derive(Subcommand)]
enum LocalTopClientCommand {
    /// List top clients by bandwidth
    List {
        #[arg(long)]
        site: Option<String>,
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum LocalTopDeviceCommand {
    /// List top devices by number of clients
    List {
        #[arg(long)]
        site: Option<String>,
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum LocalLogCommand {
    /// Get system log settings
    Settings {
        #[arg(long)]
        site: Option<String>,
    },
    /// Query all system logs
    All {
        #[arg(long)]
        site: Option<String>,
        #[arg(long, value_name = "LIMIT")]
        limit: Option<usize>,
        #[arg(long, value_name = "OFFSET")]
        offset: Option<usize>,
    },
    /// Count log entries
    Count {
        #[arg(long)]
        site: Option<String>,
    },
    /// Get critical system logs
    Critical {
        #[arg(long)]
        site: Option<String>,
        #[arg(long, value_name = "LIMIT")]
        limit: Option<usize>,
    },
    /// Get device alert logs
    DeviceAlert {
        #[arg(long)]
        site: Option<String>,
        #[arg(long, value_name = "LIMIT")]
        limit: Option<usize>,
    },
    /// Get admin-activity / audit logs (ADMIN_ACCESS and other AUDIT events)
    AdminActivity {
        #[arg(long)]
        site: Option<String>,
        #[arg(long, value_name = "LIMIT")]
        limit: Option<usize>,
    },
}

#[derive(Subcommand)]
enum LocalWifiCommand {
    /// Get WiFi connectivity statistics
    Connectivity {
        #[arg(long)]
        site: Option<String>,
    },
    /// Get detailed WiFi statistics (requires time range)
    Stats {
        #[arg(long)]
        site: Option<String>,
        #[arg(long, help = "Show radio statistics")]
        radios: bool,
        /// Start timestamp (milliseconds since epoch)
        #[arg(long)]
        start: i64,
        /// End timestamp (milliseconds since epoch)
        #[arg(long)]
        end: i64,
        /// AP MAC address (use 'all' for all APs) - only for details, not radios
        #[arg(long)]
        ap_mac: Option<String>,
    },
    /// Get Radio AI isolation matrix
    RadioAi {
        #[arg(long)]
        site: Option<String>,
    },
    /// Get WiFi management data
    Management {
        #[arg(long)]
        site: Option<String>,
    },
    /// Get enhanced WLAN configuration
    Config {
        #[arg(long)]
        site: Option<String>,
    },
}

#[derive(Subcommand)]
enum LocalTrafficCommand {
    /// Get traffic statistics (requires time range)
    Stats {
        #[arg(long)]
        site: Option<String>,
        /// Start timestamp (milliseconds since epoch)
        #[arg(long)]
        start: i64,
        /// End timestamp (milliseconds since epoch)
        #[arg(long)]
        end: i64,
        /// Include unidentified traffic (default: true)
        #[arg(long, default_value = "true", action = clap::ArgAction::Set)]
        include_unidentified: bool,
    },
    /// Get latest traffic flow statistics (requires period and top)
    FlowLatest {
        #[arg(long)]
        site: Option<String>,
        /// Period: DAY or MONTH
        #[arg(long, value_enum)]
        period: FlowPeriod,
        /// Number of top flows to return
        #[arg(long)]
        top: u32,
    },
    /// Get traffic flow filter metadata
    FilterData {
        #[arg(long)]
        site: Option<String>,
    },
    /// Get traffic routing rules
    Routes {
        #[arg(long)]
        site: Option<String>,
    },
    /// Get traffic rules
    Rules {
        #[arg(long)]
        site: Option<String>,
    },
    /// Query application traffic rate (requires time range)
    AppRate {
        #[arg(long)]
        site: Option<String>,
        /// Start timestamp (milliseconds since epoch)
        #[arg(long)]
        start: i64,
        /// End timestamp (milliseconds since epoch)
        #[arg(long)]
        end: i64,
        /// Include unidentified traffic (default: true)
        #[arg(long, default_value = "true", action = clap::ArgAction::Set)]
        include_unidentified: bool,
    },
    /// Query traffic flows
    Flows {
        #[arg(long)]
        site: Option<String>,
        #[arg(long, value_name = "JSON")]
        query: Option<String>,
    },
}

#[derive(Subcommand)]
enum LocalStatCommand {
    /// Get country code statistics
    Ccode {
        #[arg(long)]
        site: Option<String>,
    },
    /// Get current channel statistics
    CurrentChannel {
        #[arg(long)]
        site: Option<String>,
    },
    /// Get basic device statistics
    DeviceBasic {
        #[arg(long)]
        site: Option<String>,
    },
    /// Get guest statistics
    Guest {
        #[arg(long)]
        site: Option<String>,
    },
    /// Get rogue AP detection results
    Rogueap {
        #[arg(long)]
        site: Option<String>,
    },
    /// Get threat-management / IPS-IDS alarms (and other system alarms)
    Alarm {
        #[arg(long)]
        site: Option<String>,
        /// Include archived/acknowledged alarms instead of only active ones
        #[arg(long)]
        archived: bool,
        /// Maximum number of results to return (default: 30)
        #[arg(long, default_value_t = 30)]
        limit: usize,
    },
    /// Get SDN statistics
    Sdn {
        #[arg(long)]
        site: Option<String>,
    },
    /// Get 5-minute AP report
    Report5min {
        #[arg(long)]
        site: Option<String>,
    },
}

#[derive(Subcommand)]
enum LocalDnsCommand {
    /// List static DNS records
    List {
        #[arg(long)]
        site: Option<String>,
        /// Maximum number of results to return (default: 30)
        #[arg(long, default_value_t = 30)]
        limit: usize,
    },
    /// Add a static DNS record
    Add {
        /// Hostname (key) for the record
        #[arg(value_name = "HOST")]
        host: String,
        /// Value: IP address for A/AAAA, target hostname for CNAME
        #[arg(value_name = "VALUE")]
        value: String,
        /// Record type (A, AAAA, CNAME, ...)
        #[arg(long, default_value = "A")]
        record_type: String,
        /// Create the record in disabled state
        #[arg(long)]
        disabled: bool,
        #[arg(long)]
        site: Option<String>,
    },
    /// Update a static DNS record by id (partial; only provided fields change)
    Update {
        #[arg(value_name = "ID")]
        id: String,
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        value: Option<String>,
        #[arg(long)]
        record_type: Option<String>,
        /// Enable the record
        #[arg(long)]
        enabled: bool,
        /// Disable the record
        #[arg(long, conflicts_with = "enabled")]
        disabled: bool,
        #[arg(long)]
        site: Option<String>,
    },
    /// Delete a static DNS record by id
    Delete {
        #[arg(value_name = "ID")]
        id: String,
        #[arg(long)]
        site: Option<String>,
        #[arg(long, help = "Show what would be deleted without actually deleting")]
        dry_run: bool,
        #[arg(long, help = "Skip confirmation prompt")]
        yes: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum OutputFormat {
    Pretty,
    Json,
    Raw,
    Csv,
    /// LLM-optimized output with schema, summaries, and token estimates
    Llm,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    PowerShell,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ScopeArg {
    Local,
    User,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum FlowPeriod {
    Day,
    Month,
}

impl From<ScopeArg> for Scope {
    fn from(value: ScopeArg) -> Self {
        match value {
            ScopeArg::Local => Scope::Local,
            ScopeArg::User => Scope::User,
        }
    }
}

#[derive(Clone)]
struct RenderOpts {
    columns_override: Option<Vec<String>>,
    sort_by: Option<String>,
    filter: Option<String>,
    filter_regex: Option<String>,
    schema: Option<&'static str>,
    target: Option<String>,
    site: Option<String>,
}

fn command_schema(command: &Commands) -> Option<&'static str> {
    match command {
        Commands::Local { command, .. } => match command {
            LocalCommands::Device(LocalDeviceCommand::List { .. })
            | LocalCommands::TopDevice(_) => Some("device.list"),
            LocalCommands::Client(
                LocalClientCommand::List { .. }
                | LocalClientCommand::Active { .. }
                | LocalClientCommand::History { .. },
            )
            | LocalCommands::TopClient(_) => Some("client.list"),
            LocalCommands::Event(_) => Some("event.list"),
            LocalCommands::Health(_) => Some("health.get"),
            _ => None,
        },
        _ => None,
    }
}

fn local_target_id(command: &LocalCommands) -> Option<&str> {
    match command {
        LocalCommands::Network(
            NetworkCommand::Update { id, .. } | NetworkCommand::Delete { id, .. },
        )
        | LocalCommands::Wlan(WlanCommand::Update { id, .. } | WlanCommand::Delete { id, .. })
        | LocalCommands::FirewallRule(
            FirewallRuleCommand::Update { id, .. } | FirewallRuleCommand::Delete { id, .. },
        )
        | LocalCommands::FirewallGroup(
            FirewallGroupCommand::Update { id, .. } | FirewallGroupCommand::Delete { id, .. },
        )
        | LocalCommands::PolicyTable(
            PolicyTableCommand::Update { id, .. } | PolicyTableCommand::Delete { id, .. },
        )
        | LocalCommands::Zone(ZoneCommand::Update { id, .. } | ZoneCommand::Delete { id, .. })
        | LocalCommands::Object(
            ObjectCommand::Update { id, .. } | ObjectCommand::Delete { id, .. },
        )
        | LocalCommands::Dns(
            LocalDnsCommand::Update { id, .. } | LocalDnsCommand::Delete { id, .. },
        ) => Some(id),
        LocalCommands::Device(
            LocalDeviceCommand::Get { mac, .. }
            | LocalDeviceCommand::Restart { mac, .. }
            | LocalDeviceCommand::Provision { mac, .. }
            | LocalDeviceCommand::Adopt { mac, .. }
            | LocalDeviceCommand::Upgrade { mac, .. }
            | LocalDeviceCommand::SpectrumScan { mac, .. },
        ) => Some(mac),
        _ => None,
    }
}

fn response_rows(response: &ResponseData) -> Result<Vec<serde_json::Value>> {
    response
        .json
        .as_ref()
        .and_then(output::rows)
        .cloned()
        .ok_or_else(|| anyhow!("Invalid collection response: expected an array or data array"))
}

fn validation_check(name: &str, result: Result<ResponseData>) -> serde_json::Value {
    match result {
        Ok(_) => json!({"name": name, "status": "pass"}),
        Err(error) => {
            json!({"name": name, "status": "error", "error": terminal_safe(&format!("{error:#}"))})
        }
    }
}

fn render_value(value: serde_json::Value, output: OutputFormat, opts: &RenderOpts) -> Result<()> {
    render_response(
        ResponseData {
            status: 200,
            body: serde_json::to_string(&value)?,
            json: Some(value),
        },
        output,
        opts,
        None,
    )
}

fn validate_controller_url(url: &str) -> Result<String> {
    Ok(crate::client::validate_base_url(url.trim(), true)?.to_string())
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let output = cli.output;
    match run(cli) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            let message = terminal_safe(&format!("{error:#}"));
            if matches!(
                output,
                OutputFormat::Json | OutputFormat::Llm | OutputFormat::Csv
            ) {
                eprintln!(
                    "{}",
                    json!({"error": {"message": message}, "collected_at": chrono::Utc::now().to_rfc3339(), "outcome": "error"})
                );
            } else {
                eprintln!("Error: {message}");
            }
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    config::set_no_project_config(cli.no_project_config);
    if let Some(pattern) = &cli.filter_regex {
        RegexBuilder::new(pattern)
            .case_insensitive(true)
            .build()
            .context("Invalid filter regular expression")?;
    }
    let cwd = std::env::current_dir().context("reading current directory")?;
    FULL_IDS.get_or_init(|| cli.full_ids);
    session::set_disabled(cli.no_session_cache);

    if let Commands::Login {
        command: None,
        args,
    } = &cli.command
    {
        if args.api_key.is_none() && args.controller_url.is_none() {
            return Err(anyhow!(
                "Provide at least --api-key or --controller-url (with --username and --password)"
            ));
        }

        let mut existing = config::load_scope(args.scope.into(), &cwd)?;

        if let Some(key) = &args.api_key {
            existing.api_key = Some(key.trim().to_string());
        }

        if let Some(url) = &args.controller_url {
            let validated_url = validate_controller_url(url)?;
            let mut local_cfg = existing.local.take().unwrap_or_default();
            let same_target = local_cfg
                .url
                .as_deref()
                .and_then(|previous| validate_controller_url(previous).ok())
                .is_some_and(|previous| previous == validated_url);
            if !same_target {
                // A trust exception belongs to its controller, not the next login.
                local_cfg.verify_tls = None;
                local_cfg.ca_file = None;
                local_cfg.port_fallback = None;
            }
            if args.port_fallback {
                local_cfg.port_fallback = Some(true);
            }
            if args.no_port_fallback {
                local_cfg.port_fallback = Some(false);
            }
            if args.verify_tls {
                local_cfg.verify_tls = Some(true);
            }
            if args.insecure {
                local_cfg.verify_tls = Some(false);
            }
            if let Some(ca_file) = &args.ca_file {
                local_cfg.ca_file = Some(
                    fs::canonicalize(cwd.join(ca_file)).context("Resolving controller CA file")?,
                );
            }
            let verify_tls = local_cfg.verify_tls.unwrap_or(true);
            if !verify_tls && local_cfg.ca_file.is_some() {
                return Err(anyhow!(
                    "A controller CA requires TLS verification; use --verify-tls or remove the stored CA before selecting --insecure"
                ));
            }
            if verify_tls && validated_url.starts_with("http:") {
                return Err(anyhow!(
                    "HTTPS is required; explicitly select --insecure to save an HTTP controller"
                ));
            }
            let u = args.username.clone().ok_or_else(|| {
                anyhow!("--username is required when setting a local controller URL")
            })?;
            let p = match &args.password {
                Some(p) => {
                    eprintln!(
                        "Warning: passing --password on the command line is insecure.\n\
                         The value is visible in your shell history and to other users via\n\
                         process listings (e.g. `ps aux`). Omit --password next time to be\n\
                         prompted securely with hidden input."
                    );
                    p.clone()
                }
                None => rpassword::prompt_password("Local controller password: ")
                    .context("reading password from terminal")?,
            };
            local_cfg.url = Some(validated_url);
            local_cfg.username = Some(u);
            local_cfg.password = Some(p);
            local_cfg.site = Some(args.site.clone());
            existing.local = Some(local_cfg);
        }

        let path = save(args.scope.into(), &existing, &cwd)?;
        println!("Credentials saved to {}", path.display());
        return Ok(());
    }

    let render_opts = RenderOpts {
        columns_override: cli.columns.as_ref().map(|c| {
            c.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        }),
        sort_by: cli.sort_by.clone(),
        filter: cli.filter.clone(),
        filter_regex: cli.filter_regex.clone(),
        schema: command_schema(&cli.command),
        target: None,
        site: None,
    };

    match cli.command {
        Commands::Cloud { command } => {
            let effective = resolve(&cwd, cli.api_key.clone(), cli.base_url.clone())?;
            let client = ApiClient::new(&effective.base_url, &effective.api_key)?;
            let mut render_opts = render_opts.clone();
            render_opts.target = Some(effective.base_url);
            match command {
                CloudCommands::Host(command) => match command {
                    HostCommand::List => run_get(
                        &client,
                        "/v1/hosts",
                        vec![],
                        cli.output,
                        &render_opts,
                        Some(&[
                            "name",
                            "displayName",
                            "type",
                            "hostType",
                            "status",
                            "publicIp",
                            "id",
                        ]),
                        cli.watch,
                    )?,
                    HostCommand::Get { id } => run_get(
                        &client,
                        &format!("/v1/hosts/{id}"),
                        vec![],
                        cli.output,
                        &render_opts,
                        None,
                        cli.watch,
                    )?,
                },
                CloudCommands::Site(command) => match command {
                    SiteCommand::List { host_id } => {
                        let mut query = Vec::new();
                        if let Some(host) = host_id {
                            query.push(("hostId", host));
                        }
                        run_get(
                            &client,
                            "/v1/sites",
                            query,
                            cli.output,
                            &render_opts,
                            Some(&["name", "displayName", "hostId", "siteId", "id"]),
                            cli.watch,
                        )?
                    }
                },
                CloudCommands::Device(command) => match command {
                    DeviceCommand::List { host_id, site_id } => {
                        let mut query = Vec::new();
                        if let Some(host) = host_id {
                            query.push(("hostId", host));
                        }
                        if let Some(site) = site_id {
                            query.push(("siteId", site));
                        }
                        run_get(
                            &client,
                            "/v1/devices",
                            query,
                            cli.output,
                            &render_opts,
                            Some(&[
                                "name",
                                "displayName",
                                "hostname",
                                "model",
                                "type",
                                "siteId",
                                "hostId",
                                "ip",
                                "mac",
                                "version",
                                "status",
                            ]),
                            cli.watch,
                        )?
                    }
                    DeviceCommand::Get {
                        id,
                        host_id,
                        site_id,
                    } => {
                        let mut query = Vec::new();
                        if let Some(host) = host_id {
                            query.push(("hostId", host));
                        }
                        if let Some(site) = site_id {
                            query.push(("siteId", site));
                        }
                        run_get(
                            &client,
                            &format!("/v1/devices/{id}"),
                            query,
                            cli.output,
                            &render_opts,
                            Some(&[
                                "name",
                                "displayName",
                                "hostname",
                                "model",
                                "type",
                                "ip",
                                "mac",
                                "siteId",
                                "hostId",
                                "version",
                                "status",
                            ]),
                            cli.watch,
                        )?
                    }
                },
                CloudCommands::Isp(command) => match command {
                    IspCommand::Get {
                        metric_type,
                        host_id,
                        site_id,
                        start,
                        end,
                    } => {
                        let mut query = Vec::new();
                        if let Some(host) = host_id {
                            query.push(("hostId", host));
                        }
                        if let Some(site) = site_id {
                            query.push(("siteId", site));
                        }
                        if let Some(start) = start {
                            query.push(("start", start));
                        }
                        if let Some(end) = end {
                            query.push(("end", end));
                        }
                        run_get(
                            &client,
                            &format!("/ea/isp-metrics/{metric_type}"),
                            query,
                            cli.output,
                            &render_opts,
                            None,
                            cli.watch,
                        )?
                    }
                    IspCommand::Query {
                        metric_type,
                        body,
                        body_file,
                    } => {
                        let payload = parse_body(&body, &body_file)?.ok_or_else(|| {
                            anyhow!("Provide --body or --body-file with JSON content")
                        })?;
                        run_post(
                            &client,
                            &format!("/ea/isp-metrics/{metric_type}/query"),
                            vec![],
                            payload,
                            cli.output,
                            &render_opts,
                            None,
                        )?
                    }
                },
                CloudCommands::Sdwan(command) => match command {
                    SdwanCommand::List => run_get(
                        &client,
                        "/ea/sd-wan-configs",
                        vec![],
                        cli.output,
                        &render_opts,
                        Some(&["id", "name", "status", "hostId", "siteId"]),
                        cli.watch,
                    )?,
                    SdwanCommand::Get { id } => run_get(
                        &client,
                        &format!("/ea/sd-wan-configs/{id}"),
                        vec![],
                        cli.output,
                        &render_opts,
                        None,
                        cli.watch,
                    )?,
                    SdwanCommand::Status { id } => run_get(
                        &client,
                        &format!("/ea/sd-wan-configs/{id}/status"),
                        vec![],
                        cli.output,
                        &render_opts,
                        None,
                        cli.watch,
                    )?,
                },
            }
        }
        Commands::Login {
            command:
                Some(LoginCommand::Validate {
                    cloud_only,
                    local_only,
                }),
            ..
        } => {
            if cloud_only && local_only {
                return Err(anyhow!("Use only one of --cloud-only or --local-only"));
            }

            let mut checks = Vec::new();
            if !local_only {
                let result =
                    resolve(&cwd, cli.api_key.clone(), cli.base_url.clone()).and_then(|cfg| {
                        ApiClient::new(&cfg.base_url, &cfg.api_key)?.get("/v1/hosts", &[])
                    });
                checks.push(validation_check("cloud", result));
            }
            if !cloud_only {
                let result = resolve_local(&cwd, None)
                    .and_then(|cfg| LocalClient::from_config(&cfg)?.validate_credentials());
                checks.push(validation_check("local", result));
            }
            let failed = checks.iter().any(|check| check["status"] != "pass");
            let result =
                json!({"validation": checks, "outcome": if failed { "failed" } else { "success" }});
            render_value(result, cli.output, &render_opts)?;
            if failed {
                return Err(anyhow!("Credential validation failed"));
            }
        }
        Commands::Login {
            command: Some(LoginCommand::Show),
            ..
        } => {
            let merged = config::load(&cwd)?;
            let mut masked = merged.clone();
            if let Some(local) = masked.local.as_mut()
                && local.password.is_some()
            {
                local.password = Some("*****".into());
            }
            if masked.api_key.is_some() {
                masked.api_key = Some("*****".into());
            }
            println!("{}", serde_json::to_string_pretty(&masked)?);
        }
        Commands::Local { site, command } => {
            handle_local(command, site, &cwd, cli.output, &render_opts, cli.watch)?;
        }
        Commands::Completion { shell } => {
            use clap_complete::{generate, shells};
            let mut cmd = Cli::command();
            let bin = cmd.get_name().to_string();
            match shell {
                CompletionShell::Bash => {
                    generate(shells::Bash, &mut cmd, bin, &mut std::io::stdout())
                }
                CompletionShell::Zsh => {
                    generate(shells::Zsh, &mut cmd, bin, &mut std::io::stdout())
                }
                CompletionShell::Fish => {
                    generate(shells::Fish, &mut cmd, bin, &mut std::io::stdout())
                }
                CompletionShell::PowerShell => {
                    generate(shells::PowerShell, &mut cmd, bin, &mut std::io::stdout())
                }
            }
        }
        Commands::Login { command: None, .. } => unreachable!("handled earlier"),
    }

    Ok(())
}

fn handle_local(
    cmd: LocalCommands,
    global_site: Option<String>,
    cwd: &std::path::Path,
    output: OutputFormat,
    render_opts: &RenderOpts,
    watch: Option<u64>,
) -> Result<()> {
    if let Some(id) = local_target_id(&cmd) {
        local::validate_target_id(id)?;
    }
    let cfg = resolve_local(cwd, site_override(global_site.clone()))?;
    let mut opts = render_opts.clone();
    opts.target = Some(cfg.url);
    opts.site = Some(cfg.site);
    let render_opts = &opts;
    match cmd {
        LocalCommands::Site(LocalSiteCommand::List) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || client.list_sites(),
                output,
                render_opts,
                Some(&["name", "desc", "role"]),
                watch,
            )
        }
        LocalCommands::Device(LocalDeviceCommand::List {
            site: _,
            unadopted,
            limit,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || {
                    let mut resp = client.list_devices()?;
                    if let Some(mut json) = resp.json.clone() {
                        capture_collection(&mut json);
                        if let Some(arr) = json.get_mut("data").and_then(|d| d.as_array_mut()) {
                            if unadopted {
                                arr.retain(|item| {
                                    let state = item.get("state").and_then(|s| s.as_str());
                                    let adopted = item.get("adopted").and_then(|a| a.as_bool());
                                    state == Some("pending") || adopted == Some(false)
                                });
                            }
                            if arr.len() > limit {
                                arr.truncate(limit);
                            }
                        }
                        resp.body =
                            serde_json::to_string(&json).unwrap_or_else(|_| resp.body.clone());
                        resp.json = Some(json);
                    }
                    Ok(resp)
                },
                output,
                render_opts,
                Some(&[
                    "name", "model", "type", "ip", "mac", "version", "state", "adopted",
                ]),
                watch,
            )
        }
        LocalCommands::Device(LocalDeviceCommand::AdoptAll { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let devices = client.list_devices()?;
            let data = response_rows(&devices)?;
            let mut results = Vec::new();
            let mut stop_remaining = false;
            for device in data {
                let unadopted = device.get("state").and_then(|v| v.as_str()) == Some("pending")
                    || device.get("adopted").and_then(|v| v.as_bool()) == Some(false);
                if !unadopted {
                    continue;
                }
                let mac = device.get("mac").and_then(|v| v.as_str());
                let mut result = json!({"mac": mac, "name": device.get("name")});
                if stop_remaining {
                    result["status"] = json!("not_attempted");
                    result["error"] = json!(
                        "Batch stopped after an ambiguous write outcome, authentication/permission denial or rate limiting; inspect prior results and read back state before retrying"
                    );
                    results.push(result);
                    continue;
                }
                match mac {
                    Some(mac) => match client.device_action(mac, "adopt") {
                        Ok(_) => result["status"] = json!("accepted"),
                        Err(error) => {
                            let message = format!("{error:#}");
                            stop_remaining = local::should_stop_batch(&error)
                                || message.contains("outcome=unknown");
                            result["status"] = json!("not_confirmed");
                            result["error"] = json!(terminal_safe(&message));
                        }
                    },
                    None => {
                        result["status"] = json!("not_attempted");
                        result["error"] =
                            json!("Unadopted device has no MAC; target cannot be identified");
                    }
                }
                results.push(result);
            }
            let accepted = results.iter().filter(|r| r["status"] == "accepted").count();
            let unconfirmed = results.len() - accepted;
            let report = json!({
                "action": "adopt", "outcome": if unconfirmed == 0 { "accepted" } else { "partial_or_failed" },
                "accepted_count": accepted, "unconfirmed_count": unconfirmed,
                "batch_stopped": stop_remaining,
                "results": results,
                "verification": "Acceptance is not completed adoption; read back each device before further actions"
            });
            render_value(report, output, render_opts)?;
            if unconfirmed > 0 {
                return Err(anyhow!(
                    "Adoption has {unconfirmed} unconfirmed or unattempted targets; inspect results before retrying"
                ));
            }
            Ok(())
        }
        LocalCommands::Device(LocalDeviceCommand::Get {
            mac,
            site: _,
            config,
            ports,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || {
                    // stats/config/ports are derived from device listing
                    let mut resp = client.device_stats(&mac)?;
                    if let Some(mut json) = resp.json.clone() {
                        capture_collection(&mut json);
                        if let Some(arr) = json.get_mut("data").and_then(|d| d.as_array_mut())
                            && let Some(first) = arr.get_mut(0)
                        {
                            if !ports && let Some(o) = first.as_object_mut() {
                                o.remove("port_table");
                            }
                            if !config {
                                // keep stats only (remove config-heavy?)
                            }
                        }
                        resp.body =
                            serde_json::to_string(&json).unwrap_or_else(|_| resp.body.clone());
                        resp.json = Some(json);
                    }
                    Ok(resp)
                },
                output,
                render_opts,
                Some(&["name", "model", "type", "ip", "mac", "version", "state"]),
                watch,
            )
        }
        LocalCommands::Device(LocalDeviceCommand::Restart { mac, site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_response(
                client.device_action(&mac, "restart")?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::Device(LocalDeviceCommand::Provision { mac, site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_response(
                client.device_action(&mac, "force-provision")?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::Device(LocalDeviceCommand::Adopt { mac, site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_response(
                client.device_action(&mac, "adopt")?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::Device(LocalDeviceCommand::Upgrade { mac, site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_response(
                client.device_action(&mac, "upgrade")?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::Device(LocalDeviceCommand::SpectrumScan { mac, site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || client.stat_spectrum_scan(&mac),
                output,
                render_opts,
                None,
                watch,
            )
        }
        LocalCommands::Device(LocalDeviceCommand::PortAnomalies { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || client.ports_anomalies(),
                output,
                render_opts,
                None,
                watch,
            )
        }
        LocalCommands::Device(LocalDeviceCommand::MacTables { site: _, device }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let payload = device.map(|d| serde_json::json!({ "device": d }));
            render_local(
                || client.ports_mac_tables(payload.as_ref()),
                output,
                render_opts,
                None,
                watch,
            )
        }
        LocalCommands::Client(LocalClientCommand::List {
            site: _,
            wired,
            wireless,
            blocked,
            limit,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || {
                    let mut resp = client.list_clients()?;
                    if let Some(mut json) = resp.json.clone() {
                        capture_collection(&mut json);
                        if let Some(arr) = list_payload_mut(&mut json) {
                            arr.retain(|item| {
                                let is_wired = item
                                    .get("is_wired")
                                    .and_then(|w| w.as_bool())
                                    .unwrap_or(false);
                                let is_wireless = !is_wired;
                                let is_blocked = item
                                    .get("blocked")
                                    .and_then(|b| b.as_bool())
                                    .unwrap_or(false);

                                (wired && is_wired)
                                    || (wireless && is_wireless)
                                    || (blocked && is_blocked)
                                    || (!wired && !wireless && !blocked)
                            });
                            truncate_with_warning(arr, limit, "clients");
                        }
                        resp.body =
                            serde_json::to_string(&json).unwrap_or_else(|_| resp.body.clone());
                        resp.json = Some(json);
                    }
                    Ok(resp)
                },
                output,
                render_opts,
                Some(&[
                    "hostname",
                    "name",
                    "ip",
                    "mac",
                    "is_wired",
                    "blocked",
                    "oui",
                    "network_name",
                ]),
                watch,
            )
        }
        LocalCommands::Client(LocalClientCommand::Block { mac, site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_response(
                client.client_action(&mac, "block")?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::Client(LocalClientCommand::Unblock { mac, site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_response(
                client.client_action(&mac, "unblock")?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::Client(LocalClientCommand::Reconnect { mac, site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_response(
                client.client_action(&mac, "reconnect")?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::Client(LocalClientCommand::Active { site: _, limit }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || {
                    let mut resp = client.clients_v2_active()?;
                    if let Some(mut json) = resp.json.clone() {
                        capture_collection(&mut json);
                        // v2 endpoint: bare array, no `data` envelope — see the
                        // note in `client history`.
                        if let Some(arr) = list_payload_mut(&mut json) {
                            truncate_with_warning(arr, limit, "active clients");
                        }
                        resp.body =
                            serde_json::to_string(&json).unwrap_or_else(|_| resp.body.clone());
                        resp.json = Some(json);
                    }
                    Ok(resp)
                },
                output,
                render_opts,
                Some(&["mac", "hostname", "ip", "is_wired", "network_name"]),
                watch,
            )
        }
        LocalCommands::Client(LocalClientCommand::History {
            site: _,
            mac,
            limit,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let mac_filter = mac.clone();
            render_local(
                move || {
                    let mut resp = client.clients_v2_history()?;
                    if let Some(mut json) = resp.json.clone() {
                        capture_collection(&mut json);
                        // `clients/history` is a v2 endpoint: it answers with a
                        // bare array, not a `{"data": …}` envelope. Reaching
                        // straight for `data` found nothing, so both --mac and
                        // --limit were silently ignored here.
                        if let Some(arr) = list_payload_mut(&mut json) {
                            if let Some(ref mac_val) = mac_filter
                                && !retain_clients_with_mac(arr, mac_val)
                            {
                                eprintln!(
                                    "No matching client: no entry in the connection history has \
                                     MAC {mac_val}. (History covers clients the controller still \
                                     remembers; try `client active` or `client list` for \
                                     currently known clients.)"
                                );
                            }
                            truncate_with_warning(arr, limit, "history entries");
                        }
                        resp.body =
                            serde_json::to_string(&json).unwrap_or_else(|_| resp.body.clone());
                        resp.json = Some(json);
                    }
                    Ok(resp)
                },
                output,
                render_opts,
                Some(&[
                    "mac",
                    "hostname",
                    "ip",
                    "is_wired",
                    "network_name",
                    "last_seen",
                ]),
                watch,
            )
        }
        LocalCommands::Client(LocalClientCommand::UpdateMetadata {
            mac,
            site: _,
            metadata,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let mac_clone = mac.clone();
            let mut payload = if let Some(meta_json) = metadata {
                serde_json::from_str::<serde_json::Value>(&meta_json)
                    .context("parsing metadata JSON")?
            } else {
                return Err(anyhow!("--metadata is required"));
            };
            // Ensure MAC address is included in payload
            if let serde_json::Value::Object(ref mut map) = payload {
                map.insert(
                    "mac".to_string(),
                    serde_json::Value::String(mac_clone.clone()),
                );
            }
            render_response(
                client.update_client_metadata(&mac_clone, &payload)?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::Event(LocalEventCommand::List { site: _, limit }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || {
                    // The v2 event feed pages at 50 records unless `pageSize`
                    // is sent, so truncating a single default response could
                    // never honor a --limit above 50. Paginate instead, and say
                    // so out loud when the controller runs dry early.
                    let (mut resp, stats) = client.list_events_paged(limit)?;
                    attach_paged_metadata(&mut resp, stats)?;
                    if stats.truncated {
                        match stats.total_available {
                            Some(total) => eprintln!(
                                "Warning: requested {} events but only {} could be retrieved \
                                 ({} exist on the controller). Results are incomplete.",
                                stats.requested, stats.returned, total
                            ),
                            None => eprintln!(
                                "Warning: requested {} events but only {} could be retrieved. \
                                 Results are incomplete.",
                                stats.requested, stats.returned
                            ),
                        }
                    }
                    Ok(resp)
                },
                output,
                render_opts,
                Some(&["timestamp", "key", "category", "event", "message_raw"]),
                watch,
            )
        }
        LocalCommands::Log(LocalLogCommand::Settings { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || client.system_log_settings(),
                output,
                render_opts,
                None,
                watch,
            )
        }
        LocalCommands::Log(LocalLogCommand::All {
            site: _,
            limit,
            offset,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let mut payload = serde_json::json!({});
            if let Some(lim) = limit {
                payload["pageSize"] = serde_json::json!(lim);
            }
            if let Some(off) = offset {
                payload["pageNumber"] = serde_json::json!(off);
            }
            render_local(
                || client.system_log_all(Some(&payload)),
                output,
                render_opts,
                Some(&["timestamp", "key", "category", "subcategory", "message"]),
                watch,
            )
        }
        LocalCommands::Log(LocalLogCommand::Count { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || client.system_log_count(None),
                output,
                render_opts,
                None,
                watch,
            )
        }
        LocalCommands::Log(LocalLogCommand::Critical { site: _, limit }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let payload = limit.map(|lim| serde_json::json!({ "pageSize": lim }));
            render_local(
                || client.system_log_critical(payload.as_ref()),
                output,
                render_opts,
                Some(&["timestamp", "key", "category", "subcategory", "message"]),
                watch,
            )
        }
        LocalCommands::Log(LocalLogCommand::DeviceAlert { site: _, limit }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let payload = limit.map(|lim| serde_json::json!({ "pageSize": lim }));
            render_local(
                || client.system_log_device_alert(payload.as_ref()),
                output,
                render_opts,
                Some(&["timestamp", "key", "category", "subcategory", "message"]),
                watch,
            )
        }
        LocalCommands::Log(LocalLogCommand::AdminActivity { site: _, limit }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let payload = limit.map(|lim| serde_json::json!({ "pageSize": lim }));
            render_local(
                || client.system_log_admin_activity(payload.as_ref()),
                output,
                render_opts,
                Some(&["timestamp", "key", "category", "subcategory", "message"]),
                watch,
            )
        }
        LocalCommands::Wifi(LocalWifiCommand::Connectivity { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || client.wifi_connectivity(),
                output,
                render_opts,
                None,
                watch,
            )
        }
        LocalCommands::Wifi(LocalWifiCommand::Stats {
            site: _,
            radios,
            start,
            end,
            ap_mac,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            if radios {
                let query = serde_json::json!({
                    "start": start,
                    "end": end,
                });
                render_local(
                    || client.wifi_stats_radios(&query),
                    output,
                    render_opts,
                    None,
                    watch,
                )
            } else {
                let mut query_obj = serde_json::json!({
                    "start": start,
                    "end": end,
                });
                if let Some(ref mac) = ap_mac {
                    query_obj["apMac"] = serde_json::Value::String(mac.clone());
                } else {
                    query_obj["apMac"] = serde_json::Value::String("all".to_string());
                }
                render_local(
                    || client.wifi_stats_details(&query_obj),
                    output,
                    render_opts,
                    None,
                    watch,
                )
            }
        }
        LocalCommands::Wifi(LocalWifiCommand::RadioAi { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || client.radio_ai_isolation_matrix(),
                output,
                render_opts,
                None,
                watch,
            )
        }
        LocalCommands::Wifi(LocalWifiCommand::Management { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(|| client.wifiman(), output, render_opts, None, watch)
        }
        LocalCommands::Wifi(LocalWifiCommand::Config { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || client.wlan_enriched_config(),
                output,
                render_opts,
                None,
                watch,
            )
        }
        LocalCommands::Traffic(LocalTrafficCommand::Stats {
            site: _,
            start,
            end,
            include_unidentified,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let query = serde_json::json!({
                "start": start,
                "end": end,
                "includeUnidentified": include_unidentified,
            });
            render_local(
                || client.traffic_stats(&query),
                output,
                render_opts,
                None,
                watch,
            )
        }
        LocalCommands::Traffic(LocalTrafficCommand::FlowLatest {
            site: _,
            period,
            top,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let period_str = match period {
                FlowPeriod::Day => "DAY",
                FlowPeriod::Month => "MONTH",
            };
            let query = serde_json::json!({
                "period": period_str,
                "top": top,
            });
            render_local(
                || client.traffic_flow_latest(&query),
                output,
                render_opts,
                None,
                watch,
            )
        }
        LocalCommands::Traffic(LocalTrafficCommand::FilterData { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || client.traffic_flows_filter_data(),
                output,
                render_opts,
                None,
                watch,
            )
        }
        LocalCommands::Traffic(LocalTrafficCommand::Routes { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(|| client.traffic_routes(), output, render_opts, None, watch)
        }
        LocalCommands::Traffic(LocalTrafficCommand::Rules { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(|| client.traffic_rules(), output, render_opts, None, watch)
        }
        LocalCommands::Traffic(LocalTrafficCommand::AppRate {
            site: _,
            start,
            end,
            include_unidentified,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let query = serde_json::json!({
                "start": start,
                "end": end,
                "includeUnidentified": include_unidentified,
            });
            let payload = serde_json::json!({});
            render_local(
                move || client.app_traffic_rate(&payload, &query),
                output,
                render_opts,
                None,
                watch,
            )
        }
        LocalCommands::Traffic(LocalTrafficCommand::Flows { site: _, query }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let payload = query
                .map(|q| serde_json::from_str(&q).context("parsing query JSON"))
                .transpose()?;
            render_local(
                || client.traffic_flows_query(payload.as_ref()),
                output,
                render_opts,
                None,
                watch,
            )
        }
        LocalCommands::Stat(LocalStatCommand::Ccode { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(|| client.stat_ccode(), output, render_opts, None, watch)
        }
        LocalCommands::Stat(LocalStatCommand::CurrentChannel { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || client.stat_current_channel(),
                output,
                render_opts,
                None,
                watch,
            )
        }
        LocalCommands::Stat(LocalStatCommand::DeviceBasic { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || client.stat_device_basic(),
                output,
                render_opts,
                None,
                watch,
            )
        }
        LocalCommands::Stat(LocalStatCommand::Guest { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(|| client.stat_guest(), output, render_opts, None, watch)
        }
        LocalCommands::Stat(LocalStatCommand::Rogueap { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(|| client.stat_rogueap(), output, render_opts, None, watch)
        }
        LocalCommands::Stat(LocalStatCommand::Alarm {
            site: _,
            archived,
            limit,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || {
                    let mut resp = client.list_alarms(archived)?;
                    if let Some(mut json) = resp.json.clone() {
                        capture_collection(&mut json);
                        if let Some(arr) = json.get_mut("data").and_then(|d| d.as_array_mut())
                            && arr.len() > limit
                        {
                            arr.truncate(limit);
                        }
                        resp.body =
                            serde_json::to_string(&json).unwrap_or_else(|_| resp.body.clone());
                        resp.json = Some(json);
                    }
                    Ok(resp)
                },
                output,
                render_opts,
                Some(&["time", "key", "catname", "msg", "subsystem"]),
                watch,
            )
        }
        LocalCommands::Stat(LocalStatCommand::Sdn { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(|| client.stat_sdn(), output, render_opts, None, watch)
        }
        LocalCommands::Stat(LocalStatCommand::Report5min { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || client.stat_report_5min_ap(None),
                output,
                render_opts,
                None,
                watch,
            )
        }
        LocalCommands::Health(LocalHealthCommand::Get { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || {
                    let mut resp = client.list_health()?;
                    if let Some(mut json) = resp.json.clone() {
                        capture_collection(&mut json);
                        enrich_health_status_messages(&mut json);
                        resp.body =
                            serde_json::to_string(&json).unwrap_or_else(|_| resp.body.clone());
                        resp.json = Some(json);
                    }
                    Ok(resp)
                },
                output,
                render_opts,
                Some(&["subsystem", "status", "status_msg", "status_message"]),
                watch,
            )
        }
        LocalCommands::Vpn(LocalVpnCommand::Get { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || {
                    let mut resp = client.vpn_health()?;
                    if let Some(mut json) = resp.json.clone() {
                        capture_collection(&mut json);
                        enrich_health_status_messages(&mut json);
                        resp.body =
                            serde_json::to_string(&json).unwrap_or_else(|_| resp.body.clone());
                        resp.json = Some(json);
                    }
                    Ok(resp)
                },
                output,
                render_opts,
                Some(&["subsystem", "status", "status_msg", "status_message"]),
                watch,
            )
        }
        LocalCommands::Security(LocalSecurityCommand::Get { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || client.security_settings(),
                output,
                render_opts,
                None,
                watch,
            )
        }
        LocalCommands::Wan(LocalWanCommand::Get { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || {
                    let mut resp = client.list_health()?;
                    if let Some(mut json) = resp.json.clone()
                        && let Some(arr) = json.get_mut("data").and_then(|d| d.as_array_mut())
                    {
                        arr.retain(|item| {
                            item.get("subsystem")
                                .and_then(|v| v.as_str())
                                .map(|s| s.eq_ignore_ascii_case("wan"))
                                .unwrap_or(false)
                        });
                        enrich_health_status_messages(&mut json);
                        resp.body =
                            serde_json::to_string(&json).unwrap_or_else(|_| resp.body.clone());
                        resp.json = Some(json);
                    }
                    Ok(resp)
                },
                output,
                render_opts,
                Some(&["subsystem", "status", "status_msg", "status_message"]),
                watch,
            )
        }
        LocalCommands::Network(NetworkCommand::List) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || client.networks(),
                output,
                render_opts,
                Some(&[
                    "name",
                    "purpose",
                    "vlan_enabled",
                    "vlan",
                    "subnet",
                    "dhcpd_enabled",
                    "domain_name",
                ]),
                watch,
            )
        }
        LocalCommands::Wlan(WlanCommand::List) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || client.wlans(),
                output,
                render_opts,
                Some(&[
                    "name",
                    "essid",
                    "enabled",
                    "security",
                    "wpa3_support",
                    "mac_filter_enabled",
                ]),
                watch,
            )
        }
        LocalCommands::PortProfile(PortProfileCommand::List) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || client.port_profiles(),
                output,
                render_opts,
                Some(&["name", "autoneg", "op_mode", "poe_mode", "vlan"]),
                watch,
            )
        }
        LocalCommands::FirewallRule(FirewallRuleCommand::List) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || client.firewall_rules(),
                output,
                render_opts,
                Some(&[
                    "rule_index",
                    "name",
                    "enabled",
                    "action",
                    "rule_action",
                    "src_firewallgroup_ids",
                    "dst_firewallgroup_ids",
                ]),
                watch,
            )
        }
        LocalCommands::FirewallGroup(FirewallGroupCommand::List) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || client.firewall_groups(),
                output,
                render_opts,
                Some(&["name", "group_type", "group_members"]),
                watch,
            )
        }
        LocalCommands::Network(NetworkCommand::Create {
            name,
            vlan,
            subnet,
            dhcp,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let mut payload = serde_json::Map::new();
            payload.insert("name".into(), json!(name));
            payload.insert("purpose".into(), json!("corporate"));
            payload.insert("vlan_enabled".into(), json!(vlan.is_some()));
            if let Some(vlan) = vlan {
                payload.insert("vlan".into(), json!(vlan));
            }
            if let Some(subnet) = subnet {
                payload.insert("subnet".into(), json!(subnet));
            }
            payload.insert("dhcpd_enabled".into(), json!(dhcp));
            render_response(
                client.create_network(&serde_json::Value::Object(payload))?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::Network(NetworkCommand::Update {
            id,
            name,
            vlan,
            subnet,
            dhcp,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let mut payload = serde_json::Map::new();
            if let Some(name) = name {
                payload.insert("name".into(), json!(name));
            }
            if let Some(vlan) = vlan {
                payload.insert("vlan_enabled".into(), json!(true));
                payload.insert("vlan".into(), json!(vlan));
            }
            if let Some(subnet) = subnet {
                payload.insert("subnet".into(), json!(subnet));
            }
            if let Some(dhcp) = dhcp {
                payload.insert("dhcpd_enabled".into(), json!(dhcp));
            }
            if payload.is_empty() {
                return Err(anyhow!("Provide at least one field to update"));
            }
            render_response(
                client.update_network(&id, &serde_json::Value::Object(payload))?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::Network(NetworkCommand::Delete { id, dry_run, yes }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            if dry_run {
                // Fetch the network to show what would be deleted
                let networks = client.networks()?;
                if let Some(json) = networks.json
                    && let Some(data) = json.get("data").and_then(|d| d.as_array())
                    && let Some(network) = data.iter().find(|n| {
                        n.get("_id").and_then(|id| id.as_str()) == Some(&id)
                            || n.get("id").and_then(|id| id.as_str()) == Some(&id)
                    })
                {
                    println!("Would delete network:");
                    println!("{}", output::pretty_json(network)?);
                    return Ok(());
                }
                println!("Would delete network with ID: {}", id);
                println!("(Network details not found - may already be deleted)");
                Ok(())
            } else {
                // Fetch network name for confirmation
                let networks = client.networks()?;
                let network_name: Option<String> = if let Some(ref json) = networks.json {
                    json.get("data")
                        .and_then(|d| d.as_array())
                        .and_then(|arr| {
                            arr.iter().find(|n| {
                                n.get("_id").and_then(|id| id.as_str()) == Some(&id)
                                    || n.get("id").and_then(|id| id.as_str()) == Some(&id)
                            })
                        })
                        .and_then(|n| n.get("name").and_then(|n| n.as_str()))
                        .map(|s| s.to_string())
                } else {
                    None
                };

                if !confirm_deletion("network", &id, network_name.as_deref(), yes)? {
                    println!("Deletion cancelled.");
                    return Ok(());
                }
                render_response(client.delete_network(&id)?, output, render_opts, None)
            }
        }
        LocalCommands::Wlan(WlanCommand::Create {
            name,
            password,
            open,
            enabled,
        }) => {
            if !open && password.as_ref().is_none_or(|p| p.is_empty()) {
                return Err(anyhow!(
                    "Provide a nonempty --password or explicitly choose --open"
                ));
            }
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let mut payload = serde_json::Map::new();
            payload.insert("name".into(), json!(name));
            payload.insert("enabled".into(), json!(enabled));
            match password {
                Some(pass) => {
                    payload.insert("security".into(), json!("wpapsk"));
                    payload.insert("x_passphrase".into(), json!(pass));
                }
                None => {
                    payload.insert("security".into(), json!("open"));
                }
            }
            render_response(
                client.create_wlan(&serde_json::Value::Object(payload))?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::Wlan(WlanCommand::Update {
            id,
            name,
            password,
            enabled,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let mut payload = serde_json::Map::new();
            if let Some(name) = name {
                payload.insert("name".into(), json!(name));
            }
            if let Some(pass) = password {
                payload.insert("security".into(), json!("wpapsk"));
                payload.insert("x_passphrase".into(), json!(pass));
            }
            if let Some(enabled) = enabled {
                payload.insert("enabled".into(), json!(enabled));
            }
            if payload.is_empty() {
                return Err(anyhow!("Provide at least one field to update"));
            }
            render_response(
                client.update_wlan(&id, &serde_json::Value::Object(payload))?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::Wlan(WlanCommand::Delete { id, dry_run, yes }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            if dry_run {
                // Fetch the WLAN to show what would be deleted
                let wlans = client.wlans()?;
                if let Some(json) = wlans.json
                    && let Some(data) = json.get("data").and_then(|d| d.as_array())
                    && let Some(wlan) = data.iter().find(|w| {
                        w.get("_id").and_then(|id| id.as_str()) == Some(&id)
                            || w.get("id").and_then(|id| id.as_str()) == Some(&id)
                    })
                {
                    println!("Would delete WLAN:");
                    println!("{}", output::pretty_json(wlan)?);
                    return Ok(());
                }
                println!("Would delete WLAN with ID: {}", id);
                println!("(WLAN details not found - may already be deleted)");
                Ok(())
            } else {
                // Fetch WLAN name for confirmation
                let wlans = client.wlans()?;
                let wlan_name: Option<String> = if let Some(ref json) = wlans.json {
                    json.get("data")
                        .and_then(|d| d.as_array())
                        .and_then(|arr| {
                            arr.iter().find(|w| {
                                w.get("_id").and_then(|id| id.as_str()) == Some(&id)
                                    || w.get("id").and_then(|id| id.as_str()) == Some(&id)
                            })
                        })
                        .and_then(|w| {
                            w.get("name")
                                .or_else(|| w.get("essid"))
                                .and_then(|n| n.as_str())
                        })
                        .map(|s| s.to_string())
                } else {
                    None
                };

                if !confirm_deletion("WLAN", &id, wlan_name.as_deref(), yes)? {
                    println!("Deletion cancelled.");
                    return Ok(());
                }
                render_response(client.delete_wlan(&id)?, output, render_opts, None)
            }
        }
        LocalCommands::FirewallRule(FirewallRuleCommand::Create {
            name,
            action,
            src_group,
            dst_group,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let mut payload = serde_json::Map::new();
            payload.insert("name".into(), json!(name));
            payload.insert("enabled".into(), json!(true));
            payload.insert("action".into(), json!(action));
            payload.insert("rule_action".into(), json!(action));
            if let Some(src) = src_group {
                payload.insert("src_firewallgroup_ids".into(), json!([src]));
            }
            if let Some(dst) = dst_group {
                payload.insert("dst_firewallgroup_ids".into(), json!([dst]));
            }
            render_response(
                client.create_firewall_rule(&serde_json::Value::Object(payload))?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::FirewallRule(FirewallRuleCommand::Update {
            id,
            name,
            action,
            src_group,
            dst_group,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let mut payload = serde_json::Map::new();
            if let Some(name) = name {
                payload.insert("name".into(), json!(name));
            }
            if let Some(action) = action {
                payload.insert("action".into(), json!(action));
                payload.insert("rule_action".into(), json!(action));
            }
            if let Some(src) = src_group {
                payload.insert("src_firewallgroup_ids".into(), json!([src]));
            }
            if let Some(dst) = dst_group {
                payload.insert("dst_firewallgroup_ids".into(), json!([dst]));
            }
            if payload.is_empty() {
                return Err(anyhow!("Provide at least one field to update"));
            }
            render_response(
                client.update_firewall_rule(&id, &serde_json::Value::Object(payload))?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::FirewallRule(FirewallRuleCommand::Delete { id, dry_run, yes }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            if dry_run {
                // Fetch the firewall rule to show what would be deleted
                let rules = client.firewall_rules()?;
                if let Some(json) = rules.json
                    && let Some(data) = json.get("data").and_then(|d| d.as_array())
                    && let Some(rule) = data.iter().find(|r| {
                        r.get("_id").and_then(|id| id.as_str()) == Some(&id)
                            || r.get("id").and_then(|id| id.as_str()) == Some(&id)
                    })
                {
                    println!("Would delete firewall rule:");
                    println!("{}", output::pretty_json(rule)?);
                    return Ok(());
                }
                println!("Would delete firewall rule with ID: {}", id);
                println!("(Firewall rule details not found - may already be deleted)");
                Ok(())
            } else {
                // Fetch rule name for confirmation
                let rules = client.firewall_rules()?;
                let rule_name: Option<String> = if let Some(ref json) = rules.json {
                    json.get("data")
                        .and_then(|d| d.as_array())
                        .and_then(|arr| {
                            arr.iter().find(|r| {
                                r.get("_id").and_then(|id| id.as_str()) == Some(&id)
                                    || r.get("id").and_then(|id| id.as_str()) == Some(&id)
                            })
                        })
                        .and_then(|r| r.get("name").and_then(|n| n.as_str()))
                        .map(|s| s.to_string())
                } else {
                    None
                };

                if !confirm_deletion("firewall rule", &id, rule_name.as_deref(), yes)? {
                    println!("Deletion cancelled.");
                    return Ok(());
                }
                render_response(client.delete_firewall_rule(&id)?, output, render_opts, None)
            }
        }
        LocalCommands::FirewallGroup(FirewallGroupCommand::Create {
            name,
            group_type,
            members,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let mut payload = serde_json::Map::new();
            payload.insert("name".into(), json!(name));
            payload.insert("group_type".into(), json!(group_type));
            payload.insert("group_members".into(), json!(members.unwrap_or_default()));
            render_response(
                client.create_firewall_group(&serde_json::Value::Object(payload))?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::FirewallGroup(FirewallGroupCommand::Update { id, name, members }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let mut payload = serde_json::Map::new();
            if let Some(name) = name {
                payload.insert("name".into(), json!(name));
            }
            if let Some(members) = members {
                payload.insert("group_members".into(), json!(members));
            }
            if payload.is_empty() {
                return Err(anyhow!("Provide at least one field to update"));
            }
            render_response(
                client.update_firewall_group(&id, &serde_json::Value::Object(payload))?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::FirewallGroup(FirewallGroupCommand::Delete { id, dry_run, yes }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            if dry_run {
                // Fetch the firewall group to show what would be deleted
                let groups = client.firewall_groups()?;
                if let Some(json) = groups.json
                    && let Some(data) = json.get("data").and_then(|d| d.as_array())
                    && let Some(group) = data.iter().find(|g| {
                        g.get("_id").and_then(|id| id.as_str()) == Some(&id)
                            || g.get("id").and_then(|id| id.as_str()) == Some(&id)
                    })
                {
                    println!("Would delete firewall group:");
                    println!("{}", output::pretty_json(group)?);
                    return Ok(());
                }
                println!("Would delete firewall group with ID: {}", id);
                println!("(Firewall group details not found - may already be deleted)");
                Ok(())
            } else {
                // Fetch group name for confirmation
                let groups = client.firewall_groups()?;
                let group_name: Option<String> = if let Some(ref json) = groups.json {
                    json.get("data")
                        .and_then(|d| d.as_array())
                        .and_then(|arr| {
                            arr.iter().find(|g| {
                                g.get("_id").and_then(|id| id.as_str()) == Some(&id)
                                    || g.get("id").and_then(|id| id.as_str()) == Some(&id)
                            })
                        })
                        .and_then(|g| g.get("name").and_then(|n| n.as_str()))
                        .map(|s| s.to_string())
                } else {
                    None
                };

                if !confirm_deletion("firewall group", &id, group_name.as_deref(), yes)? {
                    println!("Deletion cancelled.");
                    return Ok(());
                }
                render_response(
                    client.delete_firewall_group(&id)?,
                    output,
                    render_opts,
                    None,
                )
            }
        }
        LocalCommands::TopClient(LocalTopClientCommand::List { site: _, limit }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || {
                    let mut resp = client.list_clients()?;
                    if let Some(mut json) = resp.json.clone() {
                        capture_collection(&mut json);
                        if let Some(arr) = json.get_mut("data").and_then(|d| d.as_array_mut()) {
                            let score = |item: &serde_json::Value| -> u128 {
                                let tx = item.get("tx_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                                let rx = item.get("rx_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                                tx as u128 + rx as u128
                            };
                            arr.sort_by_key(|item| std::cmp::Reverse(score(item)));
                            if arr.len() > limit {
                                arr.truncate(limit);
                            }
                        }
                        resp.body =
                            serde_json::to_string(&json).unwrap_or_else(|_| resp.body.clone());
                        resp.json = Some(json);
                    }
                    Ok(resp)
                },
                output,
                render_opts,
                Some(&[
                    "hostname", "mac", "ip", "ap_mac", "essid", "is_wired", "tx_bytes", "rx_bytes",
                ]),
                watch,
            )
        }
        LocalCommands::TopDevice(LocalTopDeviceCommand::List { site: _, limit }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || {
                    let mut resp = client.list_devices()?;
                    if let Some(mut json) = resp.json.clone() {
                        capture_collection(&mut json);
                        if let Some(arr) = json.get_mut("data").and_then(|d| d.as_array_mut()) {
                            let score = |item: &serde_json::Value| -> i64 {
                                item.get("num_sta")
                                    .and_then(|v| v.as_i64())
                                    .or_else(|| item.get("num_clients").and_then(|v| v.as_i64()))
                                    .unwrap_or(0)
                            };
                            arr.sort_by_key(|item| std::cmp::Reverse(score(item)));
                            if arr.len() > limit {
                                arr.truncate(limit);
                            }
                        }
                        resp.body =
                            serde_json::to_string(&json).unwrap_or_else(|_| resp.body.clone());
                        resp.json = Some(json);
                    }
                    Ok(resp)
                },
                output,
                render_opts,
                Some(&[
                    "name", "model", "type", "ip", "mac", "num_sta", "version", "state",
                ]),
                watch,
            )
        }
        LocalCommands::Dpi(LocalDpiCommand::Get { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || client.dpi(),
                output,
                render_opts,
                Some(&["app", "cat", "tx_bytes", "rx_bytes"]),
                watch,
            )
        }
        LocalCommands::PolicyTable(PolicyTableCommand::List) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || client.policy_tables(),
                output,
                render_opts,
                Some(&["name", "description", "enabled", "rules"]),
                watch,
            )
        }
        LocalCommands::PolicyTable(PolicyTableCommand::Create { name, description }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let mut payload = serde_json::Map::new();
            payload.insert("name".into(), json!(name));
            payload.insert("enabled".into(), json!(true));
            if let Some(desc) = description {
                payload.insert("description".into(), json!(desc));
            }
            render_response(
                client.create_policy_table(&serde_json::Value::Object(payload))?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::PolicyTable(PolicyTableCommand::Update {
            id,
            name,
            description,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let mut payload = serde_json::Map::new();
            if let Some(name) = name {
                payload.insert("name".into(), json!(name));
            }
            if let Some(desc) = description {
                payload.insert("description".into(), json!(desc));
            }
            if payload.is_empty() {
                return Err(anyhow!("Provide at least one field to update"));
            }
            render_response(
                client.update_policy_table(&id, &serde_json::Value::Object(payload))?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::PolicyTable(PolicyTableCommand::Delete { id, dry_run, yes }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            if dry_run {
                let tables = client.policy_tables()?;
                if let Some(json) = tables.json
                    && let Some(data) = json.get("data").and_then(|d| d.as_array())
                    && let Some(table) = data.iter().find(|t| {
                        t.get("_id").and_then(|id| id.as_str()) == Some(&id)
                            || t.get("id").and_then(|id| id.as_str()) == Some(&id)
                    })
                {
                    println!("Would delete policy table:");
                    println!("{}", output::pretty_json(table)?);
                    return Ok(());
                }
                println!("Would delete policy table with ID: {}", id);
                println!("(Policy table details not found - may already be deleted)");
                Ok(())
            } else {
                let tables = client.policy_tables()?;
                let table_name: Option<String> = if let Some(ref json) = tables.json {
                    json.get("data")
                        .and_then(|d| d.as_array())
                        .and_then(|arr| {
                            arr.iter().find(|t| {
                                t.get("_id").and_then(|id| id.as_str()) == Some(&id)
                                    || t.get("id").and_then(|id| id.as_str()) == Some(&id)
                            })
                        })
                        .and_then(|t| t.get("name").and_then(|n| n.as_str()))
                        .map(|s| s.to_string())
                } else {
                    None
                };

                if !confirm_deletion("policy table", &id, table_name.as_deref(), yes)? {
                    println!("Deletion cancelled.");
                    return Ok(());
                }
                render_response(client.delete_policy_table(&id)?, output, render_opts, None)
            }
        }
        LocalCommands::Zone(ZoneCommand::List) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || client.zones(),
                output,
                render_opts,
                Some(&["name", "description", "enabled", "interfaces"]),
                watch,
            )
        }
        LocalCommands::Zone(ZoneCommand::Create { name, description }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let mut payload = serde_json::Map::new();
            payload.insert("name".into(), json!(name));
            payload.insert("enabled".into(), json!(true));
            if let Some(desc) = description {
                payload.insert("description".into(), json!(desc));
            }
            render_response(
                client.create_zone(&serde_json::Value::Object(payload))?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::Zone(ZoneCommand::Update {
            id,
            name,
            description,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let mut payload = serde_json::Map::new();
            if let Some(name) = name {
                payload.insert("name".into(), json!(name));
            }
            if let Some(desc) = description {
                payload.insert("description".into(), json!(desc));
            }
            if payload.is_empty() {
                return Err(anyhow!("Provide at least one field to update"));
            }
            render_response(
                client.update_zone(&id, &serde_json::Value::Object(payload))?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::Zone(ZoneCommand::Delete { id, dry_run, yes }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            if dry_run {
                let zones = client.zones()?;
                if let Some(json) = zones.json
                    && let Some(data) = json.get("data").and_then(|d| d.as_array())
                    && let Some(zone) = data.iter().find(|z| {
                        z.get("_id").and_then(|id| id.as_str()) == Some(&id)
                            || z.get("id").and_then(|id| id.as_str()) == Some(&id)
                    })
                {
                    println!("Would delete zone:");
                    println!("{}", output::pretty_json(zone)?);
                    return Ok(());
                }
                println!("Would delete zone with ID: {}", id);
                println!("(Zone details not found - may already be deleted)");
                Ok(())
            } else {
                let zones = client.zones()?;
                let zone_name: Option<String> = if let Some(ref json) = zones.json {
                    json.get("data")
                        .and_then(|d| d.as_array())
                        .and_then(|arr| {
                            arr.iter().find(|z| {
                                z.get("_id").and_then(|id| id.as_str()) == Some(&id)
                                    || z.get("id").and_then(|id| id.as_str()) == Some(&id)
                            })
                        })
                        .and_then(|z| z.get("name").and_then(|n| n.as_str()))
                        .map(|s| s.to_string())
                } else {
                    None
                };

                if !confirm_deletion("zone", &id, zone_name.as_deref(), yes)? {
                    println!("Deletion cancelled.");
                    return Ok(());
                }
                render_response(client.delete_zone(&id)?, output, render_opts, None)
            }
        }
        LocalCommands::Object(ObjectCommand::List) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            render_local(
                || client.objects(),
                output,
                render_opts,
                Some(&["name", "type", "value", "description"]),
                watch,
            )
        }
        LocalCommands::Object(ObjectCommand::Create {
            name,
            object_type,
            value,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let mut payload = serde_json::Map::new();
            payload.insert("name".into(), json!(name));
            payload.insert("type".into(), json!(object_type));
            if let Some(val) = value {
                payload.insert("value".into(), json!(val));
            }
            render_response(
                client.create_object(&serde_json::Value::Object(payload))?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::Object(ObjectCommand::Update { id, name, value }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let mut payload = serde_json::Map::new();
            if let Some(name) = name {
                payload.insert("name".into(), json!(name));
            }
            if let Some(val) = value {
                payload.insert("value".into(), json!(val));
            }
            if payload.is_empty() {
                return Err(anyhow!("Provide at least one field to update"));
            }
            render_response(
                client.update_object(&id, &serde_json::Value::Object(payload))?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::Object(ObjectCommand::Delete { id, dry_run, yes }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            if dry_run {
                let objects = client.objects()?;
                if let Some(json) = objects.json
                    && let Some(data) = json.get("data").and_then(|d| d.as_array())
                    && let Some(obj) = data.iter().find(|o| {
                        o.get("_id").and_then(|id| id.as_str()) == Some(&id)
                            || o.get("id").and_then(|id| id.as_str()) == Some(&id)
                    })
                {
                    println!("Would delete object:");
                    println!("{}", output::pretty_json(obj)?);
                    return Ok(());
                }
                println!("Would delete object with ID: {}", id);
                println!("(Object details not found - may already be deleted)");
                Ok(())
            } else {
                let objects = client.objects()?;
                let object_name: Option<String> = if let Some(ref json) = objects.json {
                    json.get("data")
                        .and_then(|d| d.as_array())
                        .and_then(|arr| {
                            arr.iter().find(|o| {
                                o.get("_id").and_then(|id| id.as_str()) == Some(&id)
                                    || o.get("id").and_then(|id| id.as_str()) == Some(&id)
                            })
                        })
                        .and_then(|o| o.get("name").and_then(|n| n.as_str()))
                        .map(|s| s.to_string())
                } else {
                    None
                };

                if !confirm_deletion("object", &id, object_name.as_deref(), yes)? {
                    println!("Deletion cancelled.");
                    return Ok(());
                }
                render_response(client.delete_object(&id)?, output, render_opts, None)
            }
        }
        LocalCommands::Correlate(cmd) => {
            let effective = resolve_local(cwd, site_override(global_site.clone()))?;
            let mut client = LocalClient::from_config(&effective)?;
            handle_correlate_command(&cmd, &mut client, output, render_opts, global_site)?;
            Ok(())
        }
        LocalCommands::Diagnose(cmd) => {
            let effective = resolve_local(cwd, site_override(global_site.clone()))?;
            let mut client = LocalClient::from_config(&effective)?;
            handle_diagnose_command(&cmd, &mut client, output, render_opts, global_site)?;
            Ok(())
        }
        LocalCommands::TimeSeries(cmd) => {
            let effective = resolve_local(cwd, site_override(global_site.clone()))?;
            let mut client = LocalClient::from_config(&effective)?;
            handle_timeseries_command(&cmd, &mut client, output, render_opts, global_site)?;
            Ok(())
        }
        LocalCommands::Dns(LocalDnsCommand::List { site: _, limit }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let mut resp = client.list_dns_records()?;
            if let Some(mut json) = resp.json.clone() {
                capture_collection(&mut json);
                if let Some(arr) = json.get_mut("data").and_then(|d| d.as_array_mut())
                    && arr.len() > limit
                {
                    arr.truncate(limit);
                }
                resp.body = serde_json::to_string(&json).unwrap_or_else(|_| resp.body.clone());
                resp.json = Some(json);
            }
            render_response(
                resp,
                output,
                render_opts,
                Some(&["_id", "key", "record_type", "value", "enabled"]),
            )
        }
        LocalCommands::Dns(LocalDnsCommand::Add {
            host,
            value,
            record_type,
            disabled,
            site: _,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let payload = serde_json::json!({
                "key": host,
                "record_type": record_type,
                "value": value,
                "enabled": !disabled,
            });
            render_response(
                client.create_dns_record(&payload)?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::Dns(LocalDnsCommand::Update {
            id,
            host,
            value,
            record_type,
            enabled,
            disabled,
            site: _,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            if host.is_none() && value.is_none() && record_type.is_none() && !enabled && !disabled {
                anyhow::bail!(
                    "dns update requires at least one of --host, --value, --record-type, --enabled, --disabled"
                );
            }
            // UniFi's static-dns PUT requires a full-object body; fetch the existing
            // record and merge user-provided fields before sending.
            let existing = client.list_dns_records()?;
            let records = existing
                .json
                .as_ref()
                .and_then(|j| j.as_array())
                .ok_or_else(|| anyhow::anyhow!("unexpected list response shape"))?;
            let mut record = records
                .iter()
                .find(|r| r.get("_id").and_then(|v| v.as_str()) == Some(id.as_str()))
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no DNS record with id {id}"))?;
            let obj = record
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("record is not an object"))?;
            if let Some(h) = host {
                obj.insert("key".to_string(), serde_json::Value::String(h));
            }
            if let Some(v) = value {
                obj.insert("value".to_string(), serde_json::Value::String(v));
            }
            if let Some(rt) = record_type {
                obj.insert("record_type".to_string(), serde_json::Value::String(rt));
            }
            if enabled {
                obj.insert("enabled".to_string(), serde_json::Value::Bool(true));
            } else if disabled {
                obj.insert("enabled".to_string(), serde_json::Value::Bool(false));
            }
            render_response(
                client.update_dns_record(&id, &record)?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::Dns(LocalDnsCommand::Delete {
            id,
            site: _,
            dry_run,
            yes,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::from_config(&effective)?;
            let records = response_rows(&client.list_dns_records()?)?;
            let record = records.iter().find(|r| r["_id"] == id || r["id"] == id);
            if dry_run {
                return render_value(
                    json!({"action":"delete_dns_record", "dry_run":true, "id":id, "record":record}),
                    output,
                    render_opts,
                );
            }
            let name = record.and_then(|r| r.get("key")).and_then(|v| v.as_str());
            if !confirm_deletion("DNS record", &id, name, yes)? {
                return render_value(
                    json!({"action":"delete_dns_record", "id":id, "outcome":"cancelled"}),
                    output,
                    render_opts,
                );
            }
            render_response(client.delete_dns_record(&id)?, output, render_opts, None)
        }
    }
}

fn handle_correlate_command(
    cmd: &CorrelateCommand,
    client: &mut LocalClient,
    output: OutputFormat,
    render_opts: &RenderOpts,
    _default_site: Option<String>,
) -> Result<()> {
    use serde_json::json;

    match cmd {
        CorrelateCommand::Client {
            mac,
            site: _,
            include_events,
        } => {
            let mut correlated = json!({
                "correlation_type": "client",
                "mac": mac,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            });

            let clients = response_rows(&client.list_clients()?)?;
            correlated["client"] = clients
                .iter()
                .find(|c| {
                    c.get("mac")
                        .and_then(|m| m.as_str())
                        .is_some_and(|m| mac_matches(m, mac))
                })
                .cloned()
                .unwrap_or(json!(null));
            if let Some(ap_mac) = correlated["client"]["ap_mac"].as_str() {
                let devices = response_rows(&client.list_devices()?)?;
                correlated["connected_ap"] = devices
                    .iter()
                    .find(|d| {
                        d.get("mac")
                            .and_then(|m| m.as_str())
                            .is_some_and(|m| mac_matches(m, ap_mac))
                    })
                    .cloned()
                    .unwrap_or(json!(null));
            }

            // Optional collection is still observable when explicitly requested.
            if *include_events {
                match client.list_events_paged(50) {
                    Ok((response, stats)) => {
                        let events = response_rows(&response)?;
                        let relevant: Vec<_> = events
                            .into_iter()
                            .filter(|e| {
                                e.get("user").and_then(|v| v.as_str()) == Some(mac)
                                    || e.get("client_mac").and_then(|v| v.as_str()) == Some(mac)
                            })
                            .collect();
                        correlated["recent_events"] = json!(relevant);
                        correlated["events_collection"] = json!({"requested":50,"returned":stats.returned,"total_available":stats.total_available,"truncated":stats.truncated,"inventory_complete":"unknown","scope":"client matches in the most recent 50 events"});
                        if stats.truncated {
                            correlated["collection_error"] =
                                json!("Requested recent event range is incomplete");
                        }
                    }
                    Err(error) => {
                        correlated["collection_error"] = json!(terminal_safe(&format!("{error:#}")))
                    }
                }
            }

            correlated["llm_summary"] = json!({
                "has_client_data": !correlated["client"].is_null(),
                "is_wireless": !correlated["connected_ap"].is_null(),
                "event_count": correlated.get("recent_events")
                    .and_then(|e| e.as_array())
                    .map(|a| a.len()),
            });

            let incomplete = correlated.get("collection_error").is_some();
            correlated["collection_complete"] = json!(!incomplete);
            render_value(correlated, output, render_opts)?;
            if incomplete {
                Err(anyhow!(
                    "Requested correlation data could not be fully collected"
                ))
            } else {
                Ok(())
            }
        }
        CorrelateCommand::Device {
            mac,
            site: _,
            include_clients,
        } => {
            let mut correlated = json!({
                "correlation_type": "device",
                "mac": mac,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            });

            let devices = response_rows(&client.list_devices()?)?;
            correlated["device"] = devices
                .iter()
                .find(|d| {
                    d.get("mac")
                        .and_then(|m| m.as_str())
                        .is_some_and(|m| mac_matches(m, mac))
                })
                .cloned()
                .unwrap_or(json!(null));
            if *include_clients {
                let clients = response_rows(&client.list_clients()?)?;
                let connected: Vec<_> = clients
                    .into_iter()
                    .filter(|c| {
                        c.get("ap_mac")
                            .or_else(|| c.get("sw_mac"))
                            .and_then(|v| v.as_str())
                            .is_some_and(|m| mac_matches(m, mac))
                    })
                    .collect();
                correlated["connected_clients_count"] = json!(connected.len());
                correlated["connected_clients"] = json!(connected);
            }

            correlated["llm_summary"] = json!({
                "has_device_data": !correlated["device"].is_null(),
                "device_type": correlated["device"]["type"].as_str().unwrap_or("unknown"),
                "client_count": correlated.get("connected_clients_count").and_then(|c| c.as_u64()),
            });

            render_response(
                ResponseData {
                    status: 200,
                    body: serde_json::to_string(&correlated)?,
                    json: Some(correlated),
                },
                output,
                render_opts,
                None,
            )
        }
        CorrelateCommand::Ap { ap_mac, site: _ } => {
            // Reuse Device correlation logic
            let device_cmd = CorrelateCommand::Device {
                mac: ap_mac.clone(),
                site: None,
                include_clients: true,
            };
            handle_correlate_command(&device_cmd, client, output, render_opts, None)
        }
    }
}

fn handle_diagnose_command(
    cmd: &DiagnoseCommand,
    client: &mut LocalClient,
    output: OutputFormat,
    render_opts: &RenderOpts,
    _default_site: Option<String>,
) -> Result<()> {
    let mut checks = Vec::new();
    let kind = match cmd {
        DiagnoseCommand::Network { .. } => {
            match client.list_health().and_then(|r| response_rows(&r)) {
                Ok(health) => {
                    let healthy = !health.is_empty() && health.iter().all(|h| h["status"] == "ok");
                    let wan = health.iter().find(|h| h["subsystem"] == "wan");
                    checks.push(json!({"name":"Health", "status":if healthy {"pass"} else {"unknown_or_fail"}, "data":health}));
                    checks.push(json!({"name":"WAN", "status":match wan { Some(w) if w["status"] == "ok" => "pass", Some(_) => "fail", None => "unknown" }}));
                }
                Err(error) => {
                    checks.push(json!({"name":"Health", "status":"error", "error":terminal_safe(&format!("{error:#}"))}));
                    checks.push(json!({"name":"WAN", "status":"unknown", "error":"Health collection failed"}));
                }
            }
            match client.list_devices().and_then(|r| response_rows(&r)) {
                Ok(devices) => checks.push(json!({"name":"Devices", "status":"collected", "device_count":devices.len()})),
                Err(error) => checks.push(json!({"name":"Devices", "status":"error", "error":terminal_safe(&format!("{error:#}"))})),
            }
            "network"
        }
        DiagnoseCommand::Wifi { .. } => {
            match client.wifi_connectivity().and_then(|response| {
                let data = response.json.ok_or_else(|| anyhow!("Missing WiFi connectivity JSON"))?;
                if !data.is_object() && !data.is_array() { return Err(anyhow!("Invalid WiFi connectivity response shape")); }
                Ok(data)
            }) {
                Ok(data) => checks.push(json!({"name":"Connectivity", "status":"collected", "data":data})),
                Err(error) => checks.push(json!({"name":"Connectivity", "status":"error", "error":terminal_safe(&format!("{error:#}"))})),
            }
            match client.list_devices().and_then(|r| response_rows(&r)) {
                Ok(devices) => {
                    let aps: Vec<_> = devices.iter().filter(|d| d["type"] == "uap").map(|d| json!({"mac":d.get("mac"),"name":d.get("name"),"state":d.get("state"),"num_sta":d.get("num_sta")})).collect();
                    checks.push(json!({"name":"Access points", "status":"collected", "ap_count":aps.len(), "data":aps}));
                }
                Err(error) => checks.push(json!({"name":"Access points", "status":"error", "error":terminal_safe(&format!("{error:#}"))})),
            }
            "wifi"
        }
        DiagnoseCommand::Client { mac: Some(mac), .. } => {
            return handle_correlate_command(
                &CorrelateCommand::Client {
                    mac: mac.clone(),
                    site: None,
                    include_events: true,
                },
                client,
                output,
                render_opts,
                None,
            );
        }
        DiagnoseCommand::Client { mac: None, .. } => {
            match client.list_clients().and_then(|r| response_rows(&r)) {
                Ok(clients) => {
                    let wired = clients.iter().filter(|c| c["is_wired"] == true).count();
                    checks.push(json!({"name":"Clients", "status":"collected", "total_clients":clients.len(), "wired_clients":wired, "wireless_clients":clients.len()-wired}));
                }
                Err(error) => checks.push(json!({"name":"Clients", "status":"error", "error":terminal_safe(&format!("{error:#}"))})),
            }
            "client_overview"
        }
    };
    let collection_failed = checks.iter().any(|c| c["status"] == "error");
    let unsuccessful = checks
        .iter()
        .any(|c| c["status"] != "pass" && c["status"] != "collected");
    let result = json!({
        "diagnostic_type":kind, "timestamp":chrono::Utc::now().to_rfc3339(),
        "checks":checks, "collection_complete":!collection_failed,
        "outcome":if collection_failed {"incomplete"} else if unsuccessful {"unhealthy_or_unknown"} else {"collected"},
        "llm_summary":{"total_checks":checks.len(), "errors":checks.iter().filter(|c| c["status"] == "error").count(), "recommendation":"Collected means the request succeeded; inspect health statuses and do not infer missing data is healthy"}
    });
    render_value(result, output, render_opts)?;
    if unsuccessful {
        Err(anyhow!(
            "Diagnostics contain failed, unknown or incomplete checks"
        ))
    } else {
        Ok(())
    }
}

fn handle_timeseries_command(
    cmd: &TimeSeriesCommand,
    client: &mut LocalClient,
    _output: OutputFormat,
    render_opts: &RenderOpts,
    _default_site: Option<String>,
) -> Result<()> {
    use serde_json::json;

    match cmd {
        TimeSeriesCommand::Traffic {
            start,
            end,
            site: _,
            format,
        } => {
            let query = json!({
                "start": start,
                "end": end,
                "includeUnidentified": true,
            });

            let stats = client.traffic_stats(&query)?;

            if format == "csv" {
                render_response(
                    stats,
                    OutputFormat::Csv,
                    render_opts,
                    Some(&["time", "rx_bytes", "tx_bytes"]),
                )?;
            } else {
                render_response(stats, OutputFormat::Json, render_opts, None)?;
            }
            Ok(())
        }
        TimeSeriesCommand::Wifi {
            start,
            end,
            ap_mac,
            site: _,
            format,
        } => {
            let query = json!({
                "start": start,
                "end": end,
                "apMac": ap_mac.as_deref().unwrap_or("all"),
            });
            let stats = client.wifi_stats_details(&query)?;

            if format == "csv" {
                render_response(
                    stats,
                    OutputFormat::Csv,
                    render_opts,
                    Some(&["time", "ap_mac", "channel", "num_sta", "satisfaction"]),
                )?;
            } else {
                render_response(stats, OutputFormat::Json, render_opts, None)?;
            }
            Ok(())
        }
        TimeSeriesCommand::Events {
            limit,
            site: _,
            format,
        } => {
            let (mut events, stats) = client.list_events_paged(limit.unwrap_or(100))?;
            attach_paged_metadata(&mut events, stats)?;
            let value = events
                .json
                .as_mut()
                .ok_or_else(|| anyhow!("Missing event JSON"))?;
            let rows = list_payload_mut(value).ok_or_else(|| anyhow!("Missing event array"))?;
            for event in rows {
                let timestamp = event
                    .get("timestamp")
                    .or_else(|| event.get("time"))
                    .or_else(|| event.get("datetime"))
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                let timestamp_format = if timestamp
                    .as_str()
                    .is_some_and(|s| chrono::DateTime::parse_from_rfc3339(s).is_ok())
                {
                    "rfc3339"
                } else if timestamp.is_number() {
                    "controller_numeric"
                } else {
                    "unknown"
                };
                let message = event
                    .get("message_raw")
                    .or_else(|| event.get("msg"))
                    .or_else(|| event.get("message"))
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                let category = event
                    .get("category")
                    .or_else(|| event.get("subsystem"))
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                event["timestamp"] = timestamp;
                event["timestamp_format"] = json!(timestamp_format);
                event["message"] = message;
                event["category"] = category;
            }
            events.body = serde_json::to_string(value)?;
            render_response(
                events,
                if format == "csv" {
                    OutputFormat::Csv
                } else {
                    OutputFormat::Json
                },
                render_opts,
                Some(&[
                    "timestamp",
                    "timestamp_format",
                    "datetime",
                    "key",
                    "message",
                    "category",
                ]),
            )?;
            if stats.truncated {
                return Err(anyhow!(
                    "Event export could not retrieve the requested range"
                ));
            }
            Ok(())
        }
    }
}

fn attach_paged_metadata(response: &mut ResponseData, stats: local::PagedFetch) -> Result<()> {
    let value = response
        .json
        .as_mut()
        .ok_or_else(|| anyhow!("Missing paginated JSON"))?;
    capture_collection(value);
    value["_unifictl"]["collection"] = json!({
        "requested":stats.requested,"source_count":stats.returned,"returned_count":stats.returned,
        "total_available":stats.total_available,"requested_range_complete":!stats.truncated,
        "truncated":stats.truncated || stats.total_available.is_some_and(|n| n > stats.returned),
        "inventory_complete":if stats.truncated || stats.total_available.is_some_and(|n| n > stats.returned) {"incomplete"} else if stats.total_available == Some(stats.returned) {"complete"} else {"unknown"}
    });
    response.body = serde_json::to_string(value)?;
    Ok(())
}

/// Retain only the client records whose `mac` field matches `mac`.
///
/// Returns `true` when at least one record survived, so callers can report a
/// clean "no matching client" instead of rendering an empty table.
fn retain_clients_with_mac(arr: &mut Vec<serde_json::Value>, mac: &str) -> bool {
    arr.retain(|item| {
        item.get("mac")
            .and_then(|m| m.as_str())
            .map(|m| mac_matches(m, mac))
            .unwrap_or(false)
    });
    !arr.is_empty()
}

/// Truncate a list payload to `limit`, telling the user on stderr when rows
/// were dropped.
///
/// Silent truncation is indistinguishable from "that is all there is", which
/// is exactly how a capped result set turns into a wrong conclusion. The
/// notice goes to stderr so `-o json` output stays machine-parseable.
fn truncate_with_warning(arr: &mut Vec<serde_json::Value>, limit: usize, resource: &str) {
    let total = arr.len();
    if total > limit {
        arr.truncate(limit);
        eprintln!(
            "Warning: showing {limit} of {total} {resource} — output truncated by --limit. \
             Re-run with --limit {total} (or higher) to see them all."
        );
    }
}

fn render_local<F>(
    mut fetch: F,
    output: OutputFormat,
    render_opts: &RenderOpts,
    columns: Option<&[&str]>,
    watch: Option<u64>,
) -> Result<()>
where
    F: FnMut() -> Result<ResponseData>,
{
    if let Some(interval) = watch {
        let mut first_run = true;
        loop {
            let resp = fetch()?;
            // Clear screen on subsequent runs (not the first)
            if !first_run && output == OutputFormat::Pretty {
                // Clear screen: ESC[2J moves cursor to top, ESC[H moves to home
                print!("\x1b[2J\x1b[H");
            }
            first_run = false;

            // Print timestamp for watch mode
            if output == OutputFormat::Pretty {
                let now = chrono::Utc::now();
                println!("Collected: {}\n", now.to_rfc3339());
            }

            render_response(resp, output, render_opts, columns)?;

            // Print instructions for exiting
            if output == OutputFormat::Pretty {
                println!("\n(Press Ctrl+C to stop watching)");
            }

            std::thread::sleep(std::time::Duration::from_secs(interval));
        }
    } else {
        render_response(fetch()?, output, render_opts, columns)
    }
}

fn confirm_deletion(
    resource_type: &str,
    resource_id: &str,
    resource_name: Option<&str>,
    yes: bool,
) -> Result<bool> {
    if yes {
        return Ok(true);
    }

    let name_part = if let Some(name) = resource_name {
        format!(" \"{}\"", terminal_safe(name))
    } else {
        String::new()
    };

    eprint!(
        "Are you sure you want to delete {}{} (ID: {})? [y/N]: ",
        terminal_safe(resource_type),
        name_part,
        terminal_safe(resource_id)
    );
    io::stderr().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    Ok(input.trim().to_lowercase() == "y" || input.trim().to_lowercase() == "yes")
}

fn site_override(site: Option<String>) -> Option<LocalConfig> {
    site.map(|s| LocalConfig {
        url: None,
        username: None,
        password: None,
        site: Some(s),
        verify_tls: None,
        ca_file: None,
        port_fallback: None,
    })
}

fn run_get(
    client: &ApiClient,
    path: &str,
    query: Vec<(&str, String)>,
    output: OutputFormat,
    render_opts: &RenderOpts,
    columns: Option<&[&str]>,
    watch: Option<u64>,
) -> Result<()> {
    if let Some(interval) = watch {
        let mut first_run = true;
        loop {
            let response = client.get(path, &query)?;
            // Clear screen on subsequent runs (not the first)
            if !first_run && output == OutputFormat::Pretty {
                // Clear screen: ESC[2J moves cursor to top, ESC[H moves to home
                print!("\x1b[2J\x1b[H");
            }
            first_run = false;

            // Print timestamp for watch mode
            if output == OutputFormat::Pretty {
                let now = chrono::Utc::now();
                println!("Collected: {}\n", now.to_rfc3339());
            }

            render_response(response, output, render_opts, columns)?;

            // Print instructions for exiting
            if output == OutputFormat::Pretty {
                println!("\n(Press Ctrl+C to stop watching)");
            }

            std::thread::sleep(std::time::Duration::from_secs(interval));
        }
    } else {
        let response = client.get(path, &query)?;
        render_response(response, output, render_opts, columns)
    }
}

fn run_post(
    client: &ApiClient,
    path: &str,
    query: Vec<(&str, String)>,
    body: serde_json::Value,
    output: OutputFormat,
    render_opts: &RenderOpts,
    columns: Option<&[&str]>,
) -> Result<()> {
    let response = client.post_json(path, &query, Some(&body))?;
    render_response(response, output, render_opts, columns)
}

fn render_response(
    mut response: ResponseData,
    output: OutputFormat,
    render_opts: &RenderOpts,
    columns: Option<&[&str]>,
) -> Result<()> {
    if output == OutputFormat::Raw && response.json.is_none() {
        println!("{}", response.body);
        return Ok(());
    }
    let mut json = match response.json.take() {
        Some(json) => json,
        None if response.status == 204 && response.body.trim().is_empty() => json!({
            "outcome":"accepted",
            "verification":"unverified",
            "message":"The controller accepted the request without a response body; read back state before further actions"
        }),
        None => {
            return Err(anyhow!(
                "Invalid response: expected JSON for structured or pretty output"
            ));
        }
    };
    if !json.is_object() && !json.is_array() {
        json = json!({"data":json});
    }
    finish_collection(&mut json);
    if json.get("_unifictl").is_none() {
        json["_unifictl"] = json!({});
    }
    json["_unifictl"]["collected_at"] = json!(chrono::Utc::now().to_rfc3339());
    json["_unifictl"]["target"] = json!(render_opts.target);
    json["_unifictl"]["site"] = json!(render_opts.site);
    json["_unifictl"]["http_status"] = json!(response.status);
    json["_unifictl"]["untrusted_controller_data"] = json!(true);
    match output {
        OutputFormat::Json | OutputFormat::Raw => println!("{}", serde_json::to_string(&json)?),
        OutputFormat::Pretty => {
            let collection = &json["_unifictl"]["collection"];
            if collection["truncated"] == true {
                eprintln!(
                    "Warning: incomplete collection after filtering or limits ({} returned, {} collected, total {}). Use -o json for collection metadata.",
                    collection["returned_count"],
                    collection["source_count"],
                    collection["total_available"]
                        .as_u64()
                        .map_or_else(|| "unknown".to_string(), |n| n.to_string()),
                );
            }
            if !print_table(&json, columns, render_opts) {
                println!("{}", output::pretty_json(&json)?);
            }
        }
        OutputFormat::Csv => print_csv(&json, columns, render_opts)?,
        OutputFormat::Llm => print_llm(&json, render_opts.schema)?,
    }
    Ok(())
}

fn print_csv(
    json: &serde_json::Value,
    columns_hint: Option<&[&str]>,
    render_opts: &RenderOpts,
) -> Result<()> {
    use csv::Writer;
    use std::io;

    let rows = match json {
        serde_json::Value::Array(arr) => arr,
        serde_json::Value::Object(map) => match map.get("data") {
            Some(serde_json::Value::Array(arr)) => arr,
            _ => {
                // If not array format, output as JSON
                println!("{}", serde_json::to_string(json)?);
                return Ok(());
            }
        },
        _ => {
            println!("{}", serde_json::to_string(json)?);
            return Ok(());
        }
    };

    if rows.is_empty() {
        eprintln!(
            "{}",
            serde_json::to_string(&json!({"_unifictl":json["_unifictl"]}))?
        );
        if let Some(columns) = columns_hint {
            let mut writer = Writer::from_writer(io::stdout());
            writer.write_record(columns.iter().map(|column| spreadsheet_safe(column)))?;
            writer.flush()?;
        }
        return Ok(());
    }

    let first_obj = match &rows[0] {
        serde_json::Value::Object(map) => map,
        _ => {
            println!("{}", serde_json::to_string(json)?);
            return Ok(());
        }
    };

    let mut csv_columns: Vec<String> = Vec::new();

    if let Some(override_cols) = &render_opts.columns_override {
        for key in override_cols {
            if rows
                .iter()
                .any(|row| row.get(key).map(is_non_empty).unwrap_or(false))
            {
                csv_columns.push(key.to_string());
            }
        }
    }

    if csv_columns.is_empty()
        && let Some(hint) = columns_hint
    {
        for key in hint {
            if rows
                .iter()
                .any(|row| row.get(key).map(is_non_empty).unwrap_or(false))
            {
                csv_columns.push((*key).to_string());
            }
        }
    }

    if csv_columns.is_empty() {
        // Auto-select up to 8 non-empty fields
        for key in first_obj.keys() {
            if rows
                .iter()
                .any(|row| row.get(key).map(is_non_empty).unwrap_or(false))
            {
                csv_columns.push(key.to_string());
            }
            if csv_columns.len() >= 8 {
                break;
            }
        }
    }

    // Always include id if present
    if !csv_columns.contains(&"id".to_string())
        && rows
            .iter()
            .any(|row| row.get("id").map(is_non_empty).unwrap_or(false))
    {
        csv_columns.push("id".to_string());
    }

    if csv_columns.is_empty() {
        println!("{}", serde_json::to_string(json)?);
        return Ok(());
    }

    let mut wtr = Writer::from_writer(io::stdout());

    // Write header
    wtr.write_record(csv_columns.iter().map(|column| spreadsheet_safe(column)))?;

    // Filter rows if needed
    let needle = render_opts.filter.as_ref().map(|f| f.to_ascii_lowercase());

    // Compile regex if provided
    let regex_pattern = if let Some(pattern) = &render_opts.filter_regex {
        match RegexBuilder::new(pattern).case_insensitive(true).build() {
            Ok(re) => Some(re),
            Err(e) => {
                eprintln!("Warning: Invalid regex pattern '{}': {}", pattern, e);
                None
            }
        }
    } else {
        None
    };

    let mut filtered_rows: Vec<&serde_json::Value> = rows.iter().collect();

    filtered_rows.retain(|row| {
        if let serde_json::Value::Object(map) = row {
            let mut matches = true;

            // Apply text filter
            if let Some(needle) = &needle
                && !csv_columns.iter().any(|col| {
                    map.get(col)
                        .map(|v| value_to_str(v).to_ascii_lowercase().contains(needle))
                        .unwrap_or(false)
                })
            {
                matches = false;
            }

            // Apply regex filter
            if let Some(ref re) = regex_pattern
                && !csv_columns.iter().any(|col| {
                    map.get(col)
                        .map(|v| re.is_match(&value_to_str(v)))
                        .unwrap_or(false)
                })
            {
                matches = false;
            }

            matches
        } else {
            false
        }
    });

    // Sort if needed
    if let Some(sort) = render_opts.sort_by.as_ref()
        && let Some(idx) = csv_columns.iter().position(|c| c == sort)
    {
        filtered_rows.sort_by(|a, b| {
            if let (serde_json::Value::Object(a_map), serde_json::Value::Object(b_map)) = (a, b) {
                let a_val = a_map
                    .get(&csv_columns[idx])
                    .map(value_to_str)
                    .unwrap_or_default();
                let b_val = b_map
                    .get(&csv_columns[idx])
                    .map(value_to_str)
                    .unwrap_or_default();
                a_val.cmp(&b_val)
            } else {
                std::cmp::Ordering::Equal
            }
        });
    }

    let mut metadata = json["_unifictl"].clone();
    if filtered_rows.len() < rows.len() {
        metadata["collection"]["returned_count"] = json!(filtered_rows.len());
        metadata["collection"]["presentation_filtered"] = json!(true);
        metadata["collection"]["inventory_complete"] = json!("incomplete");
        metadata["collection"]["truncated"] = json!(true);
    }
    metadata["csv_profile"] = json!("spreadsheet_safe");
    eprintln!("{}", serde_json::to_string(&json!({"_unifictl":metadata}))?);
    // Write rows
    for row in filtered_rows {
        if let serde_json::Value::Object(map) = row {
            let mut record = Vec::new();
            for col in &csv_columns {
                let value = map.get(col).unwrap_or(&serde_json::Value::Null);
                record.push(if value.is_string() {
                    spreadsheet_safe(&value_to_str(value))
                } else {
                    value_to_str(value)
                });
            }
            wtr.write_record(&record)?;
        }
    }

    wtr.flush()?;
    Ok(())
}

fn print_llm(json: &serde_json::Value, schema_name: Option<&str>) -> Result<()> {
    use serde_json::json;

    // Initialize schema registry
    let registry = SchemaRegistry::new();

    // Estimate tokens for the full response
    let total_tokens = estimate_tokens(json);

    // Determine if this is an array or object response
    let (data_type, item_count, data) = match json {
        serde_json::Value::Array(arr) => ("array", arr.len(), json.clone()),
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::Array(arr)) = map.get("data") {
                ("array_wrapped", arr.len(), map.get("data").unwrap().clone())
            } else {
                ("object", 1, json.clone())
            }
        }
        _ => ("primitive", 1, json.clone()),
    };

    // Create LLM-optimized output
    let mut llm_output = json!({
        "llm_metadata": {
            "version": "1.0",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "estimated_tokens": total_tokens,
            "data_type": data_type,
            "item_count": item_count,
            "truncation_applied": json["_unifictl"]["collection"]["truncated"].as_bool().unwrap_or(false),
            "sampling_applied": false,
            "ai_guidance": {
                "summary": format!("Response contains {} items with ~{} tokens", item_count, total_tokens),
                "recommended_max_tokens": 4000,
                "token_efficient": total_tokens < 4000,
            }
        }
    });

    // Add schema information if available (try to infer endpoint)
    // This is a simple heuristic - in practice, you'd pass context about which endpoint was called
    let schema = schema_name.and_then(|name| registry.get(name));
    if let Some(schema) = schema {
        llm_output["schema"] = json!({
            "name": schema.name,
            "description": schema.description,
            "use_cases": schema.use_cases,
            "important_fields": schema.fields.iter()
                .filter(|f| f.importance == crate::schema::Importance::High)
                .map(|f| json!({
                    "name": f.name,
                    "type": f.field_type,
                    "description": f.description,
                }))
                .collect::<Vec<_>>(),
        });
    }

    llm_output["_unifictl"] = json["_unifictl"].clone();
    llm_output["summary"] = summarize_response(&data, schema);

    // Intelligent truncation for large responses
    const MAX_TOKENS: usize = 4000;
    const SAMPLE_SIZE: usize = 5;

    if total_tokens > MAX_TOKENS {
        if let serde_json::Value::Array(arr) = &data {
            // For arrays, show samples from beginning, middle, and end
            let mut samples = Vec::new();

            // First N items
            for (idx, item) in arr.iter().take(SAMPLE_SIZE).enumerate() {
                samples.push(json!({
                    "position": "start",
                    "index": idx,
                    "data": item,
                }));
            }

            // Middle items (if array is large enough)
            if arr.len() > SAMPLE_SIZE * 3 {
                let mid = arr.len() / 2;
                for (offset, item) in arr.iter().skip(mid).take(SAMPLE_SIZE).enumerate() {
                    samples.push(json!({
                        "position": "middle",
                        "index": mid + offset,
                        "data": item,
                    }));
                }
            }

            // Last N items
            if arr.len() > SAMPLE_SIZE {
                for (offset, item) in arr.iter().rev().take(SAMPLE_SIZE).enumerate() {
                    samples.push(json!({
                        "position": "end",
                        "index": arr.len() - 1 - offset,
                        "data": item,
                    }));
                }
            }

            let sampled = samples.len() < arr.len();
            llm_output["llm_metadata"]["sampling_applied"] = json!(sampled);
            if sampled {
                llm_output["llm_metadata"]["truncation_applied"] = json!(true);
            }
            llm_output["data_samples"] = json!(samples);
            llm_output["llm_metadata"]["truncation_note"] = json!(format!(
                "Original response had {} items. Showing {} representative samples. Use --limit flag to control output size.",
                arr.len(),
                samples.len()
            ));
        } else {
            // For objects, include the whole thing but warn about size
            llm_output["data"] = data.clone();
            llm_output["llm_metadata"]["truncation_note"] = json!(
                "Large object response included in full. Consider using filters to reduce size."
            );
        }
    } else {
        // Response is small enough, include everything
        llm_output["data"] = data.clone();
    }

    // Add statistics for array responses
    if let serde_json::Value::Array(arr) = &data
        && !arr.is_empty()
    {
        // Extract field statistics
        let mut field_types: std::collections::HashMap<String, u32> =
            std::collections::HashMap::new();

        for item in arr.iter() {
            if let serde_json::Value::Object(obj) = item {
                for key in obj.keys() {
                    *field_types.entry(key.clone()).or_insert(0) += 1;
                }
            }
        }

        llm_output["statistics"] = json!({
            "total_items": arr.len(),
            "common_fields": field_types.iter()
                .filter(|(_, count)| **count == arr.len() as u32)
                .map(|(k, _)| k)
                .collect::<Vec<_>>(),
            "field_coverage": field_types,
        });
    }

    println!("{}", serde_json::to_string_pretty(&llm_output)?);
    Ok(())
}

fn print_table(
    json: &serde_json::Value,
    columns_hint: Option<&[&str]>,
    render_opts: &RenderOpts,
) -> bool {
    let rows = match json {
        serde_json::Value::Array(arr) => arr,
        serde_json::Value::Object(map) => match map.get("data") {
            Some(serde_json::Value::Array(arr)) => arr,
            _ => return false,
        },
        _ => return false,
    };

    if rows.is_empty() {
        let has_filter = render_opts.filter.is_some();
        if has_filter {
            println!("No resources found matching your filter.");
            println!("\nThis could mean:");
            println!("  • No resources match the filter criteria");
            println!("  • Try removing the filter or adjusting your search");
        } else {
            println!("No resources found.");
            println!("\nThis could mean:");
            println!("  • No resources exist for this query");
            println!("  • Resources may be filtered by other criteria");
        }
        println!("\nTry:");
        println!("  • Checking with JSON output: -o json");
        println!("  • Verifying your query parameters");
        return true;
    }

    let first_obj = match &rows[0] {
        serde_json::Value::Object(map) => map,
        _ => return false,
    };

    let mut columns: Vec<String> = Vec::new();

    if let Some(override_cols) = &render_opts.columns_override {
        for key in override_cols {
            if rows
                .iter()
                .any(|row| row.get(key).map(is_non_empty).unwrap_or(false))
            {
                columns.push(key.to_string());
            }
        }
    }

    if columns.is_empty()
        && let Some(hint) = columns_hint
    {
        for key in hint {
            if rows
                .iter()
                .any(|row| row.get(key).map(is_non_empty).unwrap_or(false))
            {
                columns.push((*key).to_string());
            }
        }
    }

    if columns.is_empty() {
        // Auto-select up to 8 non-empty fields present in the first object, preferring ones with values.
        for key in first_obj.keys() {
            if rows
                .iter()
                .any(|row| row.get(key).map(is_non_empty).unwrap_or(false))
            {
                columns.push(key.to_string());
            }
            if columns.len() >= 8 {
                break;
            }
        }
    }

    // Always include id if present and not already included.
    if !columns.contains(&"id".to_string())
        && rows
            .iter()
            .any(|row| row.get("id").map(is_non_empty).unwrap_or(false))
    {
        columns.push("id".to_string());
    }

    if columns.is_empty() {
        return false;
    }

    let mut widths: Vec<usize> = columns.iter().map(|c| c.len()).collect();
    let mut table: Vec<Vec<String>> = Vec::new();
    let needle = render_opts.filter.as_ref().map(|f| f.to_ascii_lowercase());

    // Compile regex if provided
    let regex_pattern = if let Some(pattern) = &render_opts.filter_regex {
        match regex::RegexBuilder::new(pattern)
            .case_insensitive(true)
            .build()
        {
            Ok(re) => Some(re),
            Err(e) => {
                eprintln!("Warning: Invalid regex pattern '{}': {}", pattern, e);
                None
            }
        }
    } else {
        None
    };

    for row in rows {
        if let serde_json::Value::Object(map) = row {
            let mut out_row = Vec::new();
            for col in columns.iter() {
                let value = map.get(col).unwrap_or(&serde_json::Value::Null);
                let mut rendered = terminal_safe(&value_to_str(value));
                if col == "id" && !*FULL_IDS.get().unwrap_or(&false) && rendered.len() > 12 {
                    rendered = format!("{}…", rendered.chars().take(12).collect::<String>());
                }
                out_row.push(rendered);
            }

            // Apply filters
            let mut matches = true;

            if let Some(needle) = &needle
                && !out_row
                    .iter()
                    .any(|cell| cell.to_ascii_lowercase().contains(needle))
            {
                matches = false;
            }

            if let Some(ref re) = regex_pattern
                && !out_row.iter().any(|cell| re.is_match(cell))
            {
                matches = false;
            }

            if !matches {
                continue;
            }
            for (idx, cell) in out_row.iter().enumerate() {
                widths[idx] = widths[idx].max(cell.len());
            }
            table.push(out_row);
        }
    }

    if table.is_empty() {
        let has_filter = render_opts.filter.is_some();
        if has_filter {
            println!("No resources found matching your filter.");
            println!("\nThis could mean:");
            println!("  • No resources match the filter criteria");
            println!("  • Try removing the filter or adjusting your search");
        } else {
            println!("No resources found.");
            println!("\nThis could mean:");
            println!("  • No resources exist for this query");
            println!("  • Resources may be filtered by other criteria");
        }
        println!("\nTry:");
        println!("  • Checking with JSON output: -o json");
        println!("  • Verifying your query parameters");
        return true;
    }

    if let Some(sort) = render_opts.sort_by.as_ref()
        && let Some(idx) = columns.iter().position(|c| c == sort)
    {
        table.sort_by(|a, b| a[idx].cmp(&b[idx]));
    }

    let print_padded = |value: &str, width: usize| {
        print!("{}", terminal_safe(value));
        if width > value.len() {
            print!("{}", " ".repeat(width - value.len()));
        }
    };

    for (i, col) in columns.iter().enumerate() {
        if i > 0 {
            print!("  ");
        }
        print_padded(col, widths[i]);
    }
    println!();
    // Separator
    for (i, width) in widths.iter().enumerate() {
        if i > 0 {
            print!("  ");
        }
        print!("{}", "-".repeat(*width));
    }
    println!();
    // Rows
    for row in table {
        for (i, cell) in row.iter().enumerate() {
            if i > 0 {
                print!("  ");
            }
            print_padded(cell, widths[i]);
        }
        println!();
    }

    true
}

fn packet_loss_pct(obj: &serde_json::Map<String, serde_json::Value>) -> Option<f64> {
    const PACKET_LOSS_KEYS: [&str; 4] = [
        "packet_loss",
        "packet_loss_pct",
        "packet_loss_percent",
        "packetloss",
    ];

    for key in PACKET_LOSS_KEYS {
        if let Some(val) = obj.get(key) {
            if let Some(loss) = val.as_f64() {
                if (0.0..=1000.0).contains(&loss) {
                    return Some(if loss <= 1.0 { loss * 100.0 } else { loss });
                }
            } else if let Some(loss) = val.as_i64()
                && (1..=1000).contains(&loss)
            {
                return Some(loss as f64);
            }
        }
    }

    None
}

fn latency_ms(obj: &serde_json::Map<String, serde_json::Value>) -> Option<f64> {
    const LAT_KEYS: [&str; 3] = ["latency", "latency_ms", "avg_latency"];
    for key in LAT_KEYS {
        if let Some(val) = obj.get(key).and_then(|v| v.as_f64())
            && (0.0..=100_000.0).contains(&val)
        {
            return Some(val);
        }
    }
    None
}

fn uptime_pct(obj: &serde_json::Map<String, serde_json::Value>) -> Option<f64> {
    const UP_KEYS: [&str; 3] = ["uptime", "uptime_pct", "uptime_percent"];
    for key in UP_KEYS {
        if let Some(val) = obj.get(key) {
            if let Some(pct) = val.as_f64() {
                if (0.0..=100.0).contains(&pct) {
                    return Some(if pct <= 1.0 { pct * 100.0 } else { pct });
                }
            } else if let Some(pct) = val.as_i64()
                && (1..=100).contains(&pct)
            {
                return Some(pct as f64);
            }
        }
    }
    None
}

fn availability_pct(obj: &serde_json::Map<String, serde_json::Value>) -> Option<f64> {
    if let Some(avail) = obj.get("availability").and_then(|v| v.as_f64())
        && (0.0..=100.0).contains(&avail)
    {
        return Some(avail);
    }
    None
}

fn enrich_health_status_messages(json: &mut serde_json::Value) {
    if let Some(arr) = json.get_mut("data").and_then(|d| d.as_array_mut()) {
        for item in arr {
            let Some(obj) = item.as_object_mut() else {
                continue;
            };

            let mut reasons = Vec::new();

            if let Some(reason) = obj
                .get("status_reason")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                reasons.push(reason.to_string());
            }

            if obj
                .get("subsystem")
                .and_then(|s| s.as_str())
                .map(|s| s.eq_ignore_ascii_case("vpn"))
                .unwrap_or(false)
            {
                let site_to_site_enabled = obj
                    .get("site_to_site_enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let site_to_site_active = obj
                    .get("site_to_site_num_active")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                let site_to_site_inactive = obj
                    .get("site_to_site_num_inactive")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                reasons.push(format!(
                    "site-to-site: enabled {}, active {}, inactive {}",
                    site_to_site_enabled, site_to_site_active, site_to_site_inactive
                ));

                let remote_user_enabled = obj
                    .get("remote_user_enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let remote_user_active = obj
                    .get("remote_user_num_active")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                let remote_user_inactive = obj
                    .get("remote_user_num_inactive")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                reasons.push(format!(
                    "remote-user: enabled {}, active {}, inactive {}",
                    remote_user_enabled, remote_user_active, remote_user_inactive
                ));

                if obj
                    .get("status")
                    .and_then(|v| v.as_str())
                    .map(|s| s.eq_ignore_ascii_case("error"))
                    .unwrap_or(false)
                    && site_to_site_inactive > 0
                {
                    obj.insert(
                        "status".to_string(),
                        serde_json::Value::String("warn".to_string()),
                    );
                }
            }

            let mut metrics = Vec::new();
            if let Some(lat) = latency_ms(obj) {
                metrics.push(format!("latency {:.1} ms", lat));
            }
            if let Some(loss) = packet_loss_pct(obj) {
                metrics.push(format!("packet loss {:.2}%", loss));
            }
            if let Some(up) = uptime_pct(obj) {
                metrics.push(format!("uptime {:.2}%", up));
            } else if let Some(up) = obj
                .get("uptime_stats")
                .and_then(|v| v.as_object())
                .and_then(availability_pct)
            {
                metrics.push(format!("uptime {:.2}%", up));
            }

            let mut parts: Vec<String> = Vec::new();
            if let Some(existing) = obj
                .get("status_msg")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                parts.push(existing.to_string());
            } else if let Some(existing) = obj
                .get("status_message")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                parts.push(existing.to_string());
            }

            if !reasons.is_empty() {
                parts.push(reasons.join("; "));
            }
            if !metrics.is_empty() {
                parts.push(metrics.join("; "));
            }

            if !parts.is_empty() {
                obj.insert(
                    "status_msg".to_string(),
                    serde_json::Value::String(parts.join(" | ")),
                );
            }
        }
    }
}

fn value_to_str(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "".into(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

fn is_non_empty(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(_) => true,
        serde_json::Value::Number(_) => true,
        serde_json::Value::String(s) => !s.trim().is_empty(),
        serde_json::Value::Array(arr) => !arr.is_empty(),
        serde_json::Value::Object(map) => !map.is_empty(),
    }
}

fn parse_body(
    body: &Option<String>,
    body_file: &Option<PathBuf>,
) -> Result<Option<serde_json::Value>> {
    match (body, body_file) {
        (Some(inline), None) => {
            let value = serde_json::from_str(inline).context("parsing --body as JSON")?;
            Ok(Some(value))
        }
        (None, Some(path)) => {
            let content = fs::read_to_string(path)
                .with_context(|| format!("reading body file {}", path.display()))?;
            let value = serde_json::from_str(&content).context("parsing --body-file as JSON")?;
            Ok(Some(value))
        }
        (None, None) => Ok(None),
        (Some(_), Some(_)) => Err(anyhow!("use only one of --body or --body-file")),
    }
}

#[cfg(test)]
mod client_filter_tests {
    use super::*;
    use serde_json::json;

    fn history_payload() -> serde_json::Value {
        // `clients/history` answers with a bare array, not a `data` envelope.
        json!([
            {"mac": "d4:8a:fc:44:0c:48", "hostname": "smoke-detector"},
            {"mac": "aa:bb:cc:dd:ee:ff", "hostname": "laptop"},
            {"mac": "11:22:33:44:55:66", "hostname": "printer"},
        ])
    }

    #[test]
    fn mac_filter_keeps_only_the_matching_client() {
        // Regression: --mac was accepted but never applied, so a lookup for one
        // client returned the entire offline set.
        let mut json = history_payload();
        let arr = list_payload_mut(&mut json).expect("bare v2 array is a list payload");
        assert!(retain_clients_with_mac(arr, "d4:8a:fc:44:0c:48"));
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["hostname"], json!("smoke-detector"));
    }

    #[test]
    fn mac_filter_is_case_insensitive_and_separator_agnostic() {
        for probe in ["D4:8A:FC:44:0C:48", "d48afc440c48", "D4-8A-FC-44-0C-48"] {
            let mut json = history_payload();
            let arr = list_payload_mut(&mut json).expect("list payload");
            assert!(
                retain_clients_with_mac(arr, probe),
                "probe {probe} should match"
            );
            assert_eq!(arr.len(), 1, "probe {probe} matched the wrong count");
        }
    }

    #[test]
    fn mac_filter_reports_no_match_instead_of_dumping_everything() {
        let mut json = history_payload();
        let arr = list_payload_mut(&mut json).expect("list payload");
        assert!(
            !retain_clients_with_mac(arr, "de:ad:be:ef:00:01"),
            "an unmatched MAC must be reported as no-match"
        );
        assert!(
            arr.is_empty(),
            "a failed filter must never fall back to the full set"
        );
    }

    #[test]
    fn mac_filter_skips_records_without_a_mac_field() {
        let mut json = json!([{"hostname": "ghost"}, {"mac": "d4:8a:fc:44:0c:48"}]);
        let arr = list_payload_mut(&mut json).expect("list payload");
        assert!(retain_clients_with_mac(arr, "d4:8a:fc:44:0c:48"));
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn truncate_with_warning_caps_at_limit() {
        let mut arr: Vec<serde_json::Value> = (0..50).map(|i| json!({"n": i})).collect();
        truncate_with_warning(&mut arr, 30, "clients");
        assert_eq!(arr.len(), 30);
    }

    #[test]
    fn truncate_with_warning_leaves_short_lists_alone() {
        let mut arr: Vec<serde_json::Value> = (0..5).map(|i| json!({"n": i})).collect();
        truncate_with_warning(&mut arr, 30, "clients");
        assert_eq!(arr.len(), 5);
    }
}

#[cfg(test)]
mod health_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn enriches_packet_loss_when_missing_status_msg() {
        let mut json = json!({
            "data": [
                {
                    "subsystem": "vpn",
                    "status": "error",
                    "packet_loss": 0.12
                }
            ]
        });

        enrich_health_status_messages(&mut json);

        let msg = json["data"][0]["status_msg"]
            .as_str()
            .expect("status_msg added");
        assert!(msg.contains("packet loss"));
        assert!(msg.contains("12")); // 0.12 -> 12%
    }

    #[test]
    fn builds_vpn_status_with_counts() {
        let mut json = json!({
            "data": [
                {
                    "subsystem": "vpn",
                    "status": "error",
                    "site_to_site_enabled": true,
                    "site_to_site_num_active": 0,
                    "site_to_site_num_inactive": 1,
                    "remote_user_enabled": true,
                    "remote_user_num_active": 0,
                    "remote_user_num_inactive": 0
                }
            ]
        });

        enrich_health_status_messages(&mut json);

        let msg = json["data"][0]["status_msg"]
            .as_str()
            .expect("status_msg added");
        assert!(msg.contains("site-to-site"));
        assert!(msg.contains("inactive 1"));
        assert!(msg.contains("remote-user"));
        assert_eq!(json["data"][0]["status"], "warn");
    }

    #[test]
    fn preserves_existing_status_message() {
        let mut json = json!({
            "data": [
                {
                    "subsystem": "vpn",
                    "status": "error",
                    "status_msg": "existing message",
                    "packet_loss": 99.0
                }
            ]
        });

        enrich_health_status_messages(&mut json);

        let msg = json["data"][0]["status_msg"].as_str().unwrap();
        assert!(msg.contains("existing message"));
        assert!(msg.contains("packet loss"));
    }

    #[test]
    fn appends_metrics_alongside_existing_message() {
        let mut json = json!({
            "data": [
                {
                    "subsystem": "wan",
                    "status": "error",
                    "status_msg": "controller reported error",
                    "latency": 3.2,
                    "uptime_pct": 99.95,
                    "packet_loss": 0.01
                }
            ]
        });

        enrich_health_status_messages(&mut json);

        let msg = json["data"][0]["status_msg"].as_str().unwrap();
        assert!(msg.contains("controller reported error"));
        assert!(msg.contains("latency 3.2"));
        assert!(msg.contains("uptime"));
        assert!(msg.contains("packet loss"));
    }
}

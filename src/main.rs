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
mod schema;

use crate::client::{ApiClient, ResponseData};
use crate::config::{LocalConfig, Scope, resolve, resolve_local, save};
use crate::local::LocalClient;
use crate::schema::{SchemaRegistry, estimate_tokens};
use anyhow::{Context, Result, anyhow};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
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
        help = "Watch mode: refresh every SECONDS (tables only)"
    )]
    watch: Option<u64>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Persist an API key to the chosen scope
    Configure {
        #[arg(long)]
        key: String,
        #[arg(
            long,
            value_enum,
            default_value_t = ScopeArg::User,
            help = "Where to write the config (local project dir or user config dir)"
        )]
        scope: ScopeArg,
        #[arg(
            long,
            value_name = "URL",
            help = "Optional base URL to store alongside the key"
        )]
        base_url: Option<String>,
    },
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
    /// Operate against a local UniFi controller using username/password
    Local {
        #[arg(long, global = true)]
        site: Option<String>,
        #[command(subcommand)]
        command: LocalCommands,
    },
    /// Validate stored credentials (cloud/local)
    Validate {
        #[arg(long, help = "Validate only cloud (Site Manager) credentials")]
        cloud_only: bool,
        #[arg(long, help = "Validate only local controller credentials")]
        local_only: bool,
    },
    /// Show current configuration (secrets masked)
    ConfigShow,
    /// Generate shell completion scripts
    Completion {
        #[arg(value_enum)]
        shell: CompletionShell,
    },
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
        #[arg(long)]
        password: Option<String>,
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
        #[arg(long, default_value = "csv", help = "Export format (csv, json)")]
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
        #[arg(long, default_value = "csv", help = "Export format (csv, json)")]
        format: String,
    },
    /// Export event log as time-series data
    Events {
        #[arg(long, help = "Number of recent events to export (default: 100)")]
        limit: Option<usize>,
        #[arg(long)]
        site: Option<String>,
        #[arg(long, default_value = "csv", help = "Export format (csv, json)")]
        format: String,
    },
}

#[derive(Subcommand)]
enum LocalCommands {
    /// Store local controller credentials (password is saved to the chosen scope)
    Configure {
        #[arg(long)]
        url: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
        #[arg(long, default_value = "default")]
        site: String,
        #[arg(
            long,
            default_value_t = false,
            help = "Enable TLS verification for the controller (self-signed certs may require disabling)"
        )]
        verify_tls: bool,
        #[arg(
            long,
            value_enum,
            default_value_t = ScopeArg::Local,
            help = "Where to write the credentials (defaults to local project file)"
        )]
        scope: ScopeArg,
    },
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
        /// Maximum number of results to return (default: 30)
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
        /// Maximum number of results to return (default: 30)
        #[arg(long, default_value_t = 30)]
        limit: usize,
    },
    /// Get client connection history (v2 API)
    History {
        #[arg(long)]
        site: Option<String>,
        #[arg(long, value_name = "MAC")]
        mac: Option<String>,
        /// Maximum number of results to return (default: 30)
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
        /// Maximum number of results to return (default: 30)
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
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cwd = std::env::current_dir().context("reading current directory")?;
    FULL_IDS.get_or_init(|| cli.full_ids);

    if let Commands::Configure {
        key,
        scope,
        base_url,
    } = &cli.command
    {
        let mut existing = config::load_scope((*scope).into(), &cwd)?;
        existing.api_key = Some(key.clone());
        if let Some(url) = base_url.clone() {
            existing.base_url = Some(url);
        }

        let path = save((*scope).into(), &existing, &cwd)?;
        println!("Saved API key to {}", path.display());
        return Ok(());
    }

    let effective = resolve(&cwd, cli.api_key.clone(), cli.base_url.clone())?;
    let client = ApiClient::new(&effective.base_url, &effective.api_key)?;
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
    };

    match cli.command {
        Commands::Host(command) => match command {
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
        Commands::Site(command) => match command {
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
        Commands::Device(command) => match command {
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
        Commands::Isp(command) => match command {
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
                let payload = parse_body(&body, &body_file)?
                    .ok_or_else(|| anyhow!("Provide --body or --body-file with JSON content"))?;
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
        Commands::Sdwan(command) => match command {
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
        Commands::Local { site, command } => {
            handle_local(command, site, &cwd, cli.output, &render_opts, cli.watch)?;
        }
        Commands::Validate {
            cloud_only,
            local_only,
        } => {
            if cloud_only && local_only {
                return Err(anyhow!("Use only one of --cloud-only or --local-only"));
            }

            if !local_only {
                println!("Validating cloud (Site Manager) credentials...");
                match client.get("/v1/hosts", &[]) {
                    Ok(_) => println!("Cloud API: ok"),
                    Err(e) => println!("Cloud API: FAILED ({})", e),
                }
            }

            if !cloud_only {
                println!("Validating local controller credentials...");
                match resolve_local(&cwd, None).and_then(|cfg| {
                    let mut local = LocalClient::new(
                        &cfg.url,
                        &cfg.username,
                        &cfg.password,
                        &cfg.site,
                        cfg.verify_tls,
                    )?;
                    local.list_sites()
                }) {
                    Ok(_) => println!("Local controller: ok"),
                    Err(e) => println!("Local controller: FAILED ({})", e),
                }
            }
        }
        Commands::ConfigShow => {
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
        Commands::Configure { .. } => unreachable!("handled earlier"),
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
    match cmd {
        LocalCommands::Configure {
            url,
            username,
            password,
            site,
            verify_tls,
            scope,
        } => {
            let mut existing = config::load_scope(scope.into(), cwd)?;
            let mut local_cfg = existing.local.unwrap_or_default();
            local_cfg.url = Some(url);
            local_cfg.username = Some(username);
            local_cfg.password = Some(password);
            local_cfg.site = Some(site);
            local_cfg.verify_tls = verify_tls;
            existing.local = Some(local_cfg);
            let path = save(scope.into(), &existing, cwd)?;
            println!("Saved local controller credentials to {}", path.display());
            Ok(())
        }
        LocalCommands::Site(LocalSiteCommand::List) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            render_local(
                || {
                    let mut resp = client.list_devices()?;
                    if let Some(mut json) = resp.json.clone() {
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            // Get all devices and adopt unadopted ones
            let devices = client.list_devices()?;
            if let Some(json) = devices.json {
                if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
                    let mut adopted_count = 0;
                    let mut failed_count = 0;

                    for device in data {
                        let state = device.get("state").and_then(|s| s.as_str());
                        let adopted = device.get("adopted").and_then(|a| a.as_bool());
                        let is_unadopted = state == Some("pending") || adopted == Some(false);

                        if is_unadopted {
                            if let Some(mac) = device.get("mac").and_then(|m| m.as_str()) {
                                match client.device_action(mac, "adopt") {
                                    Ok(_) => {
                                        adopted_count += 1;
                                        if let Some(name) =
                                            device.get("name").and_then(|n| n.as_str())
                                        {
                                            println!("Adopted: {} ({})", name, mac);
                                        } else {
                                            println!("Adopted device: {}", mac);
                                        }
                                    }
                                    Err(e) => {
                                        failed_count += 1;
                                        if let Some(name) =
                                            device.get("name").and_then(|n| n.as_str())
                                        {
                                            eprintln!("Failed to adopt {} ({}): {}", name, mac, e);
                                        } else {
                                            eprintln!("Failed to adopt device {}: {}", mac, e);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    println!(
                        "\nAdoption complete: {} adopted, {} failed",
                        adopted_count, failed_count
                    );
                    Ok(())
                } else {
                    println!("No devices found");
                    Ok(())
                }
            } else {
                println!("No devices found");
                Ok(())
            }
        }
        LocalCommands::Device(LocalDeviceCommand::Get {
            mac,
            site: _,
            config,
            ports,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            render_local(
                || {
                    // stats/config/ports are derived from device listing
                    let mut resp = client.device_stats(&mac)?;
                    if let Some(mut json) = resp.json.clone() {
                        if let Some(arr) = json.get_mut("data").and_then(|d| d.as_array_mut()) {
                            if let Some(first) = arr.get_mut(0) {
                                if !ports {
                                    first.as_object_mut().map(|o| {
                                        o.remove("port_table");
                                    });
                                }
                                if !config {
                                    // keep stats only (remove config-heavy?)
                                }
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            render_response(
                client.device_action(&mac, "restart")?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::Device(LocalDeviceCommand::Adopt { mac, site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            render_response(
                client.device_action(&mac, "adopt")?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::Device(LocalDeviceCommand::Upgrade { mac, site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            render_response(
                client.device_action(&mac, "upgrade")?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::Device(LocalDeviceCommand::SpectrumScan { mac, site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            render_local(
                || {
                    let mut resp = client.list_clients()?;
                    if let Some(mut json) = resp.json.clone() {
                        if let Some(arr) = json.get_mut("data").and_then(|d| d.as_array_mut()) {
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            render_response(
                client.client_action(&mac, "block")?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::Client(LocalClientCommand::Unblock { mac, site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            render_response(
                client.client_action(&mac, "unblock")?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::Client(LocalClientCommand::Reconnect { mac, site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            render_response(
                client.client_action(&mac, "reconnect")?,
                output,
                render_opts,
                None,
            )
        }
        LocalCommands::Client(LocalClientCommand::Active { site: _, limit }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            render_local(
                || {
                    let mut resp = client.clients_v2_active()?;
                    if let Some(mut json) = resp.json.clone() {
                        if let Some(arr) = json.get_mut("data").and_then(|d| d.as_array_mut()) {
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            let mac_filter = mac.clone();
            render_local(
                move || {
                    let mut resp = client.clients_v2_history()?;
                    if let Some(mut json) = resp.json.clone() {
                        if let Some(arr) = json.get_mut("data").and_then(|d| d.as_array_mut()) {
                            if let Some(ref mac_val) = mac_filter {
                                arr.retain(|item| {
                                    item.get("mac")
                                        .and_then(|m| m.as_str())
                                        .map(|m| m.eq_ignore_ascii_case(mac_val))
                                        .unwrap_or(false)
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            render_local(
                || {
                    let mut resp = client.list_events()?;
                    if let Some(mut json) = resp.json.clone() {
                        if let Some(arr) = json.get_mut("data").and_then(|d| d.as_array_mut()) {
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
                Some(&["time", "key", "msg", "subsystem"]),
                watch,
            )
        }
        LocalCommands::Log(LocalLogCommand::Settings { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            let mut payload = serde_json::json!({});
            if let Some(lim) = limit {
                payload["limit"] = serde_json::json!(lim);
            }
            if let Some(off) = offset {
                payload["offset"] = serde_json::json!(off);
            }
            render_local(
                || client.system_log_all(Some(&payload)),
                output,
                render_opts,
                Some(&["time", "level", "msg", "subsystem", "key"]),
                watch,
            )
        }
        LocalCommands::Log(LocalLogCommand::Count { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            let payload = limit.map(|lim| serde_json::json!({ "limit": lim }));
            render_local(
                || client.system_log_critical(payload.as_ref()),
                output,
                render_opts,
                Some(&["time", "level", "msg", "subsystem", "key"]),
                watch,
            )
        }
        LocalCommands::Log(LocalLogCommand::DeviceAlert { site: _, limit }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            let payload = limit.map(|lim| serde_json::json!({ "limit": lim }));
            render_local(
                || client.system_log_device_alert(payload.as_ref()),
                output,
                render_opts,
                Some(&["time", "level", "msg", "subsystem", "key"]),
                watch,
            )
        }
        LocalCommands::Wifi(LocalWifiCommand::Connectivity { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            render_local(|| client.wifiman(), output, render_opts, None, watch)
        }
        LocalCommands::Wifi(LocalWifiCommand::Config { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            render_local(|| client.traffic_routes(), output, render_opts, None, watch)
        }
        LocalCommands::Traffic(LocalTrafficCommand::Rules { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            render_local(|| client.traffic_rules(), output, render_opts, None, watch)
        }
        LocalCommands::Traffic(LocalTrafficCommand::AppRate {
            site: _,
            start,
            end,
            include_unidentified,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            render_local(|| client.stat_ccode(), output, render_opts, None, watch)
        }
        LocalCommands::Stat(LocalStatCommand::CurrentChannel { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            render_local(|| client.stat_guest(), output, render_opts, None, watch)
        }
        LocalCommands::Stat(LocalStatCommand::Rogueap { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            render_local(|| client.stat_rogueap(), output, render_opts, None, watch)
        }
        LocalCommands::Stat(LocalStatCommand::Sdn { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            render_local(|| client.stat_sdn(), output, render_opts, None, watch)
        }
        LocalCommands::Stat(LocalStatCommand::Report5min { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            render_local(
                || client.list_health(),
                output,
                render_opts,
                Some(&["subsystem", "status", "status_msg", "status_message"]),
                watch,
            )
        }
        LocalCommands::Security(LocalSecurityCommand::Get { site: _ }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            render_local(
                || {
                    let mut resp = client.list_health()?;
                    if let Some(mut json) = resp.json.clone() {
                        if let Some(arr) = json.get_mut("data").and_then(|d| d.as_array_mut()) {
                            arr.retain(|item| {
                                item.get("subsystem")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.eq_ignore_ascii_case("wan"))
                                    .unwrap_or(false)
                            });
                            resp.body =
                                serde_json::to_string(&json).unwrap_or_else(|_| resp.body.clone());
                            resp.json = Some(json);
                        }
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            if dry_run {
                // Fetch the network to show what would be deleted
                let networks = client.networks()?;
                if let Some(json) = networks.json {
                    if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
                        if let Some(network) = data.iter().find(|n| {
                            n.get("_id").and_then(|id| id.as_str()) == Some(&id)
                                || n.get("id").and_then(|id| id.as_str()) == Some(&id)
                        }) {
                            println!("Would delete network:");
                            println!("{}", serde_json::to_string_pretty(network)?);
                            return Ok(());
                        }
                    }
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
            enabled,
        }) => {
            let effective = resolve_local(cwd, site_override(global_site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            if dry_run {
                // Fetch the WLAN to show what would be deleted
                let wlans = client.wlans()?;
                if let Some(json) = wlans.json {
                    if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
                        if let Some(wlan) = data.iter().find(|w| {
                            w.get("_id").and_then(|id| id.as_str()) == Some(&id)
                                || w.get("id").and_then(|id| id.as_str()) == Some(&id)
                        }) {
                            println!("Would delete WLAN:");
                            println!("{}", serde_json::to_string_pretty(wlan)?);
                            return Ok(());
                        }
                    }
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            if dry_run {
                // Fetch the firewall rule to show what would be deleted
                let rules = client.firewall_rules()?;
                if let Some(json) = rules.json {
                    if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
                        if let Some(rule) = data.iter().find(|r| {
                            r.get("_id").and_then(|id| id.as_str()) == Some(&id)
                                || r.get("id").and_then(|id| id.as_str()) == Some(&id)
                        }) {
                            println!("Would delete firewall rule:");
                            println!("{}", serde_json::to_string_pretty(rule)?);
                            return Ok(());
                        }
                    }
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            if dry_run {
                // Fetch the firewall group to show what would be deleted
                let groups = client.firewall_groups()?;
                if let Some(json) = groups.json {
                    if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
                        if let Some(group) = data.iter().find(|g| {
                            g.get("_id").and_then(|id| id.as_str()) == Some(&id)
                                || g.get("id").and_then(|id| id.as_str()) == Some(&id)
                        }) {
                            println!("Would delete firewall group:");
                            println!("{}", serde_json::to_string_pretty(group)?);
                            return Ok(());
                        }
                    }
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            render_local(
                || {
                    let mut resp = client.list_clients()?;
                    if let Some(mut json) = resp.json.clone() {
                        if let Some(arr) = json.get_mut("data").and_then(|d| d.as_array_mut()) {
                            let score = |item: &serde_json::Value| -> u128 {
                                let tx = item.get("tx_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                                let rx = item.get("rx_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                                tx as u128 + rx as u128
                            };
                            arr.sort_by(|a, b| score(b).cmp(&score(a)));
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            render_local(
                || {
                    let mut resp = client.list_devices()?;
                    if let Some(mut json) = resp.json.clone() {
                        if let Some(arr) = json.get_mut("data").and_then(|d| d.as_array_mut()) {
                            let score = |item: &serde_json::Value| -> i64 {
                                item.get("num_sta")
                                    .and_then(|v| v.as_i64())
                                    .or_else(|| item.get("num_clients").and_then(|v| v.as_i64()))
                                    .unwrap_or(0)
                            };
                            arr.sort_by(|a, b| score(b).cmp(&score(a)));
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            if dry_run {
                let tables = client.policy_tables()?;
                if let Some(json) = tables.json {
                    if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
                        if let Some(table) = data.iter().find(|t| {
                            t.get("_id").and_then(|id| id.as_str()) == Some(&id)
                                || t.get("id").and_then(|id| id.as_str()) == Some(&id)
                        }) {
                            println!("Would delete policy table:");
                            println!("{}", serde_json::to_string_pretty(table)?);
                            return Ok(());
                        }
                    }
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            if dry_run {
                let zones = client.zones()?;
                if let Some(json) = zones.json {
                    if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
                        if let Some(zone) = data.iter().find(|z| {
                            z.get("_id").and_then(|id| id.as_str()) == Some(&id)
                                || z.get("id").and_then(|id| id.as_str()) == Some(&id)
                        }) {
                            println!("Would delete zone:");
                            println!("{}", serde_json::to_string_pretty(zone)?);
                            return Ok(());
                        }
                    }
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            if dry_run {
                let objects = client.objects()?;
                if let Some(json) = objects.json {
                    if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
                        if let Some(obj) = data.iter().find(|o| {
                            o.get("_id").and_then(|id| id.as_str()) == Some(&id)
                                || o.get("id").and_then(|id| id.as_str()) == Some(&id)
                        }) {
                            println!("Would delete object:");
                            println!("{}", serde_json::to_string_pretty(obj)?);
                            return Ok(());
                        }
                    }
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
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            handle_correlate_command(&cmd, &mut client, output, render_opts, global_site)?;
            Ok(())
        }
        LocalCommands::Diagnose(cmd) => {
            let effective = resolve_local(cwd, site_override(global_site.clone()))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            handle_diagnose_command(&cmd, &mut client, output, render_opts, global_site)?;
            Ok(())
        }
        LocalCommands::TimeSeries(cmd) => {
            let effective = resolve_local(cwd, site_override(global_site.clone()))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            handle_timeseries_command(&cmd, &mut client, output, global_site)?;
            Ok(())
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

            // Get client details
            let clients = client.list_clients()?;
            if let Some(ref json) = clients.json {
                if let Some(arr) = json.get("data").and_then(|d| d.as_array()) {
                    let client_data = arr
                        .iter()
                        .find(|c| c.get("mac").and_then(|m| m.as_str()) == Some(mac));
                    correlated["client"] = client_data.cloned().unwrap_or(json!(null));
                }
            }

            // Get connected AP info (if wireless)
            if let Some(ap_mac) = correlated["client"]["ap_mac"].as_str() {
                let devices = client.list_devices()?;
                if let Some(ref json) = devices.json {
                    if let Some(arr) = json.get("data").and_then(|d| d.as_array()) {
                        let ap_data = arr
                            .iter()
                            .find(|d| d.get("mac").and_then(|m| m.as_str()) == Some(ap_mac));
                        correlated["connected_ap"] = ap_data.cloned().unwrap_or(json!(null));
                    }
                }
            }

            // Get events if requested
            if *include_events {
                if let Ok(events_resp) = client.list_events() {
                    if let Some(ref json) = events_resp.json {
                        if let Some(arr) = json.get("data").and_then(|d| d.as_array()) {
                            let client_events: Vec<_> = arr
                                .iter()
                                .filter(|e| {
                                    e.get("user").and_then(|u| u.as_str()) == Some(mac)
                                        || e.get("client_mac").and_then(|m| m.as_str()) == Some(mac)
                                })
                                .take(20)
                                .cloned()
                                .collect();
                            correlated["recent_events"] = json!(client_events);
                        }
                    }
                }
            }

            correlated["llm_summary"] = json!({
                "has_client_data": !correlated["client"].is_null(),
                "is_wireless": !correlated["connected_ap"].is_null(),
                "event_count": correlated.get("recent_events")
                    .and_then(|e| e.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0),
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

            // Get device details
            let devices = client.list_devices()?;
            if let Some(ref json) = devices.json {
                if let Some(arr) = json.get("data").and_then(|d| d.as_array()) {
                    let device_data = arr
                        .iter()
                        .find(|d| d.get("mac").and_then(|m| m.as_str()) == Some(mac));
                    correlated["device"] = device_data.cloned().unwrap_or(json!(null));
                }
            }

            // Get connected clients if requested and device is an AP
            if *include_clients {
                let clients = client.list_clients()?;
                if let Some(ref json) = clients.json {
                    if let Some(arr) = json.get("data").and_then(|d| d.as_array()) {
                        let connected_clients: Vec<_> = arr
                            .iter()
                            .filter(|c| {
                                c.get("ap_mac").and_then(|m| m.as_str()) == Some(mac)
                                    || c.get("sw_mac").and_then(|m| m.as_str()) == Some(mac)
                            })
                            .cloned()
                            .collect();
                        correlated["connected_clients"] = json!(connected_clients);
                        correlated["connected_clients_count"] = json!(connected_clients.len());
                    }
                }
            }

            correlated["llm_summary"] = json!({
                "has_device_data": !correlated["device"].is_null(),
                "device_type": correlated["device"]["type"].as_str().unwrap_or("unknown"),
                "client_count": correlated.get("connected_clients_count").and_then(|c| c.as_u64()).unwrap_or(0),
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
    use serde_json::json;

    match cmd {
        DiagnoseCommand::Network { site: _ } => {
            let mut diagnostics = json!({
                "diagnostic_type": "network",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "checks": [],
            });

            let mut checks = Vec::new();

            // Health check
            if let Ok(health) = client.list_health() {
                let health_status: serde_json::Value = if let Some(ref json) = health.json {
                    json.get("data").cloned().unwrap_or(json!(null))
                } else {
                    json!(null)
                };
                checks.push(json!({
                    "name": "Health",
                    "status": if health.status == 200 { "pass" } else { "fail" },
                    "data": health_status,
                }));
            }

            // WAN check (filter health data for WAN subsystem)
            if let Ok(wan_health) = client.list_health() {
                let wan_ok = if let Some(ref json) = wan_health.json {
                    json.get("data")
                        .and_then(|d| d.as_array())
                        .map(|arr| {
                            arr.iter().any(|item| {
                                item.get("subsystem").and_then(|s| s.as_str()) == Some("wan")
                                    && item.get("status").and_then(|s| s.as_str()) == Some("ok")
                            })
                        })
                        .unwrap_or(false)
                } else {
                    false
                };
                checks.push(json!({
                    "name": "WAN",
                    "status": if wan_ok { "pass" } else { "fail" },
                }));
            }

            // Device check
            if let Ok(devices) = client.list_devices() {
                let device_count = devices
                    .json
                    .as_ref()
                    .and_then(|j| j.get("data"))
                    .and_then(|d| d.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                checks.push(json!({
                    "name": "Devices",
                    "status": "pass",
                    "device_count": device_count,
                }));
            }

            diagnostics["checks"] = json!(checks);
            diagnostics["llm_summary"] = json!({
                "total_checks": checks.len(),
                "passed": checks.iter().filter(|c| c["status"] == "pass").count(),
                "recommendation": "Review failed checks for detailed troubleshooting",
            });

            render_response(
                ResponseData {
                    status: 200,
                    body: serde_json::to_string(&diagnostics)?,
                    json: Some(diagnostics),
                },
                output,
                render_opts,
                None,
            )
        }
        DiagnoseCommand::Wifi { site: _ } => {
            let mut diagnostics = json!({
                "diagnostic_type": "wifi",
                "timestamp": chrono::Utc::now().to_rfc3339(),
            });

            // WiFi connectivity check
            if let Ok(connectivity) = client.wifi_connectivity() {
                diagnostics["connectivity"] = connectivity.json.clone().unwrap_or(json!(null));
            }

            // Get APs
            if let Ok(devices) = client.list_devices() {
                if let Some(ref json) = devices.json {
                    if let Some(arr) = json.get("data").and_then(|d| d.as_array()) {
                        let aps: Vec<_> = arr
                            .iter()
                            .filter(|d| d.get("type").and_then(|t| t.as_str()) == Some("uap"))
                            .map(|d| {
                                json!({
                                    "mac": d.get("mac"),
                                    "name": d.get("name"),
                                    "state": d.get("state"),
                                    "num_sta": d.get("num_sta"),
                                })
                            })
                            .collect();
                        diagnostics["access_points"] = json!(aps);
                        diagnostics["ap_count"] = json!(aps.len());
                    }
                }
            }

            diagnostics["llm_summary"] = json!({
                "ap_count": diagnostics.get("ap_count").and_then(|c| c.as_u64()).unwrap_or(0),
                "recommendation": "Check WiFi connectivity and AP distribution",
            });

            render_response(
                ResponseData {
                    status: 200,
                    body: serde_json::to_string(&diagnostics)?,
                    json: Some(diagnostics),
                },
                output,
                render_opts,
                None,
            )
        }
        DiagnoseCommand::Client { mac, site: _ } => {
            if let Some(mac) = mac {
                // Diagnose specific client
                handle_correlate_command(
                    &CorrelateCommand::Client {
                        mac: mac.clone(),
                        site: None,
                        include_events: true,
                    },
                    client,
                    output,
                    render_opts,
                    None,
                )
            } else {
                // Diagnose all clients
                let clients = client.list_clients()?;
                let mut diagnostics = json!({
                    "diagnostic_type": "client_overview",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                });

                if let Some(ref json) = clients.json {
                    if let Some(arr) = json.get("data").and_then(|d| d.as_array()) {
                        let wireless_count = arr
                            .iter()
                            .filter(|c| {
                                !c.get("is_wired").and_then(|w| w.as_bool()).unwrap_or(false)
                            })
                            .count();
                        let wired_count = arr.len() - wireless_count;

                        diagnostics["total_clients"] = json!(arr.len());
                        diagnostics["wireless_clients"] = json!(wireless_count);
                        diagnostics["wired_clients"] = json!(wired_count);
                    }
                }

                render_response(
                    ResponseData {
                        status: 200,
                        body: serde_json::to_string(&diagnostics)?,
                        json: Some(diagnostics),
                    },
                    output,
                    render_opts,
                    None,
                )
            }
        }
    }
}

fn handle_timeseries_command(
    cmd: &TimeSeriesCommand,
    client: &mut LocalClient,
    _output: OutputFormat,
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
                print_timeseries_csv(&stats.json.unwrap_or(json!([])), "traffic")?;
            } else {
                println!("{}", serde_json::to_string_pretty(&stats.json)?);
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
                "startTime": start,
                "endTime": end,
                "apMac": ap_mac.as_deref().unwrap_or("all"),
            });
            let stats = client.wifi_stats_details(&query)?;

            if format == "csv" {
                print_timeseries_csv(&stats.json.unwrap_or(json!([])), "wifi")?;
            } else {
                println!("{}", serde_json::to_string_pretty(&stats.json)?);
            }
            Ok(())
        }
        TimeSeriesCommand::Events {
            limit,
            site: _,
            format,
        } => {
            let events = client.list_events()?;

            if format == "csv" {
                let mut limited_events = events.json.clone().unwrap_or(json!({"data": []}));
                if let Some(limit) = limit {
                    if let Some(arr) = limited_events
                        .get_mut("data")
                        .and_then(|d| d.as_array_mut())
                    {
                        arr.truncate(*limit);
                    }
                }
                print_timeseries_csv(&limited_events, "events")?;
            } else {
                println!("{}", serde_json::to_string_pretty(&events.json)?);
            }
            Ok(())
        }
    }
}

fn print_timeseries_csv(data: &serde_json::Value, data_type: &str) -> Result<()> {
    use csv::Writer;
    use std::io;

    let mut wtr = Writer::from_writer(io::stdout());

    match data_type {
        "traffic" => {
            wtr.write_record(&["timestamp", "rx_bytes", "tx_bytes"])?;
            if let Some(arr) = data.as_array() {
                for item in arr {
                    wtr.write_record(&[
                        item.get("time")
                            .and_then(|t| t.as_u64())
                            .map(|t| t.to_string())
                            .unwrap_or_default(),
                        item.get("rx_bytes")
                            .and_then(|r| r.as_u64())
                            .map(|r| r.to_string())
                            .unwrap_or_default(),
                        item.get("tx_bytes")
                            .and_then(|t| t.as_u64())
                            .map(|t| t.to_string())
                            .unwrap_or_default(),
                    ])?;
                }
            }
        }
        "wifi" => {
            wtr.write_record(&["timestamp", "ap_mac", "channel", "num_sta", "satisfaction"])?;
            if let Some(arr) = data.as_array() {
                for item in arr {
                    wtr.write_record(&[
                        item.get("time")
                            .and_then(|t| t.as_u64())
                            .map(|t| t.to_string())
                            .unwrap_or_default(),
                        item.get("ap_mac")
                            .and_then(|m| m.as_str())
                            .unwrap_or("")
                            .to_string(),
                        item.get("channel")
                            .and_then(|c| c.as_u64())
                            .map(|c| c.to_string())
                            .unwrap_or_default(),
                        item.get("num_sta")
                            .and_then(|n| n.as_u64())
                            .map(|n| n.to_string())
                            .unwrap_or_default(),
                        item.get("satisfaction")
                            .and_then(|s| s.as_f64())
                            .map(|s| s.to_string())
                            .unwrap_or_default(),
                    ])?;
                }
            }
        }
        "events" => {
            wtr.write_record(&["timestamp", "datetime", "key", "msg", "subsystem"])?;
            if let Some(obj) = data.as_object() {
                if let Some(arr) = obj.get("data").and_then(|d| d.as_array()) {
                    for item in arr {
                        wtr.write_record(&[
                            item.get("time")
                                .and_then(|t| t.as_u64())
                                .map(|t| t.to_string())
                                .unwrap_or_default(),
                            item.get("datetime")
                                .and_then(|d| d.as_str())
                                .unwrap_or("")
                                .to_string(),
                            item.get("key")
                                .and_then(|k| k.as_str())
                                .unwrap_or("")
                                .to_string(),
                            item.get("msg")
                                .and_then(|m| m.as_str())
                                .unwrap_or("")
                                .to_string(),
                            item.get("subsystem")
                                .and_then(|s| s.as_str())
                                .unwrap_or("")
                                .to_string(),
                        ])?;
                    }
                }
            }
        }
        _ => {
            return Err(anyhow!("Unknown time-series data type: {}", data_type));
        }
    }

    wtr.flush()?;
    Ok(())
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
            // Clear screen on subsequent runs (not the first)
            if !first_run && output == OutputFormat::Pretty {
                // Clear screen: ESC[2J moves cursor to top, ESC[H moves to home
                print!("\x1b[2J\x1b[H");
            }
            first_run = false;

            // Print timestamp for watch mode
            if output == OutputFormat::Pretty {
                let now = chrono::Local::now();
                println!("Updated: {}\n", now.format("%Y-%m-%d %H:%M:%S"));
            }

            let resp = fetch()?;
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
        format!(" \"{}\"", name)
    } else {
        String::new()
    };

    print!(
        "Are you sure you want to delete {}{} (ID: {})? [y/N]: ",
        resource_type, name_part, resource_id
    );
    io::stdout().flush()?;

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
        verify_tls: false,
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
            // Clear screen on subsequent runs (not the first)
            if !first_run && output == OutputFormat::Pretty {
                // Clear screen: ESC[2J moves cursor to top, ESC[H moves to home
                print!("\x1b[2J\x1b[H");
            }
            first_run = false;

            // Print timestamp for watch mode
            if output == OutputFormat::Pretty {
                let now = chrono::Local::now();
                println!("Updated: {}\n", now.format("%Y-%m-%d %H:%M:%S"));
            }

            let response = client.get(path, &query)?;
            render_response(response.clone(), output, render_opts, columns)?;

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
    response: ResponseData,
    output: OutputFormat,
    render_opts: &RenderOpts,
    columns: Option<&[&str]>,
) -> Result<()> {
    let _status = response.status;
    match output {
        OutputFormat::Raw => {
            println!("{}", response.body);
        }
        OutputFormat::Json => {
            if let Some(json) = response.json {
                println!("{}", serde_json::to_string(&json)?);
            } else {
                println!("{}", response.body);
            }
        }
        OutputFormat::Pretty => {
            if let Some(json) = response.json {
                if !print_table(&json, columns, render_opts) {
                    println!("{}", serde_json::to_string_pretty(&json)?);
                }
            } else {
                println!("{}", response.body);
            }
        }
        OutputFormat::Csv => {
            if let Some(json) = response.json {
                print_csv(&json, columns, render_opts)?;
            } else {
                println!("{}", response.body);
            }
        }
        OutputFormat::Llm => {
            if let Some(json) = response.json {
                print_llm(&json)?;
            } else {
                println!("{}", response.body);
            }
        }
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
                .any(|row| row.get(key).map(|v| is_non_empty(v)).unwrap_or(false))
            {
                csv_columns.push(key.to_string());
            }
        }
    }

    if csv_columns.is_empty() {
        if let Some(hint) = columns_hint {
            for key in hint {
                if rows
                    .iter()
                    .any(|row| row.get(key).map(|v| is_non_empty(v)).unwrap_or(false))
                {
                    csv_columns.push((*key).to_string());
                }
            }
        }
    }

    if csv_columns.is_empty() {
        // Auto-select up to 8 non-empty fields
        for key in first_obj.keys() {
            if rows
                .iter()
                .any(|row| row.get(key).map(|v| is_non_empty(v)).unwrap_or(false))
            {
                csv_columns.push(key.to_string());
            }
            if csv_columns.len() >= 8 {
                break;
            }
        }
    }

    // Always include id if present
    if !csv_columns.contains(&"id".to_string()) {
        if rows
            .iter()
            .any(|row| row.get("id").map(|v| is_non_empty(v)).unwrap_or(false))
        {
            csv_columns.push("id".to_string());
        }
    }

    if csv_columns.is_empty() {
        println!("{}", serde_json::to_string(json)?);
        return Ok(());
    }

    let mut wtr = Writer::from_writer(io::stdout());

    // Write header
    wtr.write_record(&csv_columns)?;

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
            if let Some(needle) = &needle {
                if !csv_columns.iter().any(|col| {
                    map.get(col)
                        .map(|v| value_to_str(v).to_ascii_lowercase().contains(needle))
                        .unwrap_or(false)
                }) {
                    matches = false;
                }
            }

            // Apply regex filter
            if let Some(ref re) = regex_pattern {
                if !csv_columns.iter().any(|col| {
                    map.get(col)
                        .map(|v| re.is_match(&value_to_str(v)))
                        .unwrap_or(false)
                }) {
                    matches = false;
                }
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

    // Write rows
    for row in filtered_rows {
        if let serde_json::Value::Object(map) = row {
            let mut record = Vec::new();
            for col in &csv_columns {
                let value = map.get(col).unwrap_or(&serde_json::Value::Null);
                record.push(value_to_str(value));
            }
            wtr.write_record(&record)?;
        }
    }

    wtr.flush()?;
    Ok(())
}

fn print_llm(json: &serde_json::Value) -> Result<()> {
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
            "truncation_applied": false,
            "ai_guidance": {
                "summary": format!("Response contains {} items with ~{} tokens", item_count, total_tokens),
                "recommended_max_tokens": 4000,
                "token_efficient": total_tokens < 4000,
            }
        }
    });

    // Add schema information if available (try to infer endpoint)
    // This is a simple heuristic - in practice, you'd pass context about which endpoint was called
    let schema = registry.get("device.list"); // Placeholder - would be dynamic
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

    // Intelligent truncation for large responses
    const MAX_TOKENS: usize = 4000;
    const SAMPLE_SIZE: usize = 5;

    if total_tokens > MAX_TOKENS {
        llm_output["llm_metadata"]["truncation_applied"] = json!(true);

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
    if let serde_json::Value::Array(arr) = &data {
        if !arr.is_empty() {
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
                .any(|row| row.get(key).map(|v| is_non_empty(v)).unwrap_or(false))
            {
                columns.push(key.to_string());
            }
        }
    }

    if columns.is_empty() {
        if let Some(hint) = columns_hint {
            for key in hint {
                if rows
                    .iter()
                    .any(|row| row.get(key).map(|v| is_non_empty(v)).unwrap_or(false))
                {
                    columns.push((*key).to_string());
                }
            }
        }
    }

    if columns.is_empty() {
        // Auto-select up to 8 non-empty fields present in the first object, preferring ones with values.
        for key in first_obj.keys() {
            if rows
                .iter()
                .any(|row| row.get(key).map(|v| is_non_empty(v)).unwrap_or(false))
            {
                columns.push(key.to_string());
            }
            if columns.len() >= 8 {
                break;
            }
        }
    }

    // Always include id if present and not already included.
    if !columns.contains(&"id".to_string()) {
        if rows
            .iter()
            .any(|row| row.get("id").map(|v| is_non_empty(v)).unwrap_or(false))
        {
            columns.push("id".to_string());
        }
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
                let mut rendered = value_to_str(value);
                if col == "id" && !*FULL_IDS.get().unwrap_or(&false) && rendered.len() > 12 {
                    rendered = format!("{}…", &rendered[..12]);
                }
                out_row.push(rendered);
            }

            // Apply filters
            let mut matches = true;

            if let Some(needle) = &needle {
                if !out_row
                    .iter()
                    .any(|cell| cell.to_ascii_lowercase().contains(needle))
                {
                    matches = false;
                }
            }

            if let Some(ref re) = regex_pattern {
                if !out_row.iter().any(|cell| re.is_match(cell)) {
                    matches = false;
                }
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

    for (i, col) in columns.iter().enumerate() {
        if i > 0 {
            print!("  ");
        }
        print!("{:width$}", col, width = widths[i]);
    }
    println!();
    // Separator
    for (i, width) in widths.iter().enumerate() {
        if i > 0 {
            print!("  ");
        }
        print!("{:-<width$}", "", width = *width);
    }
    println!();
    // Rows
    for row in table {
        for (i, cell) in row.iter().enumerate() {
            if i > 0 {
                print!("  ");
            }
            print!("{:width$}", cell, width = widths[i]);
        }
        println!();
    }

    true
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

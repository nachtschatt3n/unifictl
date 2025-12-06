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

use crate::client::{ApiClient, ResponseData};
use crate::config::{LocalConfig, Scope, resolve, resolve_local, save};
use crate::local::LocalClient;
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
    Hosts(HostsCommand),
    /// Site-related operations
    #[command(subcommand)]
    Sites(SitesCommand),
    /// Device operations
    #[command(subcommand)]
    Devices(DevicesCommand),
    /// ISP metrics (EA) helpers
    #[command(subcommand)]
    Isp(IspCommand),
    /// SD-WAN configuration helpers (EA)
    #[command(subcommand)]
    Sdwan(SdwanCommand),
    /// Operate against a local UniFi controller using username/password
    #[command(subcommand)]
    Local(LocalCommands),
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
enum HostsCommand {
    /// List all hosts
    List,
    /// Fetch a host by ID
    Get {
        #[arg(value_name = "HOST_ID")]
        id: String,
    },
}

#[derive(Subcommand)]
enum SitesCommand {
    /// List sites (optionally filtered by host ID)
    List {
        #[arg(long)]
        host_id: Option<String>,
    },
}

#[derive(Subcommand)]
enum DevicesCommand {
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
    /// List sites from the local controller
    Sites,
    /// List devices from a site
    Devices {
        #[arg(long)]
        site: Option<String>,
        #[arg(long, help = "Show only unadopted/pending devices")]
        unadopted: bool,
        #[arg(long, help = "Adopt all unadopted devices")]
        adopt_all: bool,
    },
    /// Show health summaries for a site
    Health {
        #[arg(long)]
        site: Option<String>,
    },
    /// Show recent events for a site
    Events {
        #[arg(long)]
        site: Option<String>,
    },
    /// Manage devices
    Device {
        #[arg(value_name = "MAC")]
        mac: String,
        #[arg(long)]
        site: Option<String>,
        #[arg(long, help = "Show stats for the device (default if no action given)")]
        stats: bool,
        #[arg(long, help = "Show config/state for the device")]
        config: bool,
        #[arg(long, help = "Show port table for the device")]
        ports: bool,
        #[arg(long, help = "Restart the device")]
        restart: bool,
        #[arg(long, help = "Adopt the device (if pending)")]
        adopt: bool,
        #[arg(long, help = "Upgrade the device")]
        upgrade: bool,
    },
    /// List clients (with filters)
    Clients {
        #[arg(long)]
        site: Option<String>,
        #[arg(long, help = "Only wired clients")]
        wired: bool,
        #[arg(long, help = "Only wireless clients")]
        wireless: bool,
        #[arg(long, help = "Only blocked clients")]
        blocked: bool,
    },
    Client {
        #[arg(value_name = "MAC")]
        mac: String,
        #[arg(long)]
        site: Option<String>,
        #[arg(long, help = "Block the client")]
        block: bool,
        #[arg(long, help = "Unblock the client")]
        unblock: bool,
        #[arg(long, help = "Force reconnect (kick)")]
        reconnect: bool,
    },
    /// Show security settings from the local controller
    Security {
        #[arg(long)]
        site: Option<String>,
    },
    /// Show WAN health (subset of health)
    Wan {
        #[arg(long)]
        site: Option<String>,
    },
    /// List networks (VLANs) configuration
    Networks {
        #[arg(long)]
        site: Option<String>,
    },
    /// Create a network
    NetworkCreate {
        #[arg(long)]
        site: Option<String>,
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
    NetworkUpdate {
        #[arg(value_name = "NETWORK_ID")]
        id: String,
        #[arg(long)]
        site: Option<String>,
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
    NetworkDelete {
        #[arg(value_name = "NETWORK_ID")]
        id: String,
        #[arg(long)]
        site: Option<String>,
        #[arg(long, help = "Show what would be deleted without actually deleting")]
        dry_run: bool,
        #[arg(long, help = "Skip confirmation prompt")]
        yes: bool,
    },
    /// List WLAN (SSID) configuration
    Wlans {
        #[arg(long)]
        site: Option<String>,
    },
    /// Create a WLAN
    WlanCreate {
        #[arg(long)]
        site: Option<String>,
        #[arg(long)]
        name: String,
        #[arg(long)]
        password: Option<String>,
        #[arg(long, default_value_t = true)]
        enabled: bool,
    },
    /// Update a WLAN
    WlanUpdate {
        #[arg(value_name = "WLAN_ID")]
        id: String,
        #[arg(long)]
        site: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        enabled: Option<bool>,
    },
    /// Delete a WLAN
    WlanDelete {
        #[arg(value_name = "WLAN_ID")]
        id: String,
        #[arg(long)]
        site: Option<String>,
        #[arg(long, help = "Show what would be deleted without actually deleting")]
        dry_run: bool,
        #[arg(long, help = "Skip confirmation prompt")]
        yes: bool,
    },
    /// List port profiles
    PortProfiles {
        #[arg(long)]
        site: Option<String>,
    },
    /// List firewall rules
    FirewallRules {
        #[arg(long)]
        site: Option<String>,
    },
    /// Create a firewall rule
    FirewallRuleCreate {
        #[arg(long)]
        site: Option<String>,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "accept")]
        action: String,
        #[arg(long, value_name = "SRC_GROUP")]
        src_group: Option<String>,
        #[arg(long, value_name = "DST_GROUP")]
        dst_group: Option<String>,
    },
    /// Update a firewall rule
    FirewallRuleUpdate {
        #[arg(value_name = "RULE_ID")]
        id: String,
        #[arg(long)]
        site: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        action: Option<String>,
        #[arg(long, value_name = "SRC_GROUP")]
        src_group: Option<String>,
        #[arg(long, value_name = "DST_GROUP")]
        dst_group: Option<String>,
    },
    /// Delete a firewall rule
    FirewallRuleDelete {
        #[arg(value_name = "RULE_ID")]
        id: String,
        #[arg(long)]
        site: Option<String>,
        #[arg(long, help = "Show what would be deleted without actually deleting")]
        dry_run: bool,
        #[arg(long, help = "Skip confirmation prompt")]
        yes: bool,
    },
    /// List firewall groups
    FirewallGroups {
        #[arg(long)]
        site: Option<String>,
    },
    /// Create a firewall group
    FirewallGroupCreate {
        #[arg(long)]
        site: Option<String>,
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
    /// Update a firewall group
    FirewallGroupUpdate {
        #[arg(value_name = "GROUP_ID")]
        id: String,
        #[arg(long)]
        site: Option<String>,
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
    /// Delete a firewall group
    FirewallGroupDelete {
        #[arg(value_name = "GROUP_ID")]
        id: String,
        #[arg(long)]
        site: Option<String>,
        #[arg(long, help = "Show what would be deleted without actually deleting")]
        dry_run: bool,
        #[arg(long, help = "Skip confirmation prompt")]
        yes: bool,
    },
    /// Show top clients by bandwidth
    TopClients {
        #[arg(long)]
        site: Option<String>,
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
    /// Show top devices by number of clients (basic heuristic)
    TopDevices {
        #[arg(long)]
        site: Option<String>,
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
    /// DPI applications summary
    Dpi {
        #[arg(long)]
        site: Option<String>,
    },
    /// Traffic statistics
    Traffic {
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
        Commands::Hosts(command) => match command {
            HostsCommand::List => run_get(
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
            HostsCommand::Get { id } => run_get(
                &client,
                &format!("/v1/hosts/{id}"),
                vec![],
                cli.output,
                &render_opts,
                None,
                cli.watch,
            )?,
        },
        Commands::Sites(command) => match command {
            SitesCommand::List { host_id } => {
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
        Commands::Devices(command) => match command {
            DevicesCommand::List { host_id, site_id } => {
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
            DevicesCommand::Get {
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
        Commands::Local(local_cmd) => {
            handle_local(local_cmd, &cwd, cli.output, &render_opts, cli.watch)?;
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
            if let Some(local) = masked.local.as_mut() {
                if local.password.is_some() {
                    local.password = Some("*****".into());
                }
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
        LocalCommands::Sites => {
            let effective = resolve_local(cwd, None)?;
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
        LocalCommands::Devices {
            site,
            unadopted,
            adopt_all,
        } => {
            let effective = resolve_local(cwd, site_override(site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;

            if adopt_all {
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
                                                eprintln!(
                                                    "Failed to adopt {} ({}): {}",
                                                    name, mac, e
                                                );
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
                        return Ok(());
                    }
                }
                println!("No unadopted devices found.");
                return Ok(());
            }

            render_local(
                || {
                    let mut resp = client.list_devices()?;
                    if unadopted {
                        if let Some(mut json) = resp.json.clone() {
                            if let Some(arr) = json.get_mut("data").and_then(|d| d.as_array_mut()) {
                                arr.retain(|item| {
                                    // Filter for unadopted devices (state: "pending" or adopted: false)
                                    let state = item.get("state").and_then(|s| s.as_str());
                                    let adopted = item.get("adopted").and_then(|a| a.as_bool());
                                    state == Some("pending") || adopted == Some(false)
                                });
                                resp.body = serde_json::to_string(&json)
                                    .unwrap_or_else(|_| resp.body.clone());
                                resp.json = Some(json);
                            }
                        }
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
        LocalCommands::Health { site } => {
            let effective = resolve_local(cwd, site_override(site))?;
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
        LocalCommands::Events { site } => {
            let effective = resolve_local(cwd, site_override(site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            render_local(
                || client.list_events(),
                output,
                render_opts,
                Some(&["time", "datetime", "msg", "subsystem", "user", "hostname"]),
                watch,
            )
        }
        LocalCommands::Security { site } => {
            let effective = resolve_local(cwd, site_override(site))?;
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
        LocalCommands::Wan { site } => {
            let effective = resolve_local(cwd, site_override(site))?;
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
        LocalCommands::Networks { site } => {
            let effective = resolve_local(cwd, site_override(site))?;
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
        LocalCommands::Wlans { site } => {
            let effective = resolve_local(cwd, site_override(site))?;
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
        LocalCommands::PortProfiles { site } => {
            let effective = resolve_local(cwd, site_override(site))?;
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
        LocalCommands::FirewallRules { site } => {
            let effective = resolve_local(cwd, site_override(site))?;
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
        LocalCommands::FirewallGroups { site } => {
            let effective = resolve_local(cwd, site_override(site))?;
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
        LocalCommands::Device {
            mac,
            site,
            stats: _,
            config,
            ports,
            restart,
            adopt,
            upgrade,
        } => {
            let effective = resolve_local(cwd, site_override(site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            if restart {
                return render_response(
                    client.device_action(&mac, "restart")?,
                    output,
                    render_opts,
                    None,
                );
            }
            if adopt {
                return render_response(
                    client.device_action(&mac, "adopt")?,
                    output,
                    render_opts,
                    None,
                );
            }
            if upgrade {
                return render_response(
                    client.device_action(&mac, "upgrade")?,
                    output,
                    render_opts,
                    None,
                );
            }
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
        LocalCommands::Clients {
            site,
            wired,
            wireless,
            blocked,
        } => {
            let effective = resolve_local(cwd, site_override(site))?;
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
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false);
                                let is_blocked = item
                                    .get("blocked")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false);
                                if wired && !is_wired {
                                    return false;
                                }
                                if wireless && is_wired {
                                    return false;
                                }
                                if blocked && !is_blocked {
                                    return false;
                                }
                                true
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
                Some(&[
                    "hostname", "name", "mac", "ip", "ap_mac", "essid", "is_wired", "blocked",
                ]),
                watch,
            )
        }
        LocalCommands::Client {
            mac,
            site,
            block,
            unblock,
            reconnect,
        } => {
            let effective = resolve_local(cwd, site_override(site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            let cmd = if block {
                "block-sta"
            } else if unblock {
                "unblock-sta"
            } else if reconnect {
                "kick-sta"
            } else {
                return Err(anyhow!(
                    "Specify an action: --block | --unblock | --reconnect"
                ));
            };
            render_response(client.client_action(&mac, cmd)?, output, render_opts, None)
        }
        LocalCommands::NetworkCreate {
            site,
            name,
            vlan,
            subnet,
            dhcp,
        } => {
            let effective = resolve_local(cwd, site_override(site))?;
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
        LocalCommands::NetworkUpdate {
            id,
            site,
            name,
            vlan,
            subnet,
            dhcp,
        } => {
            let effective = resolve_local(cwd, site_override(site))?;
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
        LocalCommands::NetworkDelete {
            id,
            site,
            dry_run,
            yes,
        } => {
            let effective = resolve_local(cwd, site_override(site))?;
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
        LocalCommands::WlanCreate {
            site,
            name,
            password,
            enabled,
        } => {
            let effective = resolve_local(cwd, site_override(site))?;
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
        LocalCommands::WlanUpdate {
            id,
            site,
            name,
            password,
            enabled,
        } => {
            let effective = resolve_local(cwd, site_override(site))?;
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
        LocalCommands::WlanDelete {
            id,
            site,
            dry_run,
            yes,
        } => {
            let effective = resolve_local(cwd, site_override(site))?;
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
        LocalCommands::FirewallRuleCreate {
            site,
            name,
            action,
            src_group,
            dst_group,
        } => {
            let effective = resolve_local(cwd, site_override(site))?;
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
        LocalCommands::FirewallRuleUpdate {
            id,
            site,
            name,
            action,
            src_group,
            dst_group,
        } => {
            let effective = resolve_local(cwd, site_override(site))?;
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
        LocalCommands::FirewallRuleDelete {
            id,
            site,
            dry_run,
            yes,
        } => {
            let effective = resolve_local(cwd, site_override(site))?;
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
        LocalCommands::FirewallGroupCreate {
            site,
            name,
            group_type,
            members,
        } => {
            let effective = resolve_local(cwd, site_override(site))?;
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
        LocalCommands::FirewallGroupUpdate {
            id,
            site,
            name,
            members,
        } => {
            let effective = resolve_local(cwd, site_override(site))?;
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
        LocalCommands::FirewallGroupDelete {
            id,
            site,
            dry_run,
            yes,
        } => {
            let effective = resolve_local(cwd, site_override(site))?;
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
        LocalCommands::TopClients { site, limit } => {
            let effective = resolve_local(cwd, site_override(site))?;
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
        LocalCommands::TopDevices { site, limit } => {
            let effective = resolve_local(cwd, site_override(site))?;
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
        LocalCommands::Dpi { site } => {
            let effective = resolve_local(cwd, site_override(site))?;
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
        LocalCommands::Traffic { site } => {
            let effective = resolve_local(cwd, site_override(site))?;
            let mut client = LocalClient::new(
                &effective.url,
                &effective.username,
                &effective.password,
                &effective.site,
                effective.verify_tls,
            )?;
            render_local(
                || client.traffic(),
                output,
                render_opts,
                Some(&["ip", "mac", "bytes", "duration"]),
                watch,
            )
        }
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
    if let Some(sort) = &render_opts.sort_by {
        if let Some(idx) = csv_columns.iter().position(|c| c == sort) {
            filtered_rows.sort_by(|a, b| {
                if let (serde_json::Value::Object(a_map), serde_json::Value::Object(b_map)) = (a, b)
                {
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

    if let Some(sort) = &render_opts.sort_by {
        if let Some(idx) = columns.iter().position(|c| c == sort) {
            table.sort_by(|a, b| a[idx].cmp(&b[idx]));
        }
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

# unifictl

CLI for the UniFi Site Manager API (v1/EA). It wraps the documented endpoints (`/v1/hosts`, `/v1/sites`, `/v1/devices`, `/ea/isp-metrics/:type`, `/ea/sd-wan-configs`, etc.), handles the `X-API-Key` header, and stores your key either in the project directory or in the user config directory.

It also supports local UniFi controller access (username/password) for on-prem controllers/UniFi OS gateways.

## Quick start

```bash
cargo build --release
./target/release/unifictl configure --key "<YOUR_API_KEY>"
./target/release/unifictl hosts list
```

### Configuration

- Default base URL: `https://api.ui.com`
- API key lookup order: `--api-key` flag ➜ `.unifictl.yaml` in the current directory ➜ `~/.config/unifictl/config.yaml`
- Save a key locally (portable with the repo): `unifictl configure --key "<KEY>" --scope local`
- Save for the current user: `unifictl configure --key "<KEY>"` (default)
- Local controller credentials (stored in plaintext in the chosen scope):
  ```bash
  # recommended: keep local to the project dir
  unifictl local configure --url https://192.168.1.1:8443 \
      --username admin --password '<PASSWORD>' --site default --scope local
  ```
  Commands will default to the stored site; override with `--site ...`.
  Use `--verify-tls` if your controller has a valid cert; otherwise it will skip TLS verification.

### Common commands

```bash
# Hosts
unifictl hosts list
unifictl hosts get <HOST_ID>

# Sites and devices
unifictl sites list [--host-id <HOST_ID>]
unifictl devices list [--host-id <HOST_ID>] [--site-id <SITE_ID>]
unifictl devices get <DEVICE_ID> [--host-id <HOST_ID>] [--site-id <SITE_ID>]

# ISP metrics (EA)
unifictl isp get --type 5m --site-id <SITE_ID> --start <RFC3339> --end <RFC3339>
unifictl isp query --type hourly --body-file ./query.json

# SD-WAN configs (EA)
unifictl sdwan list
unifictl sdwan get <CONFIG_ID>
unifictl sdwan status <CONFIG_ID>

# Local controller (username/password)
unifictl local sites
unifictl local devices [--site <SITE>]
unifictl local device <MAC> --ports|--config|--restart|--adopt|--upgrade
unifictl local clients [--site <SITE>] [--wired|--wireless|--blocked]
unifictl local client <MAC> --block|--unblock|--reconnect
unifictl local health [--site <SITE>]
unifictl local events [--site <SITE>]
unifictl local networks|wlans|port-profiles|firewall-rules|firewall-groups
unifictl local network create|update|delete ...
unifictl local wlan create|update|delete ...
unifictl local firewall-rule create|update|delete ...
unifictl local firewall-group create|update|delete ...
unifictl local top-clients [--limit N]
unifictl local top-devices [--limit N]
unifictl local dpi
unifictl local traffic

# Output and table controls
unifictl hosts list -o json                    # json/raw/pretty (pretty is default)
unifictl devices list --columns name,ip,model --sort-by name --filter "ap"
unifictl local clients --watch 5               # refresh every 5s
unifictl hosts list --full-ids                 # do not truncate IDs

# Config helpers
unifictl configure --key "<KEY>" --scope local
unifictl config-show
unifictl completion bash|zsh|fish|powershell > /path/to/completion
```

## Testing

```bash
cargo test
```

## Packaging

- **Debian/Ubuntu (`.deb`)**: uses `cargo-deb`.

  ```bash
  cargo install cargo-deb          # once
  cargo deb                        # creates target/debian/unifictl_*.deb
  ```

- **Arch Linux (`.pkg.tar.zst`)**: uses the provided `packaging/arch/PKGBUILD`.

  ```bash
  cargo build --release
  cd packaging/arch && makepkg -sf  # outputs unifictl-<ver>-<arch>.pkg.tar.zst
  ```

Both packaging flows expect the release binary at `target/release/unifictl`.

## Notes

- The ISP metrics and SD-WAN endpoints are under `/ea/...` as per the official Site Manager API docs.
- All requests set `Accept: application/json` and `X-API-Key` automatically; use `--base-url` to point at a different API host if needed.

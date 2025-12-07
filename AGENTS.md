# Project: unifictl

CLI for the UniFi Site Manager API (v1/EA) and local UniFi controllers.

## Tech Stack
- **Language**: Rust (Edition 2024)
- **HTTP Client**: `reqwest` (blocking feature enabled, native-tls-vendored)
- **CLI Framework**: `clap` (derive feature)
- **Serialization**: `serde`, `serde_json`, `serde_yaml`
- **Error Handling**: `anyhow` (app), `thiserror` (lib/modules)
- **Config**: `dirs` for paths, `serde_yaml` for config files
- **Output**: `csv` crate for CSV export

## Architecture
- **Entry Point**: `src/main.rs` - Handles CLI parsing, config loading, and command dispatch.
- **Cloud Client**: `src/client.rs` - API client for `api.ui.com`.
- **Local Client**: `src/local.rs` - Logic for local controller interaction (auth, endpoints).
- **Configuration**: `src/config.rs` - Load/save logic for `~/.config/unifictl` or local `.unifictl.yaml`.

## Development Workflows

### Build
```bash
cargo build
```

### Test
```bash
cargo test
cargo test --test integration_test
```

### Linting & Formatting
```bash
cargo clippy
cargo fmt
```

### Key Conventions
- **Blocking I/O**: The project currently uses synchronous (blocking) I/O with `reqwest::blocking`. Do not introduce async/await unless refactoring the entire core.
- **Error Handling**: Use `anyhow::Result` for fallible CLI commands. Provide context with `.context()`.
- **Configuration**: Respect the precedence: Flag -> Local Config (`.unifictl.yaml`) -> User Config (`~/.config/...`).
- **Output**: Commands typically support `--output json|csv|pretty|raw`.

### CLI Design Philosophy
- **Structure**: Mimic `kubectl` patterns where possible.
- **Naming**: Use **singular** nouns for resources (e.g., `wlan`, `device`, `site`) rather than plurals.
- **Subcommands**: Use standard verbs as subcommands: `list` (or `index`), `get`, `create`, `delete`, `update`.
  - *Goal*: `unifictl wlan list` is preferred over `unifictl wlans`.

## Packaging
- **Debian**: `cargo deb` (via `cargo-deb`).
- **Arch**: `packaging/arch/PKGBUILD`.
- **Homebrew**: `packaging/homebrew`.
- **Winget**: `packaging/winget`.

## Common Tasks
- **Adding a Command**:
  1. Add variant to `Commands` enum in `src/main.rs`.
  2. Implement logic (usually in `src/client.rs` or `src/local.rs`).
    3. Dispatch in `main()`.
  
  ## Troubleshooting Context
  - **UDM Rate Limiting**: Users may hit login rate limits on UDM/UniFi OS gateways because `unifictl` creates a new session for each command.
    - **Symptom**: Repeated 401/Login failed errors.
    - **Fix**: Increase `success.login.limit.count` in `/usr/lib/ulp-go/config.props` on the UDM and restart `unifi-os`.
  
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
- **Output Limiting**: Commands that return arrays/lists should include a `--limit` parameter (default: 30) to prevent overwhelming output. Apply the limit by truncating the array in the response JSON before rendering:
  ```rust
  if let Some(mut json) = resp.json.clone() {
      if let Some(arr) = json.get_mut("data").and_then(|d| d.as_array_mut()) {
          if arr.len() > limit {
              arr.truncate(limit);
          }
      }
      resp.body = serde_json::to_string(&json).unwrap_or_else(|_| resp.body.clone());
      resp.json = Some(json);
  }
  ```
  This pattern should be applied to all list commands that can return large datasets (e.g., `event list`, `client list`, `client active`, `client history`, `device list`).
- **AI-Optimized Output**: Commands support `-o llm` for LLM-optimized output with:
  - Token estimation and tracking
  - Intelligent truncation for large responses (>4000 tokens)
  - JSON schema metadata for field descriptions
  - Statistical summaries and AI guidance
  - Sampling strategy: first 5, middle 5, last 5 items from large arrays

### CLI Design Philosophy
- **Structure**: Mimic `kubectl` patterns where possible.
- **Naming**: Use **singular** nouns for resources (e.g., `wlan`, `device`, `site`) rather than plurals.
- **Subcommands**: Use standard verbs as subcommands: `list` (or `index`), `get`, `create`, `delete`, `update`.
  - *Goal*: `unifictl wlan list` is preferred over `unifictl wlans`.
- **AI-First Commands**: New correlation, diagnostic, and time-series commands reduce API calls and provide aggregated insights:
  - `correlate client/device/ap` - Gather all related data in one command
  - `diagnose network/wifi/client` - Multi-endpoint health checks with recommendations
  - `time-series traffic/wifi/events` - Export historical data for trend analysis

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
  4. **Write tests**: Add unit tests for the new methods in the respective module.
  5. **Test manually**: After compilation succeeds, test the CLI command with a real UniFi controller/environment:
     - Verify the command executes without errors
     - Check output format (json, csv, pretty, raw)
     - Validate response data structure matches expectations
     - Test edge cases (missing data, errors, etc.)

## Testing Requirements

### Unit Tests
- All new methods in `src/local.rs` and `src/client.rs` must have corresponding unit tests.
- Tests should be placed in the `#[cfg(test)]` module at the bottom of each file.
- Use `httpmock` for mocking HTTP responses (see existing test patterns in `src/local.rs` and `src/client.rs`).
- Test both success and error cases where applicable.
- Example test pattern:
  ```rust
  #[test]
  fn test_new_method() {
      let server = MockServer::start();
      let mock = server.mock(|when, then| {
          when.method(GET)
              .path("/proxy/network/v2/api/site/default/clients/active");
          then.status(200).json_body(json!({"data": []}));
      });
      
      let mut client = LocalClient::new(&server.base_url(), "u", "p", "default", true).unwrap();
      let resp = client.clients_v2_active().unwrap();
      
      mock.assert();
      assert_eq!(resp.status, 200);
  }
  ```

### Manual Testing
After implementing a new command, **always** test it manually with a real UniFi controller:

1. **Compile and build**:
   ```bash
   cargo build
   ```

2. **Test the command** with your local UniFi controller environment:
   ```bash
   # Test basic functionality
   unifictl local <command> <subcommand>
   
   # Test with different output formats
   unifictl local <command> <subcommand> -o json
   unifictl local <command> <subcommand> -o csv
   unifictl local <command> <subcommand> -o pretty
   
   # Test with filters/options
   unifictl local <command> <subcommand> --site <SITE>
   ```

3. **Verify output**:
   - Check that JSON output is valid and contains expected fields
   - Verify CSV output is properly formatted
   - Ensure pretty table output displays correctly
   - **Test LLM output** (`-o llm`) includes metadata, token estimates, and schemas
   - Test error handling with invalid inputs

4. **Update EXAMPLES.md** with working examples of the new command.

### Automated Endpoint Testing
**All new endpoints must be added to `test_all_endpoints.sh`**:
- Every new command/subcommand implementation must include a corresponding test case in `test_all_endpoints.sh`
- The test should call the endpoint with appropriate demo parameters (if required)
- Use the `test_command` function with the command string and expected exit code
- For endpoints that may return 404 on some controller types, specify the expected exit code (e.g., `test_command "Name" "$BINARY command" 1`)
- Ensure the test uses `-o json` output format for consistent validation
- Example:
  ```bash
  test_command "New Endpoint" "$BINARY local new-command list -o json"
  test_command "New Endpoint with Params" "$BINARY local new-command get --id test-id -o json"
  ```
- After adding a new endpoint, run `bash test_all_endpoints.sh endpoint_test_results.log` to verify it passes

### Test Checklist
- [ ] Code compiles without warnings (`cargo check`)
- [ ] Code is formatted (`cargo fmt`)
- [ ] Unit tests pass (`cargo test`)
- [ ] Manual CLI test with real controller succeeds
- [ ] All output formats work correctly (json, csv, pretty, raw, llm)
- [ ] LLM output includes token estimates and metadata (if applicable)
- [ ] Error handling works as expected
- [ ] EXAMPLES.md updated with new command examples
- [ ] Endpoint added to `test_all_endpoints.sh` and test passes

## Troubleshooting Context
  - **UDM Rate Limiting**: Users may hit login rate limits on UDM/UniFi OS gateways because `unifictl` creates a new session for each command.
    - **Symptom**: Repeated 401/Login failed errors.
    - **Fix**: Increase `success.login.limit.count` in `/usr/lib/ulp-go/config.props` on the UDM and restart `unifi-os`.
  
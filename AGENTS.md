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

## CI/CD and GitHub Actions

### Pre-Commit Checklist
**ALWAYS run these before committing:**
1. **Format code**: `cargo fmt --all` - The CI pipeline will fail if code is not formatted
2. **Check compilation**: `cargo check` - Ensures code compiles without errors
3. **Run tests**: `cargo test` - Ensures all tests pass, including unit tests
4. **Verify test signatures**: When adding or modifying methods, ensure all test calls match the method signature (parameters, return types)

### Common CI/CD Issues and Solutions

#### 1. Code Formatting Failures
**Problem**: CI fails with "Diff in..." errors indicating formatting issues.

**Prevention**:
- Always run `cargo fmt --all` before committing
- Consider using a pre-commit hook or IDE auto-format on save
- The CI workflow runs `cargo fmt --all -- --check` which will fail if formatting differs

**Fix**: Run `cargo fmt --all` locally and commit the changes.

#### 2. Test Compilation Errors
**Problem**: Tests fail to compile because method signatures don't match their usage.

**Prevention**:
- When modifying method signatures, update all test calls immediately
- Run `cargo test` locally before pushing
- Pay attention to required parameters - if a method requires a query parameter, tests must provide it

**Example**: If `traffic_stats(&mut self, query: &serde_json::Value)` requires a query parameter, tests must call it with:
```rust
let query = json!({"start": 0, "end": 1000, "includeUnidentified": false});
let resp = client.traffic_stats(&query).unwrap();
```

**Fix**: Update test calls to match the current method signature.

#### 3. GitHub Actions Workflow Issues

##### Release Workflow - Checksums Display
**Problem**: Release notes show file paths instead of actual checksum content.

**Prevention**:
- When using GitHub Actions outputs with multiline content, use the proper multiline delimiter syntax:
  ```yaml
  {
    echo 'output_name<<DELIMITER'
    cat file.txt
    echo 'DELIMITER'
  } >> $GITHUB_OUTPUT
  ```
- Always test workflow changes with a dry-run or test release before production

**Fix**: Use multiline output syntax to read file contents, not file paths.

##### Workflow Syntax
- Always validate YAML syntax before committing workflow changes
- Test workflow changes in a branch before merging to master
- Use `gh run list` and `gh run view` to debug failed workflows

### GitHub Actions Workflow Structure

#### CI Workflow (`.github/workflows/ci.yml`)
- Runs on every push/PR to master/main
- Checks: Format, Clippy, Tests (multi-platform), Security audit
- **Must pass before merging**

#### Release Workflow (`.github/workflows/release.yml`)
- Triggers on version tags (`v*.*.*`) or manual dispatch
- Builds binaries for multiple platforms
- Creates GitHub releases with artifacts
- Publishes to crates.io (if token is configured)

**Key Points**:
- Version handling: Tags include 'v' prefix, but package versions don't
- Artifact paths: Artifacts are downloaded to subdirectories, use `artifacts/**/*` patterns
- Checksums: Must read file contents, not display paths

### Workflow Debugging
```bash
# List recent workflow runs
gh run list --limit 10

# View failed steps from a run
gh run view <run-id> --log-failed

# View full logs
gh run view <run-id> --log
```

### Best Practices
1. **Always test locally first**: Run `cargo fmt`, `cargo test`, `cargo check` before pushing
2. **Check CI status**: Monitor GitHub Actions after pushing to ensure workflows pass
3. **Fix issues immediately**: Don't let CI failures accumulate
4. **Document workflow changes**: Update this file when modifying workflows
5. **Test workflow changes**: Use workflow_dispatch or test branches to verify changes

## Troubleshooting Context
  - **UDM Rate Limiting**: Users may hit login rate limits on UDM/UniFi OS gateways because `unifictl` creates a new session for each command.
    - **Symptom**: Repeated 401/Login failed errors.
    - **Fix**: Increase `success.login.limit.count` in `/usr/lib/ulp-go/config.props` on the UDM and restart `unifi-os`.
  
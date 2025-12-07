# GitHub Actions Workflows

This directory contains CI/CD workflows for the unifictl project.

## Workflows

### `ci.yml` - Fast CI Checks
**Triggers:** Push and PR to master/main

Runs quick checks on every push/PR:
- **Format Check**: Ensures code follows Rust formatting standards
- **Clippy Lint**: Catches common mistakes and enforces best practices
- **Tests**: Runs test suite on Ubuntu, macOS, and Windows
- **Security Audit**: Scans dependencies for known vulnerabilities

**Duration:** ~5-10 minutes

### `test.yml` - Comprehensive Test Suite
**Triggers:** Push and PR to master/main

Runs extensive testing:
- **Multi-version Testing**: Tests on stable, beta, and nightly Rust
- **Format & Clippy**: Only on stable Rust
- **Integration Tests**: Separate job for integration test suite
- **Security Audit**: Dependency vulnerability scanning

**Duration:** ~15-20 minutes

### `release.yml` - Build and Release
**Triggers:** 
- Push of version tags (e.g., `v0.4.0`)
- Manual workflow dispatch

**Jobs:**
1. **build-release**: Builds release binaries for multiple platforms:
   - **Linux**: x86_64, aarch64
   - **macOS**: x86_64, aarch64 (Apple Silicon)
2. **build-arch-packages**: Builds Arch Linux packages (.pkg.tar.zst)
3. **publish-crates-io**: Automatically publishes to crates.io (requires `CRATES_IO_TOKEN` secret)
4. **create-release**: Creates GitHub Release with artifacts

**Outputs:**
- Release archives (`.tar.gz` for Unix)
- Arch Linux packages (`.pkg.tar.zst`)
- Checksums file (`checksums.txt`)
- GitHub Release with download links
- Published to crates.io

**Duration:** ~30-45 minutes

**Required Secrets:**
- `CRATES_IO_TOKEN`: crates.io API token for automated publishing (get from https://crates.io/me)

## Usage

### Running Tests Locally
```bash
# Format check
cargo fmt --all -- --check

# Clippy
cargo clippy --all-targets --all-features -- -D warnings

# Tests
cargo test --all-targets

# Integration tests
cargo test --test integration_test
```

### Creating a Release

**Automatic (Recommended):**
```bash
# Create and push a version tag
git tag v0.3.0
git push origin v0.3.0
```

**Manual:**
1. Go to GitHub Actions
2. Select "Release" workflow
3. Click "Run workflow"
4. Enter version tag (e.g., `v0.3.0`)
5. Click "Run workflow"

### Release Artifacts

After a release is created, artifacts will be available at:
- GitHub Releases page
- Download links in release notes
- Checksums for verification

## Workflow Status

View workflow runs at: https://github.com/nachtschatt3n/unifictl/actions

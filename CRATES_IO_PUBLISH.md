# Publishing to crates.io

This guide explains how to publish `unifictl` to crates.io.

## Prerequisites

1. **crates.io Account**: Create an account at https://crates.io
2. **API Token**: Get your API token from https://crates.io/me
3. **Login**: Run `cargo login <your-token>` to authenticate

## Pre-Publication Checklist

Before publishing, ensure:

- ✅ All tests pass: `cargo test --all-targets`
- ✅ Code is formatted: `cargo fmt --all`
- ✅ Clippy passes: `cargo clippy --all-targets --all-features`
- ✅ Version is updated in `Cargo.toml`
- ✅ README.md is up to date
- ✅ LICENSE file is present
- ✅ All changes are committed to git
- ✅ Dry-run succeeds: `cargo publish --dry-run`

## Publishing Steps

### 1. Verify Package Metadata

Check that `Cargo.toml` has all required fields:

```toml
[package]
name = "unifictl"
version = "0.4.0"
edition = "2024"
description = "CLI for UniFi Site Manager (API v1/EA)"
license = "GPL-3.0"
repository = "https://github.com/nachtschatt3n/unifictl"
homepage = "https://github.com/nachtschatt3n/unifictl"
authors = ["Mathias Uhl <mathiasuhl@gmx.de>"]
keywords = ["unifi", "ubiquiti", "cli", "network", "api", "site-manager"]
categories = ["command-line-utilities", "network-programming"]
readme = "README.md"
```

### 2. Run Dry-Run

Test the package before publishing:

```bash
cargo publish --dry-run
```

This will:
- Package the crate
- Verify it builds
- Show what would be uploaded
- **NOT** actually publish to crates.io

### 3. Publish

Once dry-run succeeds, publish:

```bash
cargo publish
```

**Note**: Publishing is **permanent**. Once published, you cannot:
- Delete a version
- Overwrite a version
- Unpublish a version (except within 24 hours with special circumstances)

### 4. Verify Publication

After publishing, verify at:
- https://crates.io/crates/unifictl
- https://crates.io/crates/unifictl/0.4.0

## Updating the Package

For new versions:

1. **Update version** in `Cargo.toml`:
   ```toml
   version = "0.5.0"  # Increment appropriately
   ```

2. **Update Cargo.lock**:
   ```bash
   cargo update
   ```

3. **Test**:
   ```bash
   cargo test --all-targets
   cargo publish --dry-run
   ```

4. **Publish**:
   ```bash
   cargo publish
   ```

## Versioning Guidelines

Follow [Semantic Versioning](https://semver.org/):

- **MAJOR** (1.0.0): Breaking changes
- **MINOR** (0.1.0): New features, backward compatible
- **PATCH** (0.0.1): Bug fixes, backward compatible

For pre-1.0 versions (like 0.4.0), breaking changes can increment MINOR.

## Automated Publishing (Recommended)

Publishing to crates.io is **automated** via GitHub Actions! When you create a release (by pushing a tag), the workflow will:

1. ✅ Run tests
2. ✅ Check formatting
3. ✅ Run Clippy
4. ✅ Verify version matches Cargo.toml
5. ✅ Dry-run publish
6. ✅ Publish to crates.io

### Setup

1. **Get your crates.io API token**:
   - Visit https://crates.io/me
   - Generate a new token (or use existing one)

2. **Add token to GitHub Secrets**:
   - Go to your repository → Settings → Secrets and variables → Actions
   - Click "New repository secret"
   - Name: `CRATES_IO_TOKEN`
   - Value: Your crates.io API token
   - Click "Add secret"

3. **That's it!** The next time you push a version tag, it will automatically publish to crates.io.

### Manual Publishing (Fallback)

If you need to publish manually (e.g., if automation fails):

```bash
# Login first
cargo login <your-token>

# Test
cargo publish --dry-run

# Publish
cargo publish
```

Or use the helper script:
```bash
./publish-crate.sh
```

## Troubleshooting

### "edition 2024 is not supported"

If crates.io doesn't support Rust edition 2024 yet, change to 2021:

```toml
edition = "2021"
```

### "package contains uncommitted changes"

Commit all changes before publishing:

```bash
git add .
git commit -m "Prepare for release v0.4.0"
```

### "package size exceeds limit"

crates.io has a 10MB limit per crate. If you exceed this:
- Remove unnecessary files from the package
- Use `.cargoignore` to exclude files

### "license file not found"

Ensure `LICENSE` file exists in the repository root.

## Resources

- [crates.io Documentation](https://doc.rust-lang.org/cargo/reference/publishing.html)
- [Semantic Versioning](https://semver.org/)
- [crates.io Categories](https://crates.io/category_slugs)
- [crates.io Keywords](https://crates.io/keywords)

# Automated crates.io Publishing Setup

The release workflow now automatically publishes to crates.io when a release is created.

## How It Works

When you push a version tag (e.g., `v0.4.0`), the workflow will:

1. ✅ Build release binaries for all platforms
2. ✅ Build Arch Linux packages
3. ✅ **Automatically publish to crates.io** (if token is configured)
4. ✅ Create GitHub Release with artifacts

## Setup Instructions

### 1. Get Your crates.io API Token

1. Visit https://crates.io
2. Log in (or create an account)
3. Go to https://crates.io/me
4. Click "New Token" or copy an existing token
5. Give it a name (e.g., "GitHub Actions")

### 2. Add Token to GitHub Secrets

1. Go to your repository on GitHub
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Click **"New repository secret"**
4. Name: `CRATES_IO_TOKEN`
5. Value: Paste your crates.io API token
6. Click **"Add secret"**

### 3. Verify Setup

The next time you create a release, check the workflow logs:

1. Go to **Actions** tab
2. Find the "Release" workflow run
3. Look for the "Publish to crates.io" job
4. It should show "Publishing..." and succeed

## What Gets Published

The workflow publishes:
- ✅ The crate as defined in `Cargo.toml`
- ✅ With all metadata (keywords, categories, description)
- ✅ README.md is included
- ✅ LICENSE file is included

## Version Verification

The workflow verifies that:
- The tag version matches `Cargo.toml` version
- All tests pass
- Code is properly formatted
- Clippy checks pass
- Package builds successfully

## Troubleshooting

### "CRATES_IO_TOKEN secret not set"

**Solution**: Add the `CRATES_IO_TOKEN` secret to your repository settings (see Setup Instructions above).

### "Version mismatch"

**Error**: `Cargo.toml version (0.4.0) doesn't match tag version (v0.4.0)`

**Solution**: Ensure the version in `Cargo.toml` matches the tag (without the 'v' prefix). For tag `v0.4.0`, `Cargo.toml` should have `version = "0.4.0"`.

### "Package already exists"

**Error**: `crate `unifictl` version 0.4.0 is already uploaded`

**Solution**: This version was already published. You cannot republish the same version. Either:
- Use a new version number
- Or if within 24 hours, you can yank the version: `cargo yank --vers 0.4.0`

### "Tests failed"

**Solution**: Fix failing tests before publishing. The workflow runs `cargo test --all-targets` before publishing.

## Manual Override

If you need to publish manually (e.g., automation failed):

```bash
# Login
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

## Security Notes

- ✅ The token is stored securely in GitHub Secrets
- ✅ The token is only used during the publish step
- ✅ The token is never exposed in logs
- ✅ You can revoke the token at any time from crates.io

## Resources

- [crates.io Documentation](https://doc.rust-lang.org/cargo/reference/publishing.html)
- [GitHub Secrets Documentation](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [crates.io Token Management](https://crates.io/me)

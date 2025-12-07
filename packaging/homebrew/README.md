# Homebrew Formula for unifictl

This directory contains the Homebrew formula for unifictl.

## Usage

### Installing from tap (if hosted in this repo)

```bash
brew tap nachtschatt3n/unifictl
brew install unifictl
```

### Updating the formula

Use the `update-formula.sh` script to update the formula with a new version:

```bash
./packaging/homebrew/update-formula.sh 0.4.5
```

This will:
1. Download the release binaries
2. Calculate SHA256 checksums
3. Update the formula file with new version and checksums

### Submitting to homebrew-core

To submit to the official Homebrew repository:

1. Fork https://github.com/Homebrew/homebrew-core
2. Create a new formula file: `Formula/u/unifictl.rb`
3. Copy the formula content
4. Submit a PR

Or use the `brew bump-formula-pr` command:

```bash
brew bump-formula-pr unifictl --url https://github.com/nachtschatt3n/unifictl/releases/download/v0.4.4/unifictl-x86_64-apple-darwin.tar.gz
```

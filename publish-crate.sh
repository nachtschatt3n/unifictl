#!/bin/bash
# Helper script to publish unifictl to crates.io

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🚀 Publishing unifictl to crates.io"
echo ""

# Check if logged in
if ! cargo login --check 2>/dev/null; then
    echo "❌ Not logged in to crates.io"
    echo "   Run: cargo login <your-token>"
    echo "   Get your token from: https://crates.io/me"
    exit 1
fi

# Check for uncommitted changes
if ! git diff-index --quiet HEAD -- 2>/dev/null; then
    echo "⚠️  Warning: You have uncommitted changes"
    echo "   cargo publish requires a clean git working directory"
    read -p "   Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Run tests
echo "📋 Running tests..."
if ! cargo test --all-targets; then
    echo "❌ Tests failed!"
    exit 1
fi

# Check formatting
echo "📋 Checking formatting..."
if ! cargo fmt --all -- --check; then
    echo "⚠️  Code is not formatted. Run: cargo fmt --all"
    read -p "   Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Run clippy
echo "📋 Running clippy..."
if ! cargo clippy --all-targets --all-features -- -W clippy::all 2>/dev/null; then
    echo "⚠️  Clippy found issues"
    read -p "   Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Dry run
echo "📋 Running dry-run..."
if ! cargo publish --dry-run; then
    echo "❌ Dry-run failed!"
    exit 1
fi

# Show package info
VERSION=$(grep '^version =' Cargo.toml | cut -d'"' -f2)
echo ""
echo "📦 Package: unifictl v$VERSION"
echo ""

# Confirm
read -p "🚀 Publish to crates.io? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# Publish
echo ""
echo "🚀 Publishing..."
if cargo publish; then
    echo ""
    echo "✅ Successfully published unifictl v$VERSION!"
    echo ""
    echo "📦 View at: https://crates.io/crates/unifictl"
    echo "📦 Version: https://crates.io/crates/unifictl/$VERSION"
else
    echo ""
    echo "❌ Publication failed!"
    exit 1
fi

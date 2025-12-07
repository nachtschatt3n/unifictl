#!/bin/bash
# Script to update Homebrew formula with new version and checksums

set -e

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 0.4.5"
    exit 1
fi

# Remove 'v' prefix if present
VERSION=${VERSION#v}

FORMULA_FILE="packaging/homebrew/Formula/unifictl.rb"

# Download and calculate checksums
echo "Downloading binaries and calculating checksums..."

X86_64_URL="https://github.com/nachtschatt3n/unifictl/releases/download/v${VERSION}/unifictl-x86_64-apple-darwin.tar.gz"
ARM64_URL="https://github.com/nachtschatt3n/unifictl/releases/download/v${VERSION}/unifictl-aarch64-apple-darwin.tar.gz"

# Download temporarily to calculate checksums
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

curl -L -o "$TMPDIR/x86_64.tar.gz" "$X86_64_URL" 2>/dev/null || echo "Warning: Could not download x86_64 binary"
curl -L -o "$TMPDIR/arm64.tar.gz" "$ARM64_URL" 2>/dev/null || echo "Warning: Could not download arm64 binary"

X86_64_SHA=$(sha256sum "$TMPDIR/x86_64.tar.gz" 2>/dev/null | cut -d' ' -f1 || echo "")
ARM64_SHA=$(sha256sum "$TMPDIR/arm64.tar.gz" 2>/dev/null | cut -d' ' -f1 || echo "")

# Update formula file
sed -i.bak "s/version \"[^\"]*\"/version \"${VERSION}\"/" "$FORMULA_FILE"
sed -i.bak "s|url \".*unifictl-x86_64-apple-darwin.tar.gz\"|url \"${X86_64_URL}\"|" "$FORMULA_FILE"
sed -i.bak "s|url \".*unifictl-aarch64-apple-darwin.tar.gz\"|url \"${ARM64_URL}\"|" "$FORMULA_FILE"

if [ -n "$X86_64_SHA" ]; then
    sed -i.bak "s/sha256 \"\" # Will be updated automatically/sha256 \"${X86_64_SHA}\"/" "$FORMULA_FILE"
fi

# Update ARM64 SHA (need to handle both instances)
if [ -n "$ARM64_SHA" ]; then
    # Update the second sha256 (ARM64)
    awk -v sha="$ARM64_SHA" '
        /sha256.*arm/ { 
            if (found_arm == 0) {
                found_arm = 1
                next
            }
            if (found_arm == 1 && /sha256/) {
                gsub(/sha256 \"[^\"]*\"/, "sha256 \"" sha "\"")
                found_arm = 2
            }
        }
        { print }
    ' "$FORMULA_FILE" > "$FORMULA_FILE.tmp" && mv "$FORMULA_FILE.tmp" "$FORMULA_FILE"
fi

rm -f "$FORMULA_FILE.bak"

echo "Updated $FORMULA_FILE with version $VERSION"
echo "x86_64 SHA: $X86_64_SHA"
echo "arm64 SHA: $ARM64_SHA"

#!/bin/bash
# Script to update winget manifest with new version and checksum

set -e

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 0.4.5"
    exit 1
fi

# Remove 'v' prefix if present
VERSION=${VERSION#v}

MANIFEST_FILE="packaging/winget/unifictl.yaml"
LOCALE_FILE="packaging/winget/unifictl.locale.en-US.yaml"

# Download and calculate checksum
echo "Downloading Windows binary and calculating checksum..."

ZIP_URL="https://github.com/nachtschatt3n/unifictl/releases/download/v${VERSION}/unifictl-x86_64-pc-windows-msvc.zip"

# Download temporarily to calculate checksum
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

curl -L -o "$TMPDIR/unifictl.zip" "$ZIP_URL" 2>/dev/null || {
    echo "Error: Could not download Windows binary from $ZIP_URL"
    exit 1
}

SHA=$(sha256sum "$TMPDIR/unifictl.zip" | cut -d' ' -f1)

# Update version manifest
sed -i.bak "s/PackageVersion: [0-9.]*/PackageVersion: ${VERSION}/" "$MANIFEST_FILE"
sed -i.bak "s|InstallerUrl: .*|InstallerUrl: ${ZIP_URL}|" "$MANIFEST_FILE"
sed -i.bak "s|InstallerSha256: .*|InstallerSha256: ${SHA}|" "$MANIFEST_FILE"

# Update locale manifest
sed -i.bak "s/PackageVersion: [0-9.]*/PackageVersion: ${VERSION}/" "$LOCALE_FILE"

rm -f "$MANIFEST_FILE.bak" "$LOCALE_FILE.bak"

echo "Updated manifests with version $VERSION"
echo "SHA256: $SHA"
echo ""
echo "To submit to winget-pkgs:"
echo "1. Fork https://github.com/microsoft/winget-pkgs"
echo "2. Copy manifests to manifests/n/nachtschatt3n/unifictl/${VERSION}/"
echo "3. Submit a PR"

#!/bin/bash
# Helper script to update the AUR package

set -e

VERSION=$1
if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 0.4.0"
    exit 1
fi

# Remove 'v' prefix if present
VERSION=${VERSION#v}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
AUR_DIR="$HOME/aur-unifictl"

echo "Updating AUR package to version $VERSION"

# Clone AUR repo if it doesn't exist
if [ ! -d "$AUR_DIR" ]; then
    echo "Cloning AUR repository..."
    git clone ssh://aur@aur.archlinux.org/unifictl.git "$AUR_DIR"
fi

cd "$AUR_DIR"
echo "Pulling latest changes from AUR..."
git pull || true

# Copy the AUR PKGBUILD template
cp "$SCRIPT_DIR/PKGBUILD.aur" PKGBUILD

# Update version in PKGBUILD
sed -i "s/^pkgver=.*/pkgver=$VERSION/" PKGBUILD
sed -i "s/^pkgrel=.*/pkgrel=1/" PKGBUILD

# Calculate SHA256 checksum for the source tarball
echo "Calculating SHA256 checksum..."
SOURCE_URL="https://github.com/nachtschatt3n/unifictl/archive/v$VERSION.tar.gz"
SHA256=$(curl -sL "$SOURCE_URL" | sha256sum | cut -d' ' -f1)
sed -i "s/^sha256sums=.*/sha256sums=('$SHA256')/" PKGBUILD

# Regenerate .SRCINFO
echo "Generating .SRCINFO..."
makepkg --printsrcinfo > .SRCINFO

# Show what changed
echo ""
echo "Changes to be committed:"
git diff PKGBUILD .SRCINFO || true

# Ask for confirmation
echo ""
read -p "Push to AUR? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    git add PKGBUILD .SRCINFO
    git commit -m "Update to version $VERSION"
    git push origin master
    echo ""
    echo "✓ Successfully pushed to AUR!"
    echo "  View at: https://aur.archlinux.org/packages/unifictl"
else
    echo "Aborted. Changes are in $AUR_DIR"
fi

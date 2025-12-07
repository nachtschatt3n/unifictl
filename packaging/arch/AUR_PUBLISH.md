# Publishing to AUR (Arch User Repository)

This guide explains how to publish `unifictl` to the AUR.

## Prerequisites

1. **AUR Account**: Create an account at https://aur.archlinux.org
2. **SSH Key**: Add your SSH public key to your AUR account profile
3. **Git**: Ensure git is installed

## Initial Setup (First Time Only)

1. **Clone the AUR repository**:
   ```bash
   git clone ssh://aur@aur.archlinux.org/unifictl.git aur-unifictl
   cd aur-unifictl
   ```

2. **Copy the AUR PKGBUILD**:
   ```bash
   cp /path/to/unifictl/packaging/arch/PKGBUILD.aur PKGBUILD
   ```

3. **Generate .SRCINFO**:
   ```bash
   makepkg --printsrcinfo > .SRCINFO
   ```

4. **Commit and push**:
   ```bash
   git add PKGBUILD .SRCINFO
   git commit -m "Initial AUR package for unifictl"
   git push origin master
   ```

## Updating the Package

When releasing a new version:

1. **Update PKGBUILD**:
   ```bash
   cd aur-unifictl
   # Edit PKGBUILD and update pkgver
   sed -i 's/^pkgver=.*/pkgver=0.4.0/' PKGBUILD
   ```

2. **Regenerate .SRCINFO**:
   ```bash
   makepkg --printsrcinfo > .SRCINFO
   ```

3. **Test the build** (optional but recommended):
   ```bash
   makepkg -s
   ```

4. **Commit and push**:
   ```bash
   git add PKGBUILD .SRCINFO
   git commit -m "Update to version 0.4.0"
   git push origin master
   ```

## Quick Update (Using Helper Script)

The easiest way to update the AUR package is using the provided helper script:

```bash
cd packaging/arch
./update-aur.sh 0.4.0
```

This script will:
1. Clone the AUR repository (if needed)
2. Update PKGBUILD with the new version
3. Calculate SHA256 checksum for the source tarball
4. Regenerate .SRCINFO
5. Show you the changes
6. Ask for confirmation before pushing

## Manual Update Process

If you prefer to update manually, follow the steps in the "Updating the Package" section above.

## Notes

- AUR packages must build from source (no pre-built binaries)
- The PKGBUILD.aur file downloads source from GitHub releases
- Always update both PKGBUILD and .SRCINFO when releasing
- Test builds locally before pushing to AUR
- AUR has strict rules - ensure your PKGBUILD follows AUR guidelines

## Resources

- AUR Package Guidelines: https://wiki.archlinux.org/title/AUR_submission_guidelines
- PKGBUILD Reference: https://wiki.archlinux.org/title/PKGBUILD
- AUR Help: https://wiki.archlinux.org/title/AUR_User_Guidelines

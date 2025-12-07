# winget Manifest for unifictl

This directory contains the winget manifests for unifictl.

## Files

- `unifictl.yaml` - Version manifest (defines installer)
- `unifictl.locale.en-US.yaml` - Locale manifest (defines metadata)

## Updating the manifest

Use the `update-manifest.sh` script to update the manifest with a new version:

```bash
./packaging/winget/update-manifest.sh 0.4.5
```

This will:
1. Download the Windows release binary
2. Calculate SHA256 checksum
3. Update both manifest files with new version and checksum

## Submitting to winget-pkgs

To submit to the official winget repository:

1. Fork https://github.com/microsoft/winget-pkgs
2. Create directory: `manifests/n/nachtschatt3n/unifictl/<version>/`
3. Copy both manifest files to that directory
4. Submit a PR

Or use the winget-pkgs-publisher GitHub Action (see workflow example).

## Testing locally

You can test the manifest locally using winget:

```powershell
winget install --manifest packaging/winget/unifictl.yaml
```

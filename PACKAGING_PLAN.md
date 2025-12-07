# Packaging and CI Improvement Plan

## Overview
This plan outlines the steps to:
1. Resolve Windows CI stack overflow issue
2. Build DEB packages for Ubuntu/Debian
3. Build Homebrew packages for macOS
4. Build winget packages for Windows

---

## 1. Resolve Windows CI Stack Overflow Issue

### Problem
Integration tests on Windows are failing with stack overflow errors:
```
thread 'main' has overflowed its stack
```

### Root Cause Analysis
- Windows has a smaller default stack size (~1MB) compared to Linux/macOS
- Integration tests using `assert_cmd` may be creating deep call stacks
- The test binary might need explicit stack size configuration

### Solution Steps

#### Option A: Increase Stack Size (Recommended)
1. **Modify integration test setup**
   - Add `#![windows_subsystem = "console"]` to test file
   - Use linker flags to increase stack size
   - Configure in `.cargo/config.toml` or test binary

2. **Update CI workflow**
   - Add Windows-specific environment variables
   - Set `RUSTFLAGS` with stack size options
   - Or use `cargo test` with `--test-threads=1` to reduce parallelism

#### Option B: Refactor Tests
1. Split large test functions into smaller ones
2. Reduce recursion depth in test helpers
3. Use iterative approaches instead of recursive

#### Option C: Skip Problematic Tests on Windows
1. Add `#[cfg(not(target_os = "windows"))]` to problematic tests
2. Create Windows-specific test variants

### Implementation Priority
- **Priority**: High
- **Estimated Time**: 1-2 hours
- **Files to Modify**:
  - `tests/integration_test.rs`
  - `.github/workflows/ci.yml`
  - Possibly `.cargo/config.toml`

---

## 2. Build DEB Package for Ubuntu/Debian

### Current State
- `Cargo.toml` already has `[package.metadata.deb]` section configured
- No automated DEB build in CI/CD yet

### Solution Steps

1. **Install cargo-deb in CI**
   ```yaml
   - name: Install cargo-deb
     run: cargo install cargo-deb
   ```

2. **Build DEB package**
   ```yaml
   - name: Build DEB package
     run: cargo deb --target x86_64-unknown-linux-gnu
   ```

3. **Build for multiple architectures**
   - x86_64 (amd64)
   - aarch64 (arm64) - requires cross-compilation setup

4. **Upload artifacts**
   - Upload `.deb` files as artifacts
   - Include in release assets

### File Structure
```
packaging/deb/
  ├── control (optional, if custom control file needed)
  └── README.md (documentation)
```

### Implementation Details

#### Add to release.yml workflow:
```yaml
build-deb-packages:
  name: Build DEB Packages
  runs-on: ubuntu-latest
  strategy:
    fail-fast: false
    matrix:
      arch: [amd64, arm64]
      include:
        - arch: amd64
          target: x86_64-unknown-linux-gnu
        - arch: arm64
          target: aarch64-unknown-linux-gnu
  
  steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Install Rust toolchain
      uses: dtolnay/rust-toolchain@stable
      with:
        targets: ${{ matrix.target }}
    
    - name: Install cargo-deb
      run: cargo install cargo-deb
    
    - name: Install cross-compilation dependencies (arm64)
      if: matrix.arch == 'arm64'
      run: |
        sudo apt-get update
        sudo apt-get install -y \
          gcc-aarch64-linux-gnu \
          g++-aarch64-linux-gnu \
          libc6-dev-arm64-cross
    
    - name: Build binary
      run: |
        cargo build --release --target ${{ matrix.target }}
        strip target/${{ matrix.target }}/release/unifictl || true
      env:
        # Add cross-compilation env vars for arm64
    
    - name: Build DEB package
      run: cargo deb --target ${{ matrix.target }} --no-build
    
    - name: Rename DEB file
      run: |
        VERSION=$(grep '^version =' Cargo.toml | cut -d'"' -f2)
        mv target/${{ matrix.target }}/debian/unifictl_*.deb \
           unifictl_${VERSION}_${{ matrix.arch }}.deb
    
    - name: Upload artifact
      uses: actions/upload-artifact@v4
      with:
        name: unifictl-deb-${{ matrix.arch }}
        path: unifictl_*_${{ matrix.arch }}.deb
```

### Implementation Priority
- **Priority**: High
- **Estimated Time**: 2-3 hours
- **Files to Create/Modify**:
  - `.github/workflows/release.yml` (add new job)
  - `packaging/deb/README.md` (documentation)

---

## 3. Build Homebrew Package for macOS

### Current State
- No Homebrew formula exists
- Binaries are built for macOS but not packaged

### Solution Steps

1. **Create Homebrew formula**
   - Create `Formula/unifictl.rb` file
   - Follow Homebrew formula conventions
   - Use GitHub releases as source

2. **Formula Structure**
   ```ruby
   class Unifictl < Formula
     desc "CLI for UniFi Site Manager (API v1/EA)"
     homepage "https://github.com/nachtschatt3n/unifictl"
     url "https://github.com/nachtschatt3n/unifictl/releases/download/v0.4.4/unifictl-x86_64-apple-darwin.tar.gz"
     sha256 "..."
     license "GPL-3.0"
     
     if Hardware::CPU.arm?
       url "https://github.com/nachtschatt3n/unifictl/releases/download/v0.4.4/unifictl-aarch64-apple-darwin.tar.gz"
       sha256 "..."
     end
     
     def install
       bin.install "unifictl"
     end
     
     test do
       system "#{bin}/unifictl", "--version"
     end
   end
   ```

3. **Automated Formula Updates**
   - Create script to update formula version/checksums
   - Add GitHub Action to update formula on release
   - Or use `brew bump-formula-pr` action

4. **Two Approaches**:
   - **Option A**: Host formula in this repo (tap)
   - **Option B**: Submit to homebrew-core (official)

### File Structure
```
packaging/homebrew/
  ├── Formula/
  │   └── unifictl.rb
  ├── update-formula.sh
  └── README.md
```

### Implementation Details

#### Create formula file:
```ruby
# packaging/homebrew/Formula/unifictl.rb
class Unifictl < Formula
  desc "CLI for UniFi Site Manager (API v1/EA)"
  homepage "https://github.com/nachtschatt3n/unifictl"
  url "https://github.com/nachtschatt3n/unifictl/releases/download/v#{version}/unifictl-x86_64-apple-darwin.tar.gz"
  version "0.4.4"
  sha256 "..." # Will be calculated
  
  on_arm do
    url "https://github.com/nachtschatt3n/unifictl/releases/download/v#{version}/unifictl-aarch64-apple-darwin.tar.gz"
    sha256 "..." # Will be calculated
  end
  
  license "GPL-3.0"
  
  def install
    bin.install "unifictl"
  end
  
  test do
    system "#{bin}/unifictl", "--version"
  end
end
```

#### Add to release.yml workflow:
```yaml
update-homebrew-formula:
  name: Update Homebrew Formula
  runs-on: ubuntu-latest
  needs: [build-release]
  if: startsWith(github.ref, 'refs/tags/')
  
  steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Download macOS binaries
      uses: actions/download-artifact@v4
      with:
        name: unifictl-macos-x86_64
        path: artifacts/x86_64
    
    - name: Download macOS ARM binaries
      uses: actions/download-artifact@v4
      with:
        name: unifictl-macos-aarch64
        path: artifacts/aarch64
    
    - name: Calculate checksums
      run: |
        X86_64_SHA=$(sha256sum artifacts/x86_64/unifictl-*.tar.gz | cut -d' ' -f1)
        ARM64_SHA=$(sha256sum artifacts/aarch64/unifictl-*.tar.gz | cut -d' ' -f1)
        echo "X86_64_SHA=$X86_64_SHA" >> $GITHUB_ENV
        echo "ARM64_SHA=$ARM64_SHA" >> $GITHUB_ENV
    
    - name: Update formula
      run: |
        VERSION=${GITHUB_REF#refs/tags/v}
        # Update formula with new version and checksums
        # Use sed or a script to update packaging/homebrew/Formula/unifictl.rb
    
    - name: Create PR or commit
      # Either create PR to homebrew-core or commit to tap repo
```

### Implementation Priority
- **Priority**: Medium
- **Estimated Time**: 3-4 hours
- **Files to Create**:
  - `packaging/homebrew/Formula/unifictl.rb`
  - `packaging/homebrew/update-formula.sh`
  - `.github/workflows/homebrew.yml` (optional, for tap)

---

## 4. Build winget Package for Windows

### Current State
- No winget manifest exists
- Windows binaries are not built in release workflow

### Solution Steps

1. **Add Windows build to release workflow**
   - Add Windows runner to build matrix
   - Build for `x86_64-pc-windows-msvc`

2. **Create winget manifest**
   - Create manifest YAML file
   - Follow winget schema v1.4+
   - Include installer information

3. **Manifest Structure**
   ```yaml
   # packaging/winget/unifictl.yaml
   PackageIdentifier: nachtschatt3n.unifictl
   PackageVersion: 0.4.4
   MinimumOSVersion: 10.0.17763.0
   InstallerType: zip
   Installers:
     - Architecture: x64
       InstallerUrl: https://github.com/nachtschatt3n/unifictl/releases/download/v0.4.4/unifictl-x86_64-pc-windows-msvc.zip
       InstallerSha256: ...
       InstallModes:
         - perMachine
         - perUser
   ManifestType: version
   ManifestVersion: 1.4.0
   ```

4. **Automated Updates**
   - Create script to update manifest version/checksums
   - Add GitHub Action to update manifest on release
   - Submit PR to winget-pkgs repository

### File Structure
```
packaging/winget/
  ├── unifictl.yaml (version manifest)
  ├── unifictl.locale.en-US.yaml (locale manifest)
  ├── update-manifest.sh
  └── README.md
```

### Implementation Details

#### Add Windows build to release.yml:
```yaml
build-release:
  matrix:
    include:
      # ... existing entries ...
      - os: windows-latest
        target: x86_64-pc-windows-msvc
        artifact_name: unifictl-windows-x86_64
        asset_name: unifictl-x86_64-pc-windows-msvc.zip
```

#### Create manifest file:
```yaml
# packaging/winget/unifictl.yaml
PackageIdentifier: nachtschatt3n.unifictl
PackageVersion: 0.4.4
MinimumOSVersion: 10.0.17763.0
InstallerType: zip
Installers:
  - Architecture: x64
    InstallerUrl: https://github.com/nachtschatt3n/unifictl/releases/download/v0.4.4/unifictl-x86_64-pc-windows-msvc.zip
    InstallerSha256: "..." # Calculated
    InstallModes:
      - perMachine
      - perUser
ManifestType: version
ManifestVersion: 1.4.0
```

#### Add to release.yml workflow:
```yaml
update-winget-manifest:
  name: Update winget Manifest
  runs-on: ubuntu-latest
  needs: [build-release]
  if: startsWith(github.ref, 'refs/tags/')
  
  steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Download Windows binary
      uses: actions/download-artifact@v4
      with:
        name: unifictl-windows-x86_64
    
    - name: Calculate checksum
      run: |
        SHA=$(sha256sum artifacts/unifictl-*.zip | cut -d' ' -f1)
        echo "SHA=$SHA" >> $GITHUB_ENV
    
    - name: Update manifest
      run: |
        VERSION=${GITHUB_REF#refs/tags/v}
        # Update packaging/winget/unifictl.yaml with version and checksum
    
    - name: Create PR to winget-pkgs
      # Use winget-pkgs-publisher or manual PR creation
```

### Implementation Priority
- **Priority**: Medium
- **Estimated Time**: 3-4 hours
- **Files to Create**:
  - `packaging/winget/unifictl.yaml`
  - `packaging/winget/unifictl.locale.en-US.yaml`
  - `.github/workflows/winget.yml` (optional)

---

## Implementation Order

1. **Phase 1: Fix Windows CI** (Critical)
   - Resolve stack overflow
   - Ensure all tests pass
   - **Time**: 1-2 hours

2. **Phase 2: DEB Packages** (High Value)
   - Add DEB build to release workflow
   - Test package creation
   - **Time**: 2-3 hours

3. **Phase 3: Windows Build + winget** (Medium Value)
   - Add Windows build to release
   - Create winget manifest
   - **Time**: 3-4 hours

4. **Phase 4: Homebrew** (Medium Value)
   - Create formula
   - Set up automated updates
   - **Time**: 3-4 hours

## Total Estimated Time
- **Total**: 9-13 hours
- **With testing and iteration**: 12-16 hours

## Notes

- All package builds should be triggered on version tags
- Checksums should be automatically calculated
- Version numbers should be extracted from git tags
- All packages should be uploaded as release assets
- Documentation should be updated for each package format

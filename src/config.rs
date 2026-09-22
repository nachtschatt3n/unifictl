// unifictl - CLI for UniFi Site Manager API
// Copyright (C) 2024 Mathias Uhl <mathiasuhl@gmx.de>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use anyhow::{Context, Result};
use dirs::config_dir;
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    path::{Path, PathBuf},
};
use thiserror::Error;

pub const DEFAULT_BASE_URL: &str = "https://api.ui.com";

#[derive(Debug, Serialize, Deserialize, Default, Clone, PartialEq, Eq)]
pub struct Config {
    pub api_key: Option<String>,
    pub base_url: Option<String>,
    pub local: Option<LocalConfig>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, PartialEq, Eq)]
pub struct LocalConfig {
    pub url: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub site: Option<String>,
    #[serde(default)]
    pub verify_tls: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Local,
    User,
}

#[derive(Debug, Error)]
#[allow(clippy::enum_variant_names)]
pub enum ConfigError {
    #[error("could not locate a writable config directory for the current user")]
    MissingConfigDir,
    #[error("API key is required; set it with `unifictl login --api-key <key>`")]
    MissingApiKey,
    #[error(
        "Local controller url/username/password/site are required; set them with `unifictl login --controller-url <url> --username <user> --password <pass>`"
    )]
    MissingLocalFields,
}

#[derive(Debug)]
pub struct EffectiveConfig {
    pub api_key: String,
    pub base_url: String,
}

#[derive(Debug)]
pub struct LocalEffectiveConfig {
    pub url: String,
    pub username: String,
    pub password: String,
    pub site: String,
    pub verify_tls: bool,
}

pub fn config_path(scope: Scope, cwd: &Path) -> Result<PathBuf> {
    match scope {
        Scope::Local => Ok(cwd.join(".unifictl.yaml")),
        Scope::User => {
            if let Ok(custom) = env::var("UNIFICTL_CONFIG_DIR") {
                return Ok(PathBuf::from(custom).join("config.yaml"));
            }
            let base = config_dir().ok_or(ConfigError::MissingConfigDir)?;
            Ok(base.join("unifictl").join("config.yaml"))
        }
    }
}

pub fn load(cwd: &Path) -> Result<Config> {
    let user = read_if_exists(&config_path(Scope::User, cwd)?)?.unwrap_or_default();
    let local = read_if_exists(&config_path(Scope::Local, cwd)?)?.unwrap_or_default();
    Ok(merge(user, local))
}

pub fn load_scope(scope: Scope, cwd: &Path) -> Result<Config> {
    Ok(read_if_exists(&config_path(scope, cwd)?)?.unwrap_or_default())
}

pub fn save(scope: Scope, config: &Config, cwd: &Path) -> Result<PathBuf> {
    let path = config_path(scope, cwd)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {:?}", parent))?;
        // The user config dir is ours alone, so keep it owner-only exactly as
        // the session cache does. The local scope's parent is the caller's
        // working directory, which is not ours to chmod.
        if scope == Scope::User {
            tighten_dir(parent);
        }
    }
    let serialized = serde_yaml::to_string(config).context("serializing config")?;
    // The file holds the controller password and API key: it is created 0600
    // on a fresh inode, never through the process umask (see `write_private`).
    write_private(&path, serialized.as_bytes())?;
    Ok(path)
}

pub fn resolve(
    cwd: &Path,
    api_key_override: Option<String>,
    base_url_override: Option<String>,
) -> Result<EffectiveConfig> {
    let mut merged = load(cwd)?;

    if let Some(key) = api_key_override {
        merged.api_key = Some(key);
    }
    if let Some(url) = base_url_override {
        merged.base_url = Some(url);
    }

    let api_key = merged
        .api_key
        .ok_or(ConfigError::MissingApiKey)
        .map(|k| k.trim().to_string())?;

    let base_url = merged
        .base_url
        .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());

    Ok(EffectiveConfig { api_key, base_url })
}

pub fn resolve_local(cwd: &Path, overrides: Option<LocalConfig>) -> Result<LocalEffectiveConfig> {
    let mut merged = load(cwd)?;
    if let Some(ovr) = overrides {
        merged.local = Some(merge_local(merged.local.unwrap_or_default(), ovr));
    }
    let local = merged.local.ok_or(ConfigError::MissingLocalFields)?;
    let url = local.url.ok_or(ConfigError::MissingLocalFields)?;
    let username = local.username.ok_or(ConfigError::MissingLocalFields)?;
    let password = local.password.ok_or(ConfigError::MissingLocalFields)?;
    let site = local.site.ok_or(ConfigError::MissingLocalFields)?;

    Ok(LocalEffectiveConfig {
        url,
        username,
        password,
        site,
        verify_tls: local.verify_tls,
    })
}

fn read_if_exists(path: &Path) -> Result<Option<Config>> {
    if !path.exists() {
        return Ok(None);
    }

    // Releases before 5.7 created this file through the process umask
    // (typically 0644) although it holds credentials. Repair that once, before
    // the first read; later reads find 0600 and stay silent.
    tighten_if_exposed(path);

    let contents = fs::read_to_string(path).with_context(|| format!("reading {:?}", path))?;
    let config = serde_yaml::from_str(&contents).with_context(|| format!("parsing {:?}", path))?;
    Ok(Some(config))
}

fn merge(user: Config, local: Config) -> Config {
    Config {
        api_key: local.api_key.or(user.api_key),
        base_url: local.base_url.or(user.base_url),
        local: match (user.local, local.local) {
            (Some(u), Some(l)) => Some(merge_local(u, l)),
            (Some(u), None) => Some(u),
            (None, Some(l)) => Some(l),
            (None, None) => None,
        },
    }
}

fn merge_local(user: LocalConfig, local: LocalConfig) -> LocalConfig {
    LocalConfig {
        url: local.url.or(user.url),
        username: local.username.or(user.username),
        password: local.password.or(user.password),
        site: local.site.or(user.site),
        verify_tls: local.verify_tls || user.verify_tls,
    }
}

// ---- Owner-only files -------------------------------------------------------
//
// `config.yaml` (controller password + API key) and `session.json` (session
// token) must never be readable by other users. Both files go through these
// helpers so the two can never drift apart in how they are protected.

/// Write `bytes` to `path` so the file always ends up mode 0600, with no
/// window in which the contents are group/world-readable.
///
/// On Unix the bytes go to a fresh sibling temp file created with
/// `create_new` + mode 0600 (so it never follows a pre-planted symlink and is
/// never briefly readable by others), then atomically `rename`d over the
/// target. The mode comes from the new inode, so rewriting an existing
/// world-readable file also ends at 0600. This closes the overwrite-TOCTOU and
/// symlink-follow windows and makes the write crash-atomic.
///
/// On non-Unix platforms this is a plain `fs::write`.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let tmp = path.with_file_name(format!(".{name}.{}.{nonce}.tmp", std::process::id()));
        // Refuse to follow an existing file/symlink at the temp path.
        let _ = fs::remove_file(&tmp);
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true).mode(0o600);
        let write_res = (|| -> Result<()> {
            let mut f = opts
                .open(&tmp)
                .with_context(|| format!("creating {:?}", tmp))?;
            f.write_all(bytes)
                .with_context(|| format!("writing {:?}", tmp))?;
            f.flush().ok();
            fs::rename(&tmp, path).with_context(|| format!("renaming {:?} -> {:?}", tmp, path))?;
            Ok(())
        })();
        if write_res.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        write_res?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, bytes).with_context(|| format!("writing {:?}", path))?;
    }
    Ok(())
}

/// Best-effort: make `dir` owner-only (0700). A no-op off Unix and on any
/// error (for example when we are not the owner).
pub(crate) fn tighten_dir(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(dir) {
            let mut perms = meta.permissions();
            perms.set_mode(0o700);
            let _ = fs::set_permissions(dir, perms);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

/// If `path` is a regular file readable by group or others, tighten it to
/// 0600 and say so in one line on stderr. Returns whether the mode changed.
/// Best-effort: a file we cannot stat or chmod is left alone, and an
/// already-tight file produces no output.
pub(crate) fn tighten_if_exposed(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let Ok(meta) = fs::metadata(path) else {
            return false;
        };
        if !meta.is_file() {
            return false;
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 == 0 {
            return false;
        }
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        if fs::set_permissions(path, perms).is_err() {
            return false;
        }
        eprintln!(
            "unifictl: tightened {} from {mode:04o} to 0600 (it holds credentials)",
            path.display()
        );
        true
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;
    use std::{env, fs};
    use tempfile::tempdir;

    static ENV_LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();

    #[test]
    fn merges_user_and_local_and_overrides() {
        let _guard = ENV_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap();
        let cwd = tempdir().unwrap();
        unsafe {
            env::set_var("UNIFICTL_CONFIG_DIR", cwd.path().join("config"));
            env::set_var("XDG_CONFIG_HOME", cwd.path().join("xdg"));
        }
        fs::create_dir_all(cwd.path().join("config")).unwrap();
        fs::create_dir_all(cwd.path().join("xdg")).unwrap();

        let user_cfg = Config {
            api_key: Some("user-key".into()),
            base_url: Some("https://example.test".into()),
            local: Some(LocalConfig {
                url: Some("https://controller.local".into()),
                username: Some("user".into()),
                password: Some("pass-user".into()),
                site: Some("site1".into()),
                verify_tls: false,
            }),
        };
        save(Scope::User, &user_cfg, cwd.path()).unwrap();

        let local_cfg = Config {
            api_key: Some("local-key".into()),
            base_url: Some("https://example.test".into()),
            local: Some(LocalConfig {
                url: Some("https://override.local".into()),
                username: Some("localuser".into()),
                password: Some("localpass".into()),
                site: Some("localsite".into()),
                verify_tls: true,
            }),
        };
        save(Scope::Local, &local_cfg, cwd.path()).unwrap();

        let effective = resolve(cwd.path(), None, None).unwrap();
        assert_eq!(effective.api_key, "local-key");
        assert_eq!(effective.base_url, "https://example.test");

        let local_effective = resolve_local(cwd.path(), None).unwrap();
        assert_eq!(local_effective.url, "https://override.local");
        assert_eq!(local_effective.username, "localuser");
        assert_eq!(local_effective.password, "localpass");
        assert_eq!(local_effective.site, "localsite");
        assert!(local_effective.verify_tls);

        let override_base = resolve(
            cwd.path(),
            Some("override".into()),
            Some("https://override.test".into()),
        )
        .unwrap();
        assert_eq!(override_base.api_key, "override");
        assert_eq!(override_base.base_url, "https://override.test");
    }

    #[test]
    fn errors_when_missing_key() {
        let _guard = ENV_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap();
        let cwd = tempdir().unwrap();
        unsafe {
            env::set_var("UNIFICTL_CONFIG_DIR", cwd.path().join("config"));
            env::set_var("XDG_CONFIG_HOME", cwd.path().join("xdg"));
        }
        fs::create_dir_all(cwd.path().join("config")).unwrap();
        fs::create_dir_all(cwd.path().join("xdg")).unwrap();
        let err = resolve(cwd.path(), None, None).unwrap_err();
        assert!(err.to_string().contains("API key is required"));
    }

    // ---- config.yaml holds the controller password and API key and must be
    // owner-only (0600), exactly like session.json ----

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    fn chmod(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn secret_config() -> Config {
        Config {
            api_key: Some("cloud-api-key".into()),
            base_url: None,
            local: Some(LocalConfig {
                url: Some("https://controller.local:8443".into()),
                username: Some("cli-adm".into()),
                password: Some("hunter2".into()),
                site: Some("default".into()),
                verify_tls: false,
            }),
        }
    }

    #[cfg(unix)]
    #[test]
    fn save_creates_config_0600_and_rewrites_a_0644_file_to_0600() {
        let cwd = tempdir().unwrap();
        // Local scope keeps this test off the env vars and the user config dir.
        let path = save(Scope::Local, &secret_config(), cwd.path()).unwrap();
        assert_eq!(path, cwd.path().join(".unifictl.yaml"));
        assert_eq!(mode_of(&path), 0o600, "fresh config must be owner-only");

        // A config written by a pre-fix release sits at 0644. Rewriting it
        // (e.g. running `unifictl login` again) must not inherit that mode.
        chmod(&path, 0o644);
        let mut updated = secret_config();
        updated.local.as_mut().unwrap().password = Some("rotated".into());
        save(Scope::Local, &updated, cwd.path()).unwrap();
        assert_eq!(mode_of(&path), 0o600, "rewrite must end at 0600");
        let reloaded = load_scope(Scope::Local, cwd.path()).unwrap();
        assert_eq!(reloaded, updated);

        // The atomic-rename write must leave no temp file next to the config.
        let leftovers: Vec<_> = fs::read_dir(cwd.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .filter(|n| n.to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn first_read_tightens_a_world_readable_config_once() {
        let cwd = tempdir().unwrap();
        let path = cwd.path().join(".unifictl.yaml");
        // Simulate the pre-fix writer: plain fs::write, then force 0644 so the
        // test does not depend on this host's umask.
        fs::write(&path, serde_yaml::to_string(&secret_config()).unwrap()).unwrap();
        chmod(&path, 0o644);

        let cfg = load_scope(Scope::Local, cwd.path()).unwrap();
        assert_eq!(
            cfg,
            secret_config(),
            "tightening must not alter the contents"
        );
        assert_eq!(mode_of(&path), 0o600, "first read must repair the mode");

        // An already-tight file is left alone (and produces no notice).
        assert!(!tighten_if_exposed(&path));
        assert_eq!(mode_of(&path), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn user_scope_save_keeps_file_0600_and_dir_0700() {
        let _guard = ENV_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap();
        let cwd = tempdir().unwrap();
        let dir = cwd.path().join("config");
        unsafe {
            env::set_var("UNIFICTL_CONFIG_DIR", &dir);
            env::set_var("XDG_CONFIG_HOME", cwd.path().join("xdg"));
        }

        let path = save(Scope::User, &secret_config(), cwd.path()).unwrap();
        assert_eq!(path, dir.join("config.yaml"));
        assert_eq!(mode_of(&path), 0o600, "user config must be owner-only");
        assert_eq!(mode_of(&dir), 0o700, "user config dir must be owner-only");
    }

    /// Straw: the pre-fix writer (`fs::write`) is what this change replaces.
    /// It leaves an existing 0644 file at 0644 (truncating keeps the inode's
    /// mode) and creates new files through the umask, so an assertion of 0600
    /// is a discriminating check rather than one any writer would pass.
    #[cfg(unix)]
    #[test]
    fn straw_pre_fix_writer_leaves_config_world_readable() {
        let cwd = tempdir().unwrap();
        let yaml = serde_yaml::to_string(&secret_config()).unwrap();

        // Rewrite path: deterministic regardless of umask.
        let path = cwd.path().join(".unifictl.yaml");
        fs::write(&path, &yaml).unwrap();
        chmod(&path, 0o644);
        fs::write(&path, &yaml).unwrap();
        assert_eq!(
            mode_of(&path),
            0o644,
            "fs::write keeps the old mode; that is the bug being fixed"
        );

        // Create path: depends on the umask, so only assert where it can
        // discriminate (the usual 022; a 077 umask already yields 0600).
        let fresh = cwd.path().join("fresh.yaml");
        fs::write(&fresh, &yaml).unwrap();
        let fresh_mode = mode_of(&fresh);
        if fresh_mode & 0o077 == 0 {
            eprintln!(
                "umask on this host already yields {fresh_mode:04o}; create-path straw is not discriminating here"
            );
        } else {
            assert_ne!(
                fresh_mode, 0o600,
                "fs::write must not be owner-only under umask 022"
            );
        }
    }
}

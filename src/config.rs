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

use anyhow::{Context, Result, bail};
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
    pub verify_tls: Option<bool>,
    pub ca_file: Option<PathBuf>,
    /// Opt in to retrying login on `:443` when a `:8443` controller is unreachable.
    #[serde(default)]
    pub port_fallback: Option<bool>,
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
    pub ca_file: Option<PathBuf>,
    pub port_fallback: bool,
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

static NO_PROJECT_CONFIG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

pub fn set_no_project_config(disabled: bool) {
    let _ = NO_PROJECT_CONFIG.set(disabled);
}

pub fn load(cwd: &Path) -> Result<Config> {
    let user = load_scope(Scope::User, cwd)?;
    let local = if NO_PROJECT_CONFIG.get().copied().unwrap_or(false) {
        Config::default()
    } else {
        load_scope(Scope::Local, cwd)?
    };
    Ok(merge(user, local))
}

pub fn load_scope(scope: Scope, cwd: &Path) -> Result<Config> {
    let path = scope_target(scope, &config_path(scope, cwd)?)?;
    Ok(read_if_exists(&path, scope == Scope::User)?.unwrap_or_default())
}

/// Only an explicit repair request may discard a malformed configuration.
pub fn load_scope_for_update(scope: Scope, cwd: &Path, repair: bool) -> Result<Config> {
    match load_scope(scope, cwd) {
        Err(error) if repair && error.downcast_ref::<ConfigSyntaxError>().is_some() => {
            Ok(Config::default())
        }
        result => result,
    }
}

/// User-managed symlinks are intentional; resolve once, then use a no-follow
/// handle and an atomic sibling replacement on the owned regular target.
/// Project and cache paths never opt into this behavior.
fn scope_target(scope: Scope, path: &Path) -> Result<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() && scope == Scope::User => {
            fs::canonicalize(path).context("resolving user configuration symlink")
        }
        Ok(meta) if meta.file_type().is_symlink() => {
            bail!("project configuration must not be a symlink")
        }
        Ok(_) => Ok(path.to_path_buf()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(path.to_path_buf()),
        Err(_) => bail!("cannot inspect configuration path safely"),
    }
}

pub fn save(scope: Scope, config: &Config, cwd: &Path) -> Result<PathBuf> {
    let path = config_path(scope, cwd)?;
    let target = scope_target(scope, &path)?;
    let previous = match read_if_exists(&target, scope == Scope::User) {
        Ok(previous) => previous,
        Err(error) if error.downcast_ref::<ConfigSyntaxError>().is_some() => None,
        Err(error) => return Err(error),
    };
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
    write_private(&target, serialized.as_bytes())?;
    if previous.as_ref().and_then(|c| c.local.as_ref()) != config.local.as_ref() {
        for local in [
            previous.as_ref().and_then(|c| c.local.as_ref()),
            config.local.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if let (Some(url), Some(username)) = (&local.url, &local.username) {
                crate::session::clear_principal(url, username);
            }
        }
    }
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
        verify_tls: local.verify_tls.unwrap_or(true),
        ca_file: local.ca_file,
        port_fallback: local.port_fallback.unwrap_or(false),
    })
}

#[derive(Debug, Error)]
#[error(
    "invalid configuration YAML at line {line}, column {column}; repair the file or use login --repair-config to replace it"
)]
struct ConfigSyntaxError {
    line: String,
    column: String,
}

fn read_if_exists(path: &Path, repair_permissions: bool) -> Result<Option<Config>> {
    let Some(contents) = read_private(path, repair_permissions)? else {
        return Ok(None);
    };
    // Avoid echoing malformed YAML: it can contain passwords or terminal controls.
    let mut config: Config = serde_yaml::from_str(&contents).map_err(|error| {
        let (line, column) = error
            .location()
            .map(|location| (location.line(), location.column()))
            .unwrap_or((1, 1));
        ConfigSyntaxError {
            line: line.to_string(),
            column: column.to_string(),
        }
    })?;
    if let Some(local) = config.local.as_mut()
        && let Some(ca) = local.ca_file.as_mut()
        && ca.is_relative()
    {
        *ca = path.parent().unwrap_or(Path::new(".")).join(&*ca);
    }
    Ok(Some(config))
}

/// Credentials are sent only to an explicit HTTP(S) authority, without URL
/// userinfo or query/fragment data. HTTP requires a deliberate insecure mode.
pub(crate) fn validate_controller_url(value: &str, allow_http: bool) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value).context("parsing controller URL")?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("controller URL must contain a host and no credentials, query or fragment");
    }
    if url.scheme() != "https" && !(allow_http && url.scheme() == "http") {
        bail!(
            "HTTPS is required; configure a trusted CA, or explicitly select --insecure for a local controller"
        );
    }
    Ok(url)
}

fn same_destination(left: &str, right: &str) -> bool {
    match (reqwest::Url::parse(left), reqwest::Url::parse(right)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn merge(user: Config, local: Config) -> Config {
    let changed_target = local.base_url.as_deref().is_some_and(|url| {
        !same_destination(url, user.base_url.as_deref().unwrap_or(DEFAULT_BASE_URL))
    });
    Config {
        // A project may select another target, but cannot take the user's key
        // along to it. Explicit CLI overrides are handled after this boundary.
        api_key: local
            .api_key
            .or(if changed_target { None } else { user.api_key }),
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
    let changed_target = local.url.as_deref().is_some_and(|url| {
        !user
            .url
            .as_deref()
            .is_some_and(|u| same_destination(u, url))
    });
    let changed_user = local
        .username
        .as_ref()
        .is_some_and(|u| Some(u) != user.username.as_ref());
    let inherit_password = !changed_target && !changed_user && local.password.is_none();
    LocalConfig {
        url: local.url.or(user.url),
        username: local
            .username
            .or(if changed_target { None } else { user.username }),
        password: local.password.or(if changed_target || changed_user {
            None
        } else {
            user.password
        }),
        site: local.site.or(user.site),
        // Trust settings belong to the origin of the inherited secret. A
        // checkout cannot turn verification off or install another root CA.
        verify_tls: if inherit_password {
            user.verify_tls
        } else {
            local.verify_tls.or(user.verify_tls)
        },
        ca_file: if inherit_password {
            user.ca_file
        } else {
            local.ca_file.or(user.ca_file)
        },
        // Fallback re-sends the secret to another authority: same trust rule.
        port_fallback: if inherit_password {
            user.port_fallback
        } else {
            local.port_fallback.or(user.port_fallback)
        },
    }
}

/// Read one regular, owned file through a stable handle. Never follow a symlink
/// or chmod a project file merely because the current directory contains it.
pub(crate) fn read_private(path: &Path, repair_permissions: bool) -> Result<Option<String>> {
    use std::io::Read;
    #[cfg(not(unix))]
    if fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink()) {
        bail!("configuration/cache file must not be a symlink");
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => bail!("cannot open configuration/cache file safely"),
    };
    let meta = file
        .metadata()
        .context("checking configuration/cache file")?;
    if !meta.is_file() {
        bail!("configuration/cache must be a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.uid() != unsafe { libc::geteuid() } {
            bail!("configuration/cache must be owned by the current user");
        }
        if repair_permissions && meta.permissions().mode() & 0o077 != 0 {
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .context("securing configuration/cache permissions")?;
        }
    }
    #[cfg(not(unix))]
    let _ = repair_permissions;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .context("reading configuration/cache file")?;
    Ok(Some(contents))
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
/// Off Unix, files inherit the containing directory's ACL; the atomic replacement
/// still avoids opening a planted destination symlink for writing.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = path.with_file_name(format!(".{name}.{}.{nonce}.tmp", std::process::id()));
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&tmp).context("creating private temporary file")?;
    let result = (|| -> Result<()> {
        file.write_all(bytes).context("writing private file")?;
        file.flush().context("flushing private file")?;
        file.sync_all().context("syncing private file")?;
        drop(file);
        fs::rename(&tmp, path).context("replacing private file")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Best-effort: make `dir` owner-only (0700). A no-op off Unix and on any
/// error (for example when we are not the owner).
pub(crate) fn tighten_dir(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        if let Ok(file) = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(dir)
            && let Ok(meta) = file.metadata()
            && meta.is_dir()
            && meta.uid() == unsafe { libc::geteuid() }
        {
            let _ = file.set_permissions(fs::Permissions::from_mode(0o700));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
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
                verify_tls: Some(false),
                ca_file: None,
                port_fallback: None,
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
                verify_tls: Some(true),
                ca_file: None,
                port_fallback: None,
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
                verify_tls: Some(false),
                ca_file: None,
                port_fallback: None,
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
    fn reading_project_config_does_not_change_permissions() {
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
        assert_eq!(
            mode_of(&path),
            0o644,
            "reading a project file must not chmod it"
        );

        read_private(&path, true).unwrap();
        assert_eq!(
            mode_of(&path),
            0o600,
            "trusted user cache repair uses the open handle"
        );
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

    #[test]
    fn project_destination_cannot_inherit_user_credentials() {
        let user = secret_config();
        let changed = Config {
            base_url: Some("https://other.test".into()),
            local: Some(LocalConfig {
                url: Some("https://other.test".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let merged = merge(user.clone(), changed);
        assert!(merged.api_key.is_none());
        let local = merged.local.unwrap();
        assert!(local.username.is_none());
        assert!(local.password.is_none());
        let username_change = Config {
            local: Some(LocalConfig {
                username: Some("other".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(
            merge(user, username_change)
                .local
                .unwrap()
                .password
                .is_none()
        );
    }

    #[test]
    fn inherited_secret_preserves_trust_but_allows_nonsecret_site_precedence() {
        let mut user = secret_config();
        let local = user.local.as_mut().unwrap();
        local.verify_tls = Some(true);
        local.ca_file = Some("trusted.pem".into());
        let project = Config {
            local: Some(LocalConfig {
                site: Some("branch".into()),
                verify_tls: Some(false),
                ca_file: Some("untrusted.pem".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let result = merge(user, project).local.unwrap();
        assert_eq!(result.site.as_deref(), Some("branch"));
        assert_eq!(result.verify_tls, Some(true));
        assert_eq!(result.ca_file.as_deref(), Some(Path::new("trusted.pem")));
        assert!(LocalConfig::default().verify_tls.unwrap_or(true));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_config_is_rejected_without_chmod() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, "api_key: synthetic").unwrap();
        chmod(&target, 0o644);
        symlink(&target, dir.path().join(".unifictl.yaml")).unwrap();
        assert!(load_scope(Scope::Local, dir.path()).is_err());
        assert_eq!(mode_of(&target), 0o644);
    }

    #[test]
    fn malformed_yaml_error_does_not_echo_secret() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join(".unifictl.yaml"),
            "password: [synthetic-secret",
        )
        .unwrap();
        let error = format!("{:?}", load_scope(Scope::Local, dir.path()).unwrap_err());
        assert!(!error.contains("synthetic-secret"));
    }
    #[cfg(unix)]
    #[test]
    fn user_symlink_reads_and_writes_owned_target_preserving_link() {
        use std::os::unix::fs::symlink;
        let _guard = ENV_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap();
        let dir = tempdir().unwrap();
        let config_dir = dir.path().join("config");
        fs::create_dir(&config_dir).unwrap();
        unsafe {
            env::set_var("UNIFICTL_CONFIG_DIR", &config_dir);
        }
        let target = dir.path().join("managed.yaml");
        fs::write(&target, "api_key: old-synthetic").unwrap();
        chmod(&target, 0o644);
        let link = config_dir.join("config.yaml");
        symlink(&target, &link).unwrap();
        assert_eq!(
            load_scope(Scope::User, dir.path())
                .unwrap()
                .api_key
                .as_deref(),
            Some("old-synthetic")
        );
        assert_eq!(mode_of(&target), 0o600);
        save(Scope::User, &secret_config(), dir.path()).unwrap();
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            read_if_exists(&target, true).unwrap().unwrap(),
            secret_config()
        );
        assert_eq!(mode_of(&target), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn invalid_symlink_targets_and_project_write_are_rejected() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let link = dir.path().join(".unifictl.yaml");
        let target = dir.path().join("unrelated");
        fs::write(&target, "keep").unwrap();
        symlink(&target, &link).unwrap();
        assert!(save(Scope::Local, &secret_config(), dir.path()).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep");
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let broken = dir.path().join("broken");
        symlink(dir.path().join("absent"), &broken).unwrap();
        assert!(scope_target(Scope::User, &broken).is_err());
        let directory = scope_target(Scope::User, dir.path()).unwrap();
        assert!(read_private(&directory, true).is_err());
    }

    #[test]
    fn malformed_prior_yaml_can_be_repaired_without_echoing_values() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".unifictl.yaml");
        fs::write(&path, "local:\n  password: [synthetic-secret\n").unwrap();
        let error = load_scope_for_update(Scope::Local, dir.path(), false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("line 2, column 13"), "{error}");
        assert!(!error.contains("synthetic-secret"));
        assert_eq!(
            load_scope_for_update(Scope::Local, dir.path(), true).unwrap(),
            Config::default()
        );
        save(Scope::Local, &secret_config(), dir.path()).unwrap();
        assert_eq!(
            load_scope(Scope::Local, dir.path()).unwrap(),
            secret_config()
        );
    }

    #[test]
    fn project_cannot_enable_port_fallback_for_inherited_password() {
        let mut user = secret_config();
        user.local.as_mut().unwrap().port_fallback = Some(false);
        let project = Config {
            local: Some(LocalConfig {
                port_fallback: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            merge(user, project).local.unwrap().port_fallback,
            Some(false)
        );
    }
}

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

//! Persistent local-controller session cache.
//!
//! UniFi OS gateways (UDM/UDM-Pro) rate-limit *successful* logins per source
//! IP. Because every `unifictl local <cmd>` invocation is a fresh process, a
//! naive client logs in on every command and a burst of commands (e.g. a
//! monitoring sweep) trips the per-IP login limiter, producing spurious
//! 429/"login limit reached" errors.
//!
//! This module caches the authenticated session (CSRF token + session cookie)
//! on disk so subsequent invocations reuse it instead of re-authenticating.
//! The cached session's validity is confirmed lazily: the first request that
//! receives a genuine 401/403 triggers exactly one re-login. A 429 never
//! triggers a re-login (that would extend the lockout).
//!
//! Security posture:
//! - The cache file is created with mode 0600 (owner read/write only).
//! - Token values are never logged or printed; `Debug` is redacted.
//! - Opt out with `--no-session-cache` or `UNIFICTL_NO_SESSION_CACHE=1`.

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// Process-global opt-out, set once from the CLI flag in `main()`.
static DISABLED: OnceLock<bool> = OnceLock::new();

// Per-thread test redirect for the session file. When `Some`, unit tests have
// opted into caching against an isolated temp path; when `None` under
// `cfg(test)`, caching is inert so tests never read or write the real user
// config. Has no effect in release builds.
#[cfg(test)]
thread_local! {
    static TEST_OVERRIDE: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// Record the CLI `--no-session-cache` decision. Idempotent; first write wins.
pub fn set_disabled(disabled: bool) {
    let _ = DISABLED.set(disabled);
}

/// Pure predicate for the `UNIFICTL_NO_SESSION_CACHE` env value (any non-empty,
/// non-"0" string disables caching). Kept side-effect-free so it is testable
/// without mutating process environment.
fn env_disabled(val: Option<&str>) -> bool {
    matches!(val, Some(v) if !v.is_empty() && v != "0")
}

/// True when session caching is turned off, via either the CLI flag or the
/// `UNIFICTL_NO_SESSION_CACHE` environment variable.
pub fn is_disabled() -> bool {
    #[cfg(test)]
    {
        // In tests caching is inert unless a test explicitly opts in with a
        // temp session dir (see `test_set_dir`).
        if TEST_OVERRIDE.with(|c| c.borrow().is_none()) {
            return true;
        }
    }
    if DISABLED.get().copied().unwrap_or(false) {
        return true;
    }
    env_disabled(std::env::var("UNIFICTL_NO_SESSION_CACHE").ok().as_deref())
}

/// Test-only: route the session cache to `dir/session.json` on this thread and
/// enable caching for the current test.
#[cfg(test)]
pub fn test_set_dir(dir: &std::path::Path) {
    TEST_OVERRIDE.with(|c| *c.borrow_mut() = Some(dir.join("session.json")));
}

/// A cached, authenticated local-controller session.
///
/// `Debug` is implemented by hand to redact the CSRF token and session cookie
/// so they can never leak into logs, panics, or error chains.
#[derive(Clone, Serialize, Deserialize)]
pub struct CachedSession {
    /// The controller URL as configured by the user (the cache key).
    pub key_url: String,
    /// The base URL that actually authenticated (may differ if the client
    /// fell back from `:8443` to `:443`).
    pub resolved_url: String,
    pub username: String,
    pub site: String,
    #[serde(default)]
    pub is_legacy: bool,
    pub csrf: Option<String>,
    pub session_cookie: Option<String>,
    #[serde(default)]
    pub created_at: u64,
}

impl std::fmt::Debug for CachedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact secrets: show only presence, never the token value.
        let redact = |o: &Option<String>| if o.is_some() { "<redacted>" } else { "<none>" };
        f.debug_struct("CachedSession")
            .field("key_url", &self.key_url)
            .field("resolved_url", &self.resolved_url)
            .field("username", &self.username)
            .field("site", &self.site)
            .field("is_legacy", &self.is_legacy)
            .field("csrf", &redact(&self.csrf))
            .field("session_cookie", &redact(&self.session_cookie))
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Location of the session cache file. Honors `UNIFICTL_CONFIG_DIR` (as the
/// config module does) so it can be redirected in tests.
pub fn session_path() -> Result<PathBuf> {
    #[cfg(test)]
    {
        if let Some(p) = TEST_OVERRIDE.with(|c| c.borrow().clone()) {
            return Ok(p);
        }
    }
    if let Ok(custom) = std::env::var("UNIFICTL_CONFIG_DIR") {
        return Ok(PathBuf::from(custom).join("session.json"));
    }
    let base = dirs::config_dir().ok_or_else(|| anyhow!("could not locate a config directory"))?;
    Ok(base.join("unifictl").join("session.json"))
}

/// Load a cached session iff caching is enabled and the cached entry matches
/// the given controller URL / username / site and carries a credential.
pub fn load(key_url: &str, username: &str, site: &str) -> Option<CachedSession> {
    if is_disabled() {
        return None;
    }
    let path = session_path().ok()?;
    let data = fs::read_to_string(&path).ok()?;
    let sess: CachedSession = serde_json::from_str(&data).ok()?;
    let matches = sess.key_url == key_url
        && sess.username == username
        && sess.site == site
        && (sess.csrf.is_some() || sess.session_cookie.is_some());
    if matches { Some(sess) } else { None }
}

/// Persist a session to disk with owner-only (0600) permissions. Best-effort:
/// returns an error the caller may ignore rather than fail the command.
pub fn save(sess: &CachedSession) -> Result<()> {
    if is_disabled() {
        return Ok(());
    }
    let path = session_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {:?}", parent))?;
        // Tighten the config dir to owner-only; it also holds the plaintext
        // credentials file, so world-listability is undesirable. Best-effort.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = fs::metadata(parent) {
                let mut perms = meta.permissions();
                perms.set_mode(0o700);
                let _ = fs::set_permissions(parent, perms);
            }
        }
    }
    let data = serde_json::to_string(sess).context("serializing session")?;
    write_private(&path, data.as_bytes())?;
    Ok(())
}

/// Remove any cached session (e.g. after a genuine 401 invalidation).
pub fn clear() {
    if let Ok(path) = session_path() {
        let _ = fs::remove_file(path);
    }
}

/// Current wall-clock time in seconds since the Unix epoch.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Write `bytes` to `path` so the token file always ends up mode 0600, with no
/// window in which the secret is world-readable.
///
/// On Unix the secret is written to a fresh sibling temp file created with
/// `create_new` + mode 0600 (so it can never follow a pre-planted symlink and
/// is never briefly group/world-readable), then atomically `rename`d over the
/// target. This closes the overwrite-TOCTOU and symlink-follow windows and
/// makes the write crash-atomic.
fn write_private(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let tmp = path.with_file_name(format!(
            ".session.{}.{}.tmp",
            std::process::id(),
            now_secs()
        ));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_secrets() {
        let sess = CachedSession {
            key_url: "https://c.test:8443".into(),
            resolved_url: "https://c.test:8443".into(),
            username: "admin".into(),
            site: "default".into(),
            is_legacy: false,
            csrf: Some("supersecret-csrf".into()),
            session_cookie: Some("TOKEN=supersecret-cookie".into()),
            created_at: 123,
        };
        let rendered = format!("{sess:?}");
        assert!(!rendered.contains("supersecret-csrf"));
        assert!(!rendered.contains("supersecret-cookie"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn env_disabled_parses_opt_out_values() {
        assert!(env_disabled(Some("1")));
        assert!(env_disabled(Some("true")));
        assert!(!env_disabled(Some("0")));
        assert!(!env_disabled(Some("")));
        assert!(!env_disabled(None));
    }

    #[test]
    fn save_then_load_round_trips_and_file_is_0600() {
        let dir = tempfile::tempdir().unwrap();
        test_set_dir(dir.path());

        let sess = CachedSession {
            key_url: "https://c.test:8443".into(),
            resolved_url: "https://c.test:8443".into(),
            username: "admin".into(),
            site: "default".into(),
            is_legacy: false,
            csrf: Some("csrf-1".into()),
            session_cookie: Some("TOKEN=cookie-1".into()),
            created_at: now_secs(),
        };
        save(&sess).unwrap();

        let loaded = load("https://c.test:8443", "admin", "default").expect("cache hit");
        assert_eq!(loaded.csrf.as_deref(), Some("csrf-1"));
        assert_eq!(loaded.session_cookie.as_deref(), Some("TOKEN=cookie-1"));

        // A different controller URL must not match.
        assert!(load("https://other.test:8443", "admin", "default").is_none());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(session_path().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "session file must be owner-only 0600");
        }
    }

    #[test]
    fn clear_removes_cache() {
        let dir = tempfile::tempdir().unwrap();
        test_set_dir(dir.path());
        let sess = CachedSession {
            key_url: "https://c.test:8443".into(),
            resolved_url: "https://c.test:8443".into(),
            username: "admin".into(),
            site: "default".into(),
            is_legacy: false,
            csrf: Some("csrf-1".into()),
            session_cookie: None,
            created_at: 0,
        };
        save(&sess).unwrap();
        assert!(load("https://c.test:8443", "admin", "default").is_some());
        clear();
        assert!(load("https://c.test:8443", "admin", "default").is_none());
    }
}

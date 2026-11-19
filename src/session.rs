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
//! receives a genuine 401 during a safe read triggers at most one re-login. A 429 never
//! triggers a re-login (that would extend the lockout).
//!
//! Security posture:
//! - The cache file is created with mode 0600 (owner read/write only).
//! - Token values are never logged or printed; `Debug` is redacted.
//! - Opt out with `--no-session-cache` or `UNIFICTL_NO_SESSION_CACHE=1`.

use crate::config::{read_private, tighten_dir, write_private};
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    /// Cache reuse is bound to the verification mode and CA bundle.
    #[serde(default)]
    pub trust_profile: Option<String>,
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
        TEST_OVERRIDE
            .with(|c| c.borrow().clone())
            .ok_or_else(|| anyhow!("session cache has no isolated test directory"))
    }
    #[cfg(not(test))]
    if let Ok(custom) = std::env::var("UNIFICTL_CONFIG_DIR") {
        return Ok(PathBuf::from(custom).join("session.json"));
    }
    #[cfg(not(test))]
    {
        let base =
            dirs::config_dir().ok_or_else(|| anyhow!("could not locate a config directory"))?;
        Ok(base.join("unifictl").join("session.json"))
    }
}

/// A policy identifier, not a password digest. Changing trust cannot borrow
/// a session established under a different TLS policy.
pub fn trust_profile(verify_tls: bool, ca_pem: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update([u8::from(verify_tls)]);
    digest.update(ca_pem);
    format!("{:x}", digest.finalize())
}

const MAX_SESSIONS: usize = 64;

fn identity_path(key_url: &str, username: &str, site: &str) -> Result<PathBuf> {
    let canonical_url = crate::client::validate_base_url(key_url, true)?;
    let encoded = serde_json::to_vec(&(canonical_url.as_str(), username, site))?;
    let digest = Sha256::digest(encoded);
    let filename = format!("{digest:x}.json");
    Ok(session_path()?.with_file_name("sessions").join(filename))
}

fn matches_identity(sess: &CachedSession, url: &str, username: &str, site: &str) -> bool {
    same_controller(&sess.key_url, url) && sess.username == username && sess.site == site
}

// URL spelling (host case, implicit default port, empty root path) does not
// create another principal. Preserve distinct schemes, ports and paths.
fn same_controller(left: &str, right: &str) -> bool {
    match (
        crate::client::validate_base_url(left, true),
        crate::client::validate_base_url(right, true),
    ) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// Separate atomic files prevent alternating controllers/sites from evicting
/// each other's sessions and avoid a shared read/modify/write race.
pub fn load(key_url: &str, username: &str, site: &str) -> Option<CachedSession> {
    if is_disabled() {
        return None;
    }
    let path = identity_path(key_url, username, site).ok()?;
    let data = read_private(&path, true).ok().flatten();
    // Read the old single-entry format for migration, with the same identity
    // and ownership checks. The first successful save removes that entry.
    let data = data.or_else(|| read_private(&session_path().ok()?, true).ok().flatten())?;
    let sess: CachedSession = serde_json::from_str(&data).ok()?;
    if matches_identity(&sess, key_url, username, site)
        && (sess.csrf.is_some() || sess.session_cookie.is_some())
    {
        Some(sess)
    } else {
        None
    }
}

pub fn save(sess: &CachedSession) -> Result<()> {
    if is_disabled() {
        return Ok(());
    }
    let path = identity_path(&sess.key_url, &sess.username, &sess.site)?;
    let parent = path.parent().expect("session file has a parent");
    fs::create_dir_all(parent).context("creating session cache directory")?;
    if fs::symlink_metadata(parent)?.file_type().is_symlink() {
        return Err(anyhow!("session cache directory must not be a symlink"));
    }
    tighten_dir(parent);
    if let Some(base) = parent.parent() {
        tighten_dir(base);
    }
    write_private(&path, serde_json::to_string(sess)?.as_bytes())?;
    remove_legacy(&sess.key_url, &sess.username, &sess.site);
    // Bound disk use. Pruning can lose a cache hit but cannot mix identities.
    let mut entries: Vec<_> = fs::read_dir(parent)?
        .filter_map(Result::ok)
        .filter(|e| valid_cache_filename(&e.file_name().to_string_lossy()))
        .filter_map(|e| e.metadata().ok().map(|m| (m.modified().ok(), e.path())))
        .collect();
    entries.sort_by_key(|entry| entry.0);
    let excess = entries.len().saturating_sub(MAX_SESSIONS);
    for (_, old) in entries
        .into_iter()
        .filter(|(_, old)| old != &path)
        .take(excess)
    {
        let _ = fs::remove_file(old);
    }
    Ok(())
}

fn valid_cache_filename(name: &str) -> bool {
    name.len() == 69
        && name.ends_with(".json")
        && name.as_bytes()[..64].iter().all(|b| b.is_ascii_hexdigit())
}

fn remove_legacy(url: &str, username: &str, site: &str) {
    if let Ok(path) = session_path()
        && let Ok(Some(data)) = read_private(&path, true)
        && let Ok(sess) = serde_json::from_str::<CachedSession>(&data)
        && matches_identity(&sess, url, username, site)
    {
        let _ = fs::remove_file(path);
    }
}

/// Invalidate only the affected identity, including after a password change.
/// This deliberately works when cache use is disabled for this invocation.
pub fn clear_identity(url: &str, username: &str, site: &str) {
    if let Ok(path) = identity_path(url, username, site) {
        let _ = fs::remove_file(path);
    }
    remove_legacy(url, username, site);
}

/// Credential rotation invalidates every cached site for that principal.
pub fn clear_principal(url: &str, username: &str) {
    let Ok(base) = session_path() else { return };
    let mut paths = vec![base.clone()];
    if let Ok(entries) = fs::read_dir(base.with_file_name("sessions")) {
        paths.extend(
            entries
                .filter_map(Result::ok)
                .filter(|e| valid_cache_filename(&e.file_name().to_string_lossy()))
                .map(|e| e.path()),
        );
    }
    for path in paths {
        if let Ok(Some(data)) = read_private(&path, true)
            && let Ok(sess) = serde_json::from_str::<CachedSession>(&data)
            && same_controller(&sess.key_url, url)
            && sess.username == username
        {
            let _ = fs::remove_file(path);
        }
    }
}

/// Current wall-clock time in seconds since the Unix epoch.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
            trust_profile: None,
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
            trust_profile: None,
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
            let mode =
                fs::metadata(identity_path("https://c.test:8443", "admin", "default").unwrap())
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
            trust_profile: None,
        };
        save(&sess).unwrap();
        assert!(load("https://c.test:8443", "admin", "default").is_some());
        clear_identity("https://c.test:8443", "admin", "default");
        assert!(load("https://c.test:8443", "admin", "default").is_none());
    }

    #[test]
    fn alternating_identities_are_preserved_and_invalidation_is_targeted() {
        let dir = tempfile::tempdir().unwrap();
        test_set_dir(dir.path());
        let mut sess = CachedSession {
            key_url: "https://controller.test".into(),
            resolved_url: "https://controller.test".into(),
            username: "admin".into(),
            site: "A".into(),
            is_legacy: false,
            csrf: Some("token-a".into()),
            session_cookie: None,
            created_at: now_secs(),
            trust_profile: None,
        };
        save(&sess).unwrap();
        sess.site = "B".into();
        sess.csrf = Some("token-b".into());
        save(&sess).unwrap();
        assert_eq!(
            load(&sess.key_url, "admin", "A").unwrap().csrf.as_deref(),
            Some("token-a")
        );
        clear_identity(&sess.key_url, "admin", "A");
        assert!(load(&sess.key_url, "admin", "A").is_none());
        assert_eq!(
            load(&sess.key_url, "admin", "B").unwrap().csrf.as_deref(),
            Some("token-b")
        );
    }

    #[test]
    fn equivalent_urls_share_cache_and_rotation_invalidates_all_sites() {
        let dir = tempfile::tempdir().unwrap();
        test_set_dir(dir.path());
        let mut sess = CachedSession {
            key_url: "https://CONTROLLER.test:443".into(),
            resolved_url: "https://controller.test/".into(),
            username: "admin".into(),
            site: "A".into(),
            is_legacy: false,
            csrf: Some("synthetic-token".into()),
            session_cookie: None,
            created_at: now_secs(),
            trust_profile: None,
        };
        save(&sess).unwrap();
        assert!(load("https://controller.test/", "admin", "A").is_some());
        clear_identity("https://controller.test", "admin", "A");
        assert!(load(&sess.key_url, "admin", "A").is_none());
        save(&sess).unwrap();
        sess.site = "B".into();
        save(&sess).unwrap();
        sess.username = "other-user".into();
        save(&sess).unwrap();
        clear_principal("https://controller.test/", "admin");
        assert!(load(&sess.key_url, "admin", "A").is_none());
        assert!(load(&sess.key_url, "admin", "B").is_none());
        assert!(load(&sess.key_url, "other-user", "B").is_some());
        for distinct in [
            "http://controller.test/",
            "https://controller.test:8443/",
            "https://controller.test/path/",
            "https://other.test/",
        ] {
            assert!(!same_controller(&sess.key_url, distinct));
        }
        assert!(!same_controller("invalid", "invalid"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_cache_is_not_read_or_chmodded() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        test_set_dir(dir.path());
        let target = dir.path().join("other");
        fs::write(&target, "private unrelated text").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&target, session_path().unwrap()).unwrap();
        assert!(load("https://controller.test", "admin", "A").is_none());
        assert_eq!(
            fs::metadata(target).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }
}

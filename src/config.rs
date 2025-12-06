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
    #[error("API key is required; set it with `unifictl configure --key <key>`")]
    MissingApiKey,
    #[error(
        "Local controller url/username/password/site are required; set them with `unifictl local configure ...`"
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
    }
    let serialized = serde_yaml::to_string(config).context("serializing config")?;
    fs::write(&path, serialized).with_context(|| format!("writing {:?}", path))?;
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
}

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// A Firefox profile entry from profiles.ini.
#[derive(Debug)]
pub struct Profile {
    pub name: String,
    pub path: PathBuf,
    pub is_default: bool,
}

/// A single login entry from logins.json (encrypted fields).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawLogin {
    #[serde(alias = "origin")]
    hostname: Option<String>,
    encrypted_username: Option<String>,
    encrypted_password: Option<String>,
    #[serde(default)]
    time_created: Option<u64>,
    #[serde(default)]
    time_last_used: Option<u64>,
    #[serde(default)]
    time_password_changed: Option<u64>,
    #[serde(default)]
    times_used: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct LoginsFile {
    logins: Vec<RawLogin>,
}

/// A decrypted login ready for display.
#[derive(Debug, Clone)]
pub struct Login {
    pub hostname: String,
    pub username: String,
    pub password: String,
    pub time_created: u64,
    pub time_last_used: u64,
    pub time_password_changed: u64,
    pub times_used: u32,
}

/// Find the Firefox data directory for the current platform.
pub fn firefox_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME not set")?;

    let candidates = if cfg!(target_os = "macos") {
        vec![PathBuf::from(&home).join("Library/Application Support/Firefox")]
    } else {
        vec![
            PathBuf::from(&home).join(".mozilla/firefox"),
            PathBuf::from(&home).join("snap/firefox/common/.mozilla/firefox"),
            PathBuf::from(&home).join(".var/app/org.mozilla.firefox/.mozilla/firefox"),
        ]
    };

    for dir in &candidates {
        if dir.is_dir() {
            return Ok(dir.clone());
        }
    }

    bail!(
        "Firefox data directory not found. Searched:\n{}",
        candidates
            .iter()
            .map(|p| format!("  {}", p.display()))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Parse profiles.ini and return all profiles.
pub fn list_profiles(firefox_dir: &Path) -> Result<Vec<Profile>> {
    let ini_path = firefox_dir.join("profiles.ini");
    let mut config = ini::configparser::ini::Ini::new();
    config
        .load(ini_path.to_str().unwrap_or_default())
        .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", ini_path.display()))?;

    // Find the install-default profile path (from [Install*] sections)
    let mut install_default_path: Option<PathBuf> = None;
    for section in config.sections() {
        if section.starts_with("install") {
            if let Some(raw_path) = config.get(&section, "default") {
                install_default_path = Some(firefox_dir.join(&raw_path));
            }
        }
    }

    let mut profiles = Vec::new();

    for section in config.sections() {
        if !section.starts_with("profile") {
            continue;
        }

        let name = config
            .get(&section, "name")
            .unwrap_or_else(|| section.clone());
        let raw_path = match config.get(&section, "path") {
            Some(p) => p,
            None => continue,
        };

        let is_relative = config
            .get(&section, "isrelative")
            .map(|v| v == "1")
            .unwrap_or(true);

        let path = if is_relative {
            firefox_dir.join(&raw_path)
        } else {
            PathBuf::from(&raw_path)
        };

        // Mark as default if it matches the install-default path, or has Default=1
        let is_default = install_default_path
            .as_ref()
            .map(|d| d == &path)
            .unwrap_or(false)
            || config
                .get(&section, "default")
                .map(|v| v == "1")
                .unwrap_or(false);

        profiles.push(Profile {
            name,
            path,
            is_default,
        });
    }

    if profiles.is_empty() {
        bail!("no profiles found in {}", ini_path.display());
    }

    Ok(profiles)
}

/// Pick the default profile. Prefers profiles that have key4.db, then
/// install-default, then first available.
pub fn default_profile(profiles: &[Profile]) -> &Profile {
    // Prefer: default profile with key4.db > any profile with key4.db > first
    profiles
        .iter()
        .find(|p| p.is_default && p.path.join("key4.db").exists())
        .or_else(|| profiles.iter().find(|p| p.path.join("key4.db").exists()))
        .or_else(|| profiles.iter().find(|p| p.is_default))
        .unwrap_or(&profiles[0])
}

/// Find a profile by name.
pub fn find_profile<'a>(profiles: &'a [Profile], name: &str) -> Result<&'a Profile> {
    profiles
        .iter()
        .find(|p| p.name == name)
        .with_context(|| {
            let names: Vec<_> = profiles.iter().map(|p| p.name.as_str()).collect();
            format!("profile {name:?} not found. Available: {names:?}")
        })
}

/// Read logins.json and decrypt all entries.
pub fn load_logins(profile_dir: &Path, master_key: &crate::decrypt::MasterKeys) -> Result<Vec<Login>> {
    let logins_path = profile_dir.join("logins.json");
    if !logins_path.exists() {
        bail!("logins.json not found in {}", profile_dir.display());
    }

    let data = std::fs::read_to_string(&logins_path)
        .with_context(|| format!("failed to read {}", logins_path.display()))?;

    let file: LoginsFile =
        serde_json::from_str(&data).context("failed to parse logins.json")?;

    let mut logins = Vec::new();
    for raw in &file.logins {
        let hostname = match &raw.hostname {
            Some(h) => h.clone(),
            None => continue,
        };
        let enc_user = match &raw.encrypted_username {
            Some(u) => u,
            None => continue,
        };
        let enc_pass = match &raw.encrypted_password {
            Some(p) => p,
            None => continue,
        };
        let username = match crate::decrypt::decrypt_login_field(master_key, enc_user) {
            Ok(u) => u,
            Err(_) => continue,
        };
        let password = match crate::decrypt::decrypt_login_field(master_key, enc_pass) {
            Ok(p) => p,
            Err(_) => continue,
        };
        logins.push(Login {
            hostname,
            username,
            password,
            time_created: raw.time_created.unwrap_or(0),
            time_last_used: raw.time_last_used.unwrap_or(0),
            time_password_changed: raw.time_password_changed.unwrap_or(0),
            times_used: raw.times_used.unwrap_or(0),
        });
    }

    Ok(logins)
}

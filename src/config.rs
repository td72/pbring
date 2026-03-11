use crate::error::{PbringError, Result};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Config {
    pub poll_interval_ms: u64,
    pub max_entries: usize,
    pub ttl_seconds: u64,
    pub max_entry_bytes: usize,
    pub record_types: Vec<String>,
    pub extra_ignored_types: Vec<String>,
    pub ignored_apps: Vec<String>,
    pub preview_max_chars: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            poll_interval_ms: 500,
            max_entries: 1000,
            ttl_seconds: 86400,
            max_entry_bytes: 10_485_760,
            record_types: vec!["text".to_string(), "image".to_string(), "file".to_string()],
            extra_ignored_types: vec![],
            ignored_apps: vec![],
            preview_max_chars: 100,
        }
    }
}

impl Config {
    pub fn config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("~/.config"))
            .join("pbring")
            .join("config.toml")
    }

    pub fn db_path() -> PathBuf {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("~/.local/share"))
            .join("pbring")
            .join("history.db")
    }

    pub fn pid_path() -> PathBuf {
        dirs::state_dir()
            .unwrap_or_else(|| {
                dirs::home_dir()
                    .unwrap_or_else(|| PathBuf::from("~"))
                    .join(".local")
                    .join("state")
            })
            .join("pbring")
            .join("pbringd.pid")
    }

    pub fn load() -> Result<Self> {
        let path = Self::config_path();
        if path.exists() {
            let content = std::fs::read_to_string(&path).map_err(PbringError::Io)?;
            toml::from_str(&content).map_err(|e| PbringError::Config(e.to_string()))
        } else {
            Ok(Self::default())
        }
    }
}

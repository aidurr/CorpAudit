use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub telemetry_domains: Vec<String>,
    pub memory_threshold_mb: f64,
    pub cpu_threshold_percent: f64,
    pub startup_threshold_ms: u64,
    pub permission_patterns: HashMap<String, Vec<String>>,
    pub alternatives: HashMap<String, String>,
    #[serde(default = "default_history_retention_days")]
    pub history_retention_days: u32,
    #[serde(default = "default_threat_model")]
    pub threat_model: String,
    #[serde(default = "default_monitor_interval")]
    pub monitor_interval_seconds: u64,
    #[serde(default = "default_enable_notifications")]
    pub enable_notifications: bool,
    #[serde(default)]
    pub whitelisted_processes: Vec<String>,
    #[serde(default)]
    pub whitelisted_domains: Vec<String>,
}

fn default_history_retention_days() -> u32 {
    90
}
fn default_threat_model() -> String {
    "balanced".to_string()
}
fn default_monitor_interval() -> u64 {
    300
}
fn default_enable_notifications() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        let telemetry_domains = vec![
            "google-analytics.com".to_string(),
            "analytics.google.com".to_string(),
            "stats.pushshift.com".to_string(),
            "telemetry.mozilla.org".to_string(),
            "vortex.data.microsoft.com".to_string(),
            "settings-win.data.microsoft.com".to_string(),
            "telemetry.unity3d.com".to_string(),
            "config.edge.skype.com".to_string(),
            "browser.pipe.aria.microsoft.com".to_string(),
            "sb.scorecardresearch.com".to_string(),
            "doubleclick.net".to_string(),
            "facebook.com/tr".to_string(),
            "connect.facebook.net".to_string(),
            "amazonaws.com".to_string(),
            "cloudfront.net".to_string(),
            "segment.io".to_string(),
            "mixpanel.com".to_string(),
            "amplitude.com".to_string(),
            "fullstory.com".to_string(),
            "logrocket.com".to_string(),
        ];

        let mut permission_patterns = HashMap::new();
        
        // Windows-specific permission patterns
        permission_patterns.insert(
            "camera".to_string(),
            vec![
                r"\Device\IoVideo".to_string(),
                r"\Device\HarddiskVolume".to_string(),
            ],
        );
        permission_patterns.insert(
            "microphone".to_string(),
            vec![
                r"\Device\HarddiskVolume".to_string(),
                r"\Device\Audio".to_string(),
            ],
        );
        permission_patterns.insert(
            "location".to_string(),
            vec![
                r"\Registry\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor".to_string(),
            ],
        );
        permission_patterns.insert(
            "filesystem".to_string(),
            vec![
                r"\Device\HarddiskVolume".to_string(),
                r"\??\C:\".to_string(),
                r"\??\D:\".to_string(),
            ],
        );
        permission_patterns.insert(
            "network".to_string(),
            vec![
                r"\Device\Tcp".to_string(),
                r"\Device\Udp".to_string(),
                r"\Device\Afd".to_string(),
            ],
        );
        permission_patterns.insert(
            "clipboard".to_string(),
            vec![
                r"\Clipboard".to_string(),
            ],
        );

        let mut alternatives = HashMap::new();
        alternatives.insert(
            "chrome".to_string(),
            "Brave Browser, Firefox, LibreWolf".to_string(),
        );
        alternatives.insert("vscode".to_string(), "VSCodium, Neovim, Helix".to_string());
        alternatives.insert(
            "slack".to_string(),
            "Matrix, Element, Mattermost".to_string(),
        );
        alternatives.insert(
            "discord".to_string(),
            "Matrix, Element, Guilded".to_string(),
        );
        alternatives.insert("teams".to_string(), "Matrix, Element, Jitsi".to_string());
        alternatives.insert(
            "spotify".to_string(),
            "Spotifyd, Audacious, Rhythmbox".to_string(),
        );
        alternatives.insert(
            "steam".to_string(),
            "Heroic Games Launcher, Lutris, ProtonUp-Qt".to_string(),
        );

        Self {
            telemetry_domains,
            memory_threshold_mb: 200.0,
            cpu_threshold_percent: 10.0,
            startup_threshold_ms: 2000,
            permission_patterns,
            alternatives,
            history_retention_days: 90,
            threat_model: "balanced".to_string(),
            monitor_interval_seconds: 300,
            enable_notifications: true,
            whitelisted_processes: Vec::new(),
            whitelisted_domains: Vec::new(),
        }
    }
}

impl Config {
    pub fn load_or_default() -> Result<Self> {
        let config_path = Self::get_config_path();

        if config_path.exists() {
            Self::load(&config_path)
        } else {
            Ok(Self::default())
        }
    }

    pub fn load(path: &PathBuf) -> Result<Self> {
        let content = fs::read_to_string(path)
            .context(format!("Failed to read config file: {}", path.display()))?;

        let config: Config =
            serde_json::from_str(&content).context("Failed to parse config file")?;

        Ok(config)
    }

    pub fn save(&self) -> Result<()> {
        let config_path = Self::get_config_path();

        // Create config directory if it doesn't exist
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent).context(format!(
                "Failed to create config directory: {}",
                parent.display()
            ))?;
        }

        let content = serde_json::to_string_pretty(self).context("Failed to serialize config")?;

        fs::write(&config_path, content).context(format!(
            "Failed to write config file: {}",
            config_path.display()
        ))?;

        Ok(())
    }

    fn get_config_path() -> PathBuf {
        let config_dir = dirs::config_dir().unwrap_or_else(|| PathBuf::from("/etc"));

        config_dir.join("corpaudit").join("config.json")
    }

    pub fn get_telemetry_domains(&self) -> &[String] {
        &self.telemetry_domains
    }

    pub fn get_memory_threshold_mb(&self) -> f64 {
        self.memory_threshold_mb
    }

    pub fn get_cpu_threshold_percent(&self) -> f64 {
        self.cpu_threshold_percent
    }

    #[allow(dead_code)]
    pub fn get_startup_threshold_ms(&self) -> u64 {
        self.startup_threshold_ms
    }

    pub fn get_permission_patterns(&self) -> &HashMap<String, Vec<String>> {
        &self.permission_patterns
    }

    #[allow(dead_code)]
    pub fn add_telemetry_domain(&mut self, domain: String) {
        self.telemetry_domains.push(domain);
    }

    #[allow(dead_code)]
    pub fn add_alternative(&mut self, process_name: String, alternative: String) {
        self.alternatives.insert(process_name, alternative);
    }

    #[allow(dead_code)]
    pub fn set_memory_threshold(&mut self, threshold_mb: f64) {
        self.memory_threshold_mb = threshold_mb;
    }

    #[allow(dead_code)]
    pub fn set_cpu_threshold(&mut self, threshold_percent: f64) {
        self.cpu_threshold_percent = threshold_percent;
    }

    #[allow(dead_code)]
    pub fn set_startup_threshold(&mut self, threshold_ms: u64) {
        self.startup_threshold_ms = threshold_ms;
    }

    pub fn get_alternative(&self, process_name: &str) -> Option<String> {
        let lower_name = process_name.to_lowercase();
        for (key, value) in &self.alternatives {
            if lower_name.contains(&key.to_lowercase()) {
                return Some(value.clone());
            }
        }
        None
    }

    pub fn is_process_whitelisted(&self, process_name: &str) -> bool {
        let lower = process_name.to_lowercase();
        self.whitelisted_processes
            .iter()
            .any(|p| lower.contains(&p.to_lowercase()))
    }

    pub fn is_domain_whitelisted(&self, domain: &str) -> bool {
        let lower = domain.to_lowercase();
        self.whitelisted_domains
            .iter()
            .any(|d| lower.contains(&d.to_lowercase()))
    }

    pub fn add_process_to_whitelist(&mut self, process: String) -> bool {
        if !self.whitelisted_processes.contains(&process) {
            self.whitelisted_processes.push(process);
            true
        } else {
            false
        }
    }

    pub fn add_domain_to_whitelist(&mut self, domain: String) -> bool {
        if !self.whitelisted_domains.contains(&domain) {
            self.whitelisted_domains.push(domain);
            true
        } else {
            false
        }
    }

    pub fn remove_process_from_whitelist(&mut self, process: &str) -> bool {
        if let Some(pos) = self.whitelisted_processes.iter().position(|p| p == process) {
            self.whitelisted_processes.remove(pos);
            true
        } else {
            false
        }
    }

    pub fn remove_domain_from_whitelist(&mut self, domain: &str) -> bool {
        if let Some(pos) = self.whitelisted_domains.iter().position(|d| d == domain) {
            self.whitelisted_domains.remove(pos);
            true
        } else {
            false
        }
    }
}

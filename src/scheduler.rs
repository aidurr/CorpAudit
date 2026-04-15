use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleEntry {
    pub name: String,
    pub frequency: String,
    pub created_at: String,
    pub last_run: Option<String>,
    pub enabled: bool,
}

pub struct Scheduler {
    schedules_path: PathBuf,
}

impl Scheduler {
    pub fn new() -> Result<Self> {
        let schedules_path = Self::get_schedules_path()?;

        if let Some(parent) = schedules_path.parent() {
            fs::create_dir_all(parent).context("Failed to create scheduler directory")?;
        }

        Ok(Self { schedules_path })
    }

    pub fn create_schedule(&self, frequency: &str) -> Result<()> {
        let valid_frequencies = ["hourly", "daily", "weekly", "monthly"];
        if !valid_frequencies.contains(&frequency) {
            anyhow::bail!(
                "Invalid frequency '{}'. Valid options: {}",
                frequency,
                valid_frequencies.join(", ")
            );
        }

        let entry = ScheduleEntry {
            name: format!("corpaudit_{}", frequency),
            frequency: frequency.to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            last_run: None,
            enabled: true,
        };

        let mut schedules = self.load_schedules()?;
        schedules.retain(|s| s.frequency != frequency);
        schedules.push(entry);

        self.save_schedules(&schedules)?;
        self.install_cron_job(frequency)?;

        Ok(())
    }

    pub fn list_schedules(&self) -> Result<Vec<(String, String)>> {
        let schedules = self.load_schedules()?;
        Ok(schedules
            .iter()
            .map(|s| {
                (
                    s.name.clone(),
                    format!(
                        "{} ({})",
                        s.frequency,
                        if s.enabled { "enabled" } else { "disabled" }
                    ),
                )
            })
            .collect())
    }

    pub fn remove_schedule(&self, name: &str) -> Result<bool> {
        let mut schedules = self.load_schedules()?;
        let initial_len = schedules.len();
        schedules.retain(|s| s.name != name);

        if schedules.len() < initial_len {
            self.save_schedules(&schedules)?;
            self.remove_cron_job(name)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn load_schedules(&self) -> Result<Vec<ScheduleEntry>> {
        if !self.schedules_path.exists() {
            return Ok(Vec::new());
        }

        let content =
            fs::read_to_string(&self.schedules_path).context("Failed to read schedules file")?;

        let schedules: Vec<ScheduleEntry> =
            serde_json::from_str(&content).context("Failed to parse schedules")?;

        Ok(schedules)
    }

    fn save_schedules(&self, schedules: &[ScheduleEntry]) -> Result<()> {
        let content =
            serde_json::to_string_pretty(schedules).context("Failed to serialize schedules")?;

        fs::write(&self.schedules_path, content).context("Failed to write schedules file")?;

        Ok(())
    }

    fn install_cron_job(&self, frequency: &str) -> Result<()> {
        let cron_expression = match frequency {
            "hourly" => "0 * * * *",
            "daily" => "0 0 * * *",
            "weekly" => "0 0 * * 0",
            "monthly" => "0 0 1 * *",
            _ => anyhow::bail!("Invalid frequency"),
        };

        let script = format!(
            "{} corpaudit --all --format json --output /tmp/corpaudit_{}.json 2>/dev/null",
            cron_expression, frequency
        );

        #[cfg(unix)]
        {
            let output = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!(
                    "(crontab -l 2>/dev/null; echo '{}') | crontab -",
                    script
                ))
                .output();

            if let Err(e) = output {
                anyhow::bail!(
                    "Failed to install cron job: {}. You may need to install it manually.",
                    e
                );
            }
        }

        #[cfg(windows)]
        {
            let _ = script;
            return Err(anyhow::anyhow!("Windows Task Scheduler integration not yet implemented. Please create a scheduled task manually."));
        }

        #[cfg(unix)]
        Ok(())
    }

    fn remove_cron_job(&self, name: &str) -> Result<()> {
        #[cfg(unix)]
        {
            let output = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!(
                    "crontab -l 2>/dev/null | grep -v 'corpaudit_{}' | crontab -",
                    name
                ))
                .output();

            if let Err(e) = output {
                anyhow::bail!("Failed to remove cron job: {}", e);
            }
        }

        #[cfg(windows)]
        {
            let _ = name;
        }

        Ok(())
    }

    fn get_schedules_path() -> Result<PathBuf> {
        let config_dir = dirs::data_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        Ok(config_dir.join("corpaudit").join("schedules.json"))
    }
}

use crate::audit::AuditReport;
use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

pub struct BaselineManager {
    baseline_path: PathBuf,
}

impl BaselineManager {
    pub fn new() -> Result<Self> {
        let baseline_path = Self::get_baseline_path()?;

        if let Some(parent) = baseline_path.parent() {
            fs::create_dir_all(parent).context("Failed to create baseline directory")?;
        }

        Ok(Self { baseline_path })
    }

    pub fn save_baseline(&self, report: &AuditReport) -> Result<()> {
        let content =
            serde_json::to_string_pretty(report).context("Failed to serialize baseline report")?;

        fs::write(&self.baseline_path, content).context(format!(
            "Failed to write baseline to {}",
            self.baseline_path.display()
        ))?;

        Ok(())
    }

    pub fn load_baseline(&self) -> Result<Option<AuditReport>> {
        if !self.baseline_path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&self.baseline_path).context(format!(
            "Failed to read baseline from {}",
            self.baseline_path.display()
        ))?;

        let report: AuditReport =
            serde_json::from_str(&content).context("Failed to parse baseline report")?;

        Ok(Some(report))
    }

    #[allow(dead_code)]
    pub fn delete_baseline(&self) -> Result<()> {
        if self.baseline_path.exists() {
            fs::remove_file(&self.baseline_path).context("Failed to delete baseline")?;
        }
        Ok(())
    }

    fn get_baseline_path() -> Result<PathBuf> {
        let config_dir = dirs::data_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        Ok(config_dir.join("corpaudit").join("baseline.json"))
    }
}

use crate::audit::AuditReport;
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanHistory {
    pub scan_id: String,
    pub timestamp: String,
    pub version: String,
    pub telemetry_count: usize,
    pub bloat_count: usize,
    pub permissions_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub top_telemetry_processes: Vec<String>,
    pub top_bloat_processes: Vec<String>,
    pub total_data_sent_bytes: u64,
    pub total_data_received_bytes: u64,
    pub raw_report_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendAnalysis {
    pub period_days: u32,
    pub scan_count: usize,
    pub telemetry_trend: TrendDirection,
    pub bloat_trend: TrendDirection,
    pub privacy_trend: TrendDirection,
    pub changes: Vec<HistoryChange>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrendDirection {
    Increasing { percentage: f64 },
    Decreasing { percentage: f64 },
    Stable { variance: f64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryChange {
    pub timestamp: String,
    pub change_type: String,
    pub description: String,
    pub severity: String,
}

pub struct HistoryManager {
    history_dir: PathBuf,
    retention_days: u32,
}

impl HistoryManager {
    pub fn new() -> Result<Self> {
        let history_dir = Self::get_history_dir()?;
        
        // Create directory if it doesn't exist
        if !history_dir.exists() {
            fs::create_dir_all(&history_dir).context(format!(
                "Failed to create history directory: {}",
                history_dir.display()
            ))?;
        }

        Ok(Self {
            history_dir,
            retention_days: 90, // Default 90 days retention
        })
    }

    pub fn with_retention_days(mut self, days: u32) -> Self {
        self.retention_days = days;
        self
    }

    pub fn save_scan(&self, report: &AuditReport) -> Result<ScanHistory> {
        let history = self.extract_history_data(report);
        
        // Save as individual JSON file
        let filename = format!("{}.json", history.scan_id);
        let file_path = self.history_dir.join(&filename);
        
        let content = serde_json::to_string_pretty(&history)
            .context("Failed to serialize scan history")?;
        
        fs::write(&file_path, content)
            .context(format!("Failed to write history file: {}", file_path.display()))?;

        // Cleanup old histories
        self.cleanup_old_histories()?;

        Ok(history)
    }

    pub fn save_scan_report(&self, report: &AuditReport) -> Result<ScanHistory> {
        self.save_scan(report)
    }

    pub fn load_history(&self, days: u32) -> Result<Vec<ScanHistory>> {
        let cutoff = Utc::now() - Duration::days(days as i64);
        let mut histories = Vec::new();

        if !self.history_dir.exists() {
            return Ok(histories);
        }

        for entry in fs::read_dir(&self.history_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            let content = fs::read_to_string(&path)?;
            let history: ScanHistory = serde_json::from_str(&content)
                .context(format!("Failed to parse history file: {}", path.display()))?;

            // Parse timestamp and filter by cutoff
            if let Ok(timestamp) = DateTime::parse_from_rfc3339(&history.timestamp) {
                if timestamp.with_timezone(&Utc) >= cutoff {
                    histories.push(history);
                }
            }
        }

        // Sort by timestamp (newest first)
        histories.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        Ok(histories)
    }

    pub fn analyze_trends(&self, days: u32) -> Result<TrendAnalysis> {
        let histories = self.load_history(days)?;
        
        if histories.is_empty() {
            return Ok(TrendAnalysis {
                period_days: days,
                scan_count: 0,
                telemetry_trend: TrendDirection::Stable { variance: 0.0 },
                bloat_trend: TrendDirection::Stable { variance: 0.0 },
                privacy_trend: TrendDirection::Stable { variance: 0.0 },
                changes: Vec::new(),
                recommendations: vec!["No historical data available. Run multiple scans to generate trend data.".to_string()],
            });
        }

        let telemetry_counts: Vec<_> = histories.iter().map(|h| h.telemetry_count).collect();
        let bloat_counts: Vec<_> = histories.iter().map(|h| h.bloat_count).collect();

        let telemetry_trend = Self::calculate_trend(&telemetry_counts);
        let bloat_trend = Self::calculate_trend(&bloat_counts);
        
        // Privacy trend is inverse of telemetry trend (less telemetry = better privacy)
        let privacy_trend = match &telemetry_trend {
            TrendDirection::Increasing { percentage } => {
                TrendDirection::Decreasing { percentage: *percentage }
            }
            TrendDirection::Decreasing { percentage } => {
                TrendDirection::Increasing { percentage: *percentage }
            }
            other => other.clone(),
        };

        let changes = self.detect_changes(&histories)?;
        let recommendations = self.generate_trend_recommendations(&histories, &telemetry_trend, &bloat_trend)?;

        Ok(TrendAnalysis {
            period_days: days,
            scan_count: histories.len(),
            telemetry_trend,
            bloat_trend,
            privacy_trend,
            changes,
            recommendations,
        })
    }

    pub fn get_comparison_dates(&self) -> Result<Vec<String>> {
        let histories = self.load_history(365)?; // Last year
        Ok(histories.iter().map(|h| h.timestamp.clone()).collect())
    }

    pub fn load_scan_by_id(&self, scan_id: &str) -> Result<Option<ScanHistory>> {
        let file_path = self.history_dir.join(format!("{}.json", scan_id));
        
        if !file_path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&file_path)?;
        let history: ScanHistory = serde_json::from_str(&content)
            .context(format!("Failed to parse history file: {}", file_path.display()))?;

        Ok(Some(history))
    }

    fn extract_history_data(&self, report: &AuditReport) -> ScanHistory {
        let scan_id = uuid::Uuid::new_v4().to_string();
        
        let telemetry_count = report.telemetry.as_ref().map_or(0, |t| t.findings.len());
        let bloat_count = report.bloat.as_ref().map_or(0, |b| b.findings.len());
        let permissions_count = report.permissions.as_ref().map_or(0, |p| p.findings.len());
        
        let critical_count = self.count_severity(report, "critical");
        let high_count = self.count_severity(report, "high");
        let medium_count = self.count_severity(report, "medium");
        let low_count = self.count_severity(report, "low");

        let top_telemetry_processes = report.telemetry.as_ref().map_or(Vec::new(), |t| {
            t.findings.iter()
                .take(5)
                .map(|f| f.process_name.clone())
                .collect()
        });

        let top_bloat_processes = report.bloat.as_ref().map_or(Vec::new(), |b| {
            b.findings.iter()
                .take(5)
                .map(|f| f.process_name.clone())
                .collect()
        });

        let total_data_sent_bytes = report.telemetry.as_ref().map_or(0, |t| {
            t.findings.iter().map(|f| f.data_sent.unwrap_or(0)).sum()
        });

        let total_data_received_bytes = report.telemetry.as_ref().map_or(0, |t| {
            t.findings.iter().map(|f| f.data_received.unwrap_or(0)).sum()
        });

        ScanHistory {
            scan_id,
            timestamp: report.timestamp.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            telemetry_count,
            bloat_count,
            permissions_count,
            critical_count,
            high_count,
            medium_count,
            low_count,
            top_telemetry_processes,
            top_bloat_processes,
            total_data_sent_bytes,
            total_data_received_bytes,
            raw_report_path: None,
        }
    }

    fn count_severity(&self, report: &AuditReport, severity: &str) -> usize {
        let mut count = 0;
        
        if let Some(ref telemetry) = report.telemetry {
            for finding in &telemetry.findings {
                if format!("{:?}", finding.severity).to_lowercase() == severity {
                    count += 1;
                }
            }
        }
        
        if let Some(ref bloat) = report.bloat {
            for finding in &bloat.findings {
                if format!("{:?}", finding.severity).to_lowercase() == severity {
                    count += 1;
                }
            }
        }
        
        if let Some(ref permissions) = report.permissions {
            for finding in &permissions.findings {
                if format!("{:?}", finding.severity).to_lowercase() == severity {
                    count += 1;
                }
            }
        }
        
        count
    }

    fn calculate_trend(values: &[usize]) -> TrendDirection {
        if values.len() < 2 {
            return TrendDirection::Stable { variance: 0.0 };
        }

        let first_half: Vec<_> = values[..values.len() / 2].iter().map(|v| *v as f64).collect();
        let second_half: Vec<_> = values[values.len() / 2..].iter().map(|v| *v as f64).collect();

        let first_avg = first_half.iter().sum::<f64>() / first_half.len() as f64;
        let second_avg = second_half.iter().sum::<f64>() / second_half.len() as f64;

        if first_avg == 0.0 {
            if second_avg == 0.0 {
                return TrendDirection::Stable { variance: 0.0 };
            } else {
                return TrendDirection::Increasing { percentage: 100.0 };
            }
        }

        let percentage_change = ((second_avg - first_avg) / first_avg) * 100.0;

        if percentage_change.abs() < 10.0 {
            // Less than 10% change is considered stable
            let variance = values.iter().map(|v| {
                let diff = *v as f64 - second_avg;
                diff * diff
            }).sum::<f64>() / values.len() as f64;
            
            TrendDirection::Stable { variance }
        } else if percentage_change > 0.0 {
            TrendDirection::Increasing { percentage: percentage_change.abs() }
        } else {
            TrendDirection::Decreasing { percentage: percentage_change.abs() }
        }
    }

    fn detect_changes(&self, histories: &[ScanHistory]) -> Result<Vec<HistoryChange>> {
        let mut changes = Vec::new();

        for i in 1..histories.len() {
            let prev = &histories[i];
            let curr = &histories[i - 1];

            // Detect new telemetry
            if curr.telemetry_count > prev.telemetry_count {
                changes.push(HistoryChange {
                    timestamp: curr.timestamp.clone(),
                    change_type: "new_telemetry".to_string(),
                    description: format!(
                        "Telemetry findings increased from {} to {}",
                        prev.telemetry_count, curr.telemetry_count
                    ),
                    severity: "high".to_string(),
                });
            }

            // Detect removed telemetry
            if curr.telemetry_count < prev.telemetry_count {
                changes.push(HistoryChange {
                    timestamp: curr.timestamp.clone(),
                    change_type: "telemetry_removed".to_string(),
                    description: format!(
                        "Telemetry findings decreased from {} to {}",
                        prev.telemetry_count, curr.telemetry_count
                    ),
                    severity: "info".to_string(),
                });
            }

            // Detect new bloat
            if curr.bloat_count > prev.bloat_count {
                changes.push(HistoryChange {
                    timestamp: curr.timestamp.clone(),
                    change_type: "new_bloat".to_string(),
                    description: format!(
                        "Bloat findings increased from {} to {}",
                        prev.bloat_count, curr.bloat_count
                    ),
                    severity: "medium".to_string(),
                });
            }
        }

        Ok(changes)
    }

    fn generate_trend_recommendations(
        &self,
        histories: &[ScanHistory],
        telemetry_trend: &TrendDirection,
        bloat_trend: &TrendDirection,
    ) -> Result<Vec<String>> {
        let mut recommendations = Vec::new();

        match telemetry_trend {
            TrendDirection::Increasing { percentage } => {
                recommendations.push(format!(
                    "Telemetry is increasing by {:.1}%. Consider applying telemetry fixes.",
                    percentage
                ));
            }
            TrendDirection::Decreasing { percentage } => {
                recommendations.push(format!(
                    "Good progress! Telemetry decreased by {:.1}%.",
                    percentage
                ));
            }
            _ => {}
        }

        match bloat_trend {
            TrendDirection::Increasing { percentage } => {
                recommendations.push(format!(
                    "Application bloat is increasing by {:.1}%. Consider optimizing or replacing bloated apps.",
                    percentage
                ));
            }
            TrendDirection::Decreasing { percentage } => {
                recommendations.push(format!(
                    "Bloat decreased by {:.1}%. Your optimizations are working.",
                    percentage
                ));
            }
            _ => {}
        }

        // Check for persistent high telemetry
        if histories.len() >= 3 {
            let recent_telemetry: Vec<_> = histories.iter().take(3).map(|h| h.telemetry_count).collect();
            if recent_telemetry.iter().all(|&c| c > 5) {
                recommendations.push(
                    "Consistently high telemetry detected. Consider comprehensive privacy measures.".to_string()
                );
            }
        }

        if recommendations.is_empty() {
            recommendations.push("No specific recommendations. Continue monitoring for trends.".to_string());
        }

        Ok(recommendations)
    }

    fn cleanup_old_histories(&self) -> Result<()> {
        let cutoff = Utc::now() - Duration::days(self.retention_days as i64);

        if !self.history_dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(&self.history_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            let content = fs::read_to_string(&path)?;
            if let Ok(history) = serde_json::from_str::<ScanHistory>(&content) {
                if let Ok(timestamp) = DateTime::parse_from_rfc3339(&history.timestamp) {
                    if timestamp.with_timezone(&Utc) < cutoff {
                        fs::remove_file(&path)?;
                    }
                }
            }
        }

        Ok(())
    }

    fn get_history_dir() -> Result<PathBuf> {
        let config_dir = dirs::data_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        Ok(config_dir.join("corpaudit").join("history"))
    }
}

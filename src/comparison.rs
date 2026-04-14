use crate::audit::*;
use crate::scorer::{PrivacyScore, PrivacyScorer, ThreatModel};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportComparison {
    pub baseline_timestamp: String,
    pub current_timestamp: String,
    pub telemetry_changes: TelemetryChanges,
    pub bloat_changes: BloatChanges,
    pub permissions_changes: PermissionsChanges,
    pub score_changes: Option<ScoreChanges>,
    pub summary: ComparisonSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryChanges {
    pub new_findings: Vec<TelemetryFinding>,
    pub removed_findings: Vec<TelemetryFinding>,
    pub changed_findings: Vec<TelemetryChange>,
    pub domain_changes: Vec<DomainChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryChange {
    pub process_name: String,
    pub pid: u32,
    pub baseline: TelemetryFinding,
    pub current: TelemetryFinding,
    pub change_type: ChangeType,
    pub changes: Vec<FieldChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainChange {
    pub domain: String,
    pub change_type: String, // "new", "removed"
    pub process_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloatChanges {
    pub new_findings: Vec<BloatFinding>,
    pub removed_findings: Vec<BloatFinding>,
    pub changed_findings: Vec<BloatChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloatChange {
    pub process_name: String,
    pub pid: u32,
    pub baseline: BloatFinding,
    pub current: BloatFinding,
    pub changes: Vec<FieldChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionsChanges {
    pub new_findings: Vec<PermissionsFinding>,
    pub removed_findings: Vec<PermissionsFinding>,
    pub changed_findings: Vec<PermissionsChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionsChange {
    pub process_name: String,
    pub pid: u32,
    pub baseline: PermissionsFinding,
    pub current: PermissionsFinding,
    pub changes: Vec<FieldChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreChanges {
    pub baseline_score: PrivacyScore,
    pub current_score: PrivacyScore,
    pub score_difference: f64,
    pub grade_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldChange {
    pub field: String,
    pub old_value: String,
    pub new_value: String,
    pub significance: ChangeSignificance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChangeSignificance {
    Critical,
    Significant,
    Minor,
    Informational,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChangeType {
    Increased,
    Decreased,
    SeverityIncreased,
    SeverityDecreased,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonSummary {
    pub total_changes: usize,
    pub critical_changes: usize,
    pub significant_changes: usize,
    pub minor_changes: usize,
    pub telemetry_improvement: bool,
    pub bloat_improvement: bool,
    pub permissions_improvement: bool,
    pub overall_trend: ChangeTrend,
    pub key_highlights: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChangeTrend {
    Improved { points: f64 },
    Degraded { points: f64 },
    Stable,
}

pub struct DiffEngine;

impl DiffEngine {
    pub fn compare_reports(
        baseline: &AuditReport,
        current: &AuditReport,
    ) -> Result<ReportComparison> {
        let telemetry_changes =
            Self::diff_telemetry(baseline.telemetry.as_ref(), current.telemetry.as_ref());

        let bloat_changes = Self::diff_bloat(baseline.bloat.as_ref(), current.bloat.as_ref());

        let permissions_changes =
            Self::diff_permissions(baseline.permissions.as_ref(), current.permissions.as_ref());

        let score_changes = Self::calculate_score_changes(baseline, current)?;

        let summary = Self::generate_summary(
            &telemetry_changes,
            &bloat_changes,
            &permissions_changes,
            &score_changes,
        );

        Ok(ReportComparison {
            baseline_timestamp: baseline.timestamp.clone(),
            current_timestamp: current.timestamp.clone(),
            telemetry_changes,
            bloat_changes,
            permissions_changes,
            score_changes,
            summary,
        })
    }

    fn diff_telemetry(
        baseline: Option<&TelemetryReport>,
        current: Option<&TelemetryReport>,
    ) -> TelemetryChanges {
        let baseline_findings = baseline.map_or(Vec::new(), |r| r.findings.clone());
        let current_findings = current.map_or(Vec::new(), |r| r.findings.clone());

        let baseline_map: HashMap<_, _> = baseline_findings
            .iter()
            .map(|f| (Self::normalize_process_name(&f.process_name), f))
            .collect();

        let current_map: HashMap<_, _> = current_findings
            .iter()
            .map(|f| (Self::normalize_process_name(&f.process_name), f))
            .collect();

        // New findings
        let new_findings: Vec<_> = current_findings
            .iter()
            .filter(|f| !baseline_map.contains_key(&Self::normalize_process_name(&f.process_name)))
            .cloned()
            .collect();

        // Removed findings
        let removed_findings: Vec<_> = baseline_findings
            .iter()
            .filter(|f| !current_map.contains_key(&Self::normalize_process_name(&f.process_name)))
            .cloned()
            .collect();

        // Changed findings
        let changed_findings: Vec<_> = current_findings
            .iter()
            .filter_map(|current_finding| {
                let normalized = Self::normalize_process_name(&current_finding.process_name);
                if let Some(baseline_finding) = baseline_map.get(&normalized) {
                    let changes =
                        Self::compare_telemetry_findings(baseline_finding, current_finding);
                    if !changes.is_empty() {
                        Some(TelemetryChange {
                            process_name: current_finding.process_name.clone(),
                            pid: current_finding.pid,
                            baseline: (*baseline_finding).clone(),
                            current: current_finding.clone(),
                            change_type: Self::determine_telemetry_change_type(&changes),
                            changes,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        // Domain changes
        let domain_changes = Self::detect_domain_changes(&baseline_map, &current_map);

        TelemetryChanges {
            new_findings,
            removed_findings,
            changed_findings,
            domain_changes,
        }
    }

    fn compare_telemetry_findings(
        baseline: &TelemetryFinding,
        current: &TelemetryFinding,
    ) -> Vec<FieldChange> {
        let mut changes = Vec::new();

        // Compare severity
        if baseline.severity != current.severity {
            let significance = if current.severity > baseline.severity {
                ChangeSignificance::Critical
            } else {
                ChangeSignificance::Significant
            };

            changes.push(FieldChange {
                field: "severity".to_string(),
                old_value: format!("{:?}", baseline.severity),
                new_value: format!("{:?}", current.severity),
                significance,
            });
        }

        // Compare connection count
        if baseline.connections.len() != current.connections.len() {
            let diff = current.connections.len() as i64 - baseline.connections.len() as i64;
            let significance = if diff > 10 {
                ChangeSignificance::Significant
            } else if diff > 5 {
                ChangeSignificance::Minor
            } else {
                ChangeSignificance::Informational
            };

            changes.push(FieldChange {
                field: "connections".to_string(),
                old_value: baseline.connections.len().to_string(),
                new_value: current.connections.len().to_string(),
                significance,
            });
        }

        // Compare domains
        let baseline_domains: HashSet<_> = baseline.domains.iter().collect();
        let current_domains: HashSet<_> = current.domains.iter().collect();

        let new_domains: Vec<_> = current_domains.difference(&baseline_domains).collect();
        let removed_domains: Vec<_> = baseline_domains.difference(&current_domains).collect();

        if !new_domains.is_empty() || !removed_domains.is_empty() {
            let significance = if !new_domains.is_empty() {
                ChangeSignificance::Significant
            } else {
                ChangeSignificance::Minor
            };

            changes.push(FieldChange {
                field: "domains".to_string(),
                old_value: format!("{} domains", baseline_domains.len()),
                new_value: format!("{} domains", current_domains.len()),
                significance,
            });
        }

        changes
    }

    fn detect_domain_changes(
        baseline_map: &HashMap<String, &TelemetryFinding>,
        current_map: &HashMap<String, &TelemetryFinding>,
    ) -> Vec<DomainChange> {
        let mut changes = Vec::new();

        // Collect all domains from both
        let mut all_domains: HashMap<String, Vec<String>> = HashMap::new();

        for (process, finding) in baseline_map.iter().chain(current_map.iter()) {
            for domain in &finding.domains {
                all_domains
                    .entry(domain.clone())
                    .or_default()
                    .push(process.clone());
            }
        }

        // Check for new domains
        for (domain, processes) in &all_domains {
            let in_baseline = baseline_map.values().any(|f| f.domains.contains(domain));
            let in_current = current_map.values().any(|f| f.domains.contains(domain));

            if !in_baseline && in_current {
                changes.push(DomainChange {
                    domain: domain.clone(),
                    change_type: "new".to_string(),
                    process_names: processes.clone(),
                });
            } else if in_baseline && !in_current {
                changes.push(DomainChange {
                    domain: domain.clone(),
                    change_type: "removed".to_string(),
                    process_names: processes.clone(),
                });
            }
        }

        changes
    }

    fn diff_bloat(baseline: Option<&BloatReport>, current: Option<&BloatReport>) -> BloatChanges {
        let baseline_findings = baseline.map_or(Vec::new(), |r| r.findings.clone());
        let current_findings = current.map_or(Vec::new(), |r| r.findings.clone());

        let baseline_map: HashMap<_, _> = baseline_findings
            .iter()
            .map(|f| (Self::normalize_process_name(&f.process_name), f))
            .collect();

        let current_map: HashMap<_, _> = current_findings
            .iter()
            .map(|f| (Self::normalize_process_name(&f.process_name), f))
            .collect();

        let new_findings: Vec<_> = current_findings
            .iter()
            .filter(|f| !baseline_map.contains_key(&Self::normalize_process_name(&f.process_name)))
            .cloned()
            .collect();

        let removed_findings: Vec<_> = baseline_findings
            .iter()
            .filter(|f| !current_map.contains_key(&Self::normalize_process_name(&f.process_name)))
            .cloned()
            .collect();

        let changed_findings: Vec<_> = current_findings
            .iter()
            .filter_map(|current_finding| {
                let normalized = Self::normalize_process_name(&current_finding.process_name);
                if let Some(baseline_finding) = baseline_map.get(&normalized) {
                    let changes = Self::compare_bloat_findings(baseline_finding, current_finding);
                    if !changes.is_empty() {
                        Some(BloatChange {
                            process_name: current_finding.process_name.clone(),
                            pid: current_finding.pid,
                            baseline: (*baseline_finding).clone(),
                            current: current_finding.clone(),
                            changes,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        BloatChanges {
            new_findings,
            removed_findings,
            changed_findings,
        }
    }

    fn compare_bloat_findings(baseline: &BloatFinding, current: &BloatFinding) -> Vec<FieldChange> {
        let mut changes = Vec::new();

        // Memory change
        let mem_diff = current.memory_mb - baseline.memory_mb;
        if mem_diff.abs() > 10.0 {
            let significance = if mem_diff > 100.0 {
                ChangeSignificance::Critical
            } else if mem_diff > 50.0 {
                ChangeSignificance::Significant
            } else {
                ChangeSignificance::Minor
            };

            changes.push(FieldChange {
                field: "memory_mb".to_string(),
                old_value: format!("{:.2} MB", baseline.memory_mb),
                new_value: format!("{:.2} MB", current.memory_mb),
                significance,
            });
        }

        // CPU change
        let cpu_diff = current.cpu_percent - baseline.cpu_percent;
        if cpu_diff.abs() > 5.0 {
            let significance = if cpu_diff > 20.0 {
                ChangeSignificance::Significant
            } else {
                ChangeSignificance::Minor
            };

            changes.push(FieldChange {
                field: "cpu_percent".to_string(),
                old_value: format!("{:.2}%", baseline.cpu_percent),
                new_value: format!("{:.2}%", current.cpu_percent),
                significance,
            });
        }

        changes
    }

    fn diff_permissions(
        baseline: Option<&PermissionsReport>,
        current: Option<&PermissionsReport>,
    ) -> PermissionsChanges {
        let baseline_findings = baseline.map_or(Vec::new(), |r| r.findings.clone());
        let current_findings = current.map_or(Vec::new(), |r| r.findings.clone());

        let baseline_map: HashMap<_, _> = baseline_findings
            .iter()
            .map(|f| (Self::normalize_process_name(&f.process_name), f))
            .collect();

        let current_map: HashMap<_, _> = current_findings
            .iter()
            .map(|f| (Self::normalize_process_name(&f.process_name), f))
            .collect();

        let new_findings: Vec<_> = current_findings
            .iter()
            .filter(|f| !baseline_map.contains_key(&Self::normalize_process_name(&f.process_name)))
            .cloned()
            .collect();

        let removed_findings: Vec<_> = baseline_findings
            .iter()
            .filter(|f| !current_map.contains_key(&Self::normalize_process_name(&f.process_name)))
            .cloned()
            .collect();

        let changed_findings: Vec<_> = current_findings
            .iter()
            .filter_map(|current_finding| {
                let normalized = Self::normalize_process_name(&current_finding.process_name);
                if let Some(baseline_finding) = baseline_map.get(&normalized) {
                    let changes =
                        Self::compare_permissions_findings(baseline_finding, current_finding);
                    if !changes.is_empty() {
                        Some(PermissionsChange {
                            process_name: current_finding.process_name.clone(),
                            pid: current_finding.pid,
                            baseline: (*baseline_finding).clone(),
                            current: current_finding.clone(),
                            changes,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        PermissionsChanges {
            new_findings,
            removed_findings,
            changed_findings,
        }
    }

    fn compare_permissions_findings(
        baseline: &PermissionsFinding,
        current: &PermissionsFinding,
    ) -> Vec<FieldChange> {
        let mut changes = Vec::new();

        let baseline_perms: HashSet<_> = baseline
            .permissions
            .iter()
            .map(|p| &p.permission_type)
            .collect();
        let current_perms: HashSet<_> = current
            .permissions
            .iter()
            .map(|p| &p.permission_type)
            .collect();

        let new_perms: Vec<_> = current_perms.difference(&baseline_perms).collect();
        let removed_perms: Vec<_> = baseline_perms.difference(&current_perms).collect();

        if !new_perms.is_empty() {
            changes.push(FieldChange {
                field: "permissions_added".to_string(),
                old_value: "0".to_string(),
                new_value: new_perms.len().to_string(),
                significance: ChangeSignificance::Significant,
            });
        }

        if !removed_perms.is_empty() {
            changes.push(FieldChange {
                field: "permissions_removed".to_string(),
                old_value: removed_perms.len().to_string(),
                new_value: "0".to_string(),
                significance: ChangeSignificance::Minor,
            });
        }

        if baseline.severity != current.severity {
            changes.push(FieldChange {
                field: "severity".to_string(),
                old_value: format!("{:?}", baseline.severity),
                new_value: format!("{:?}", current.severity),
                significance: ChangeSignificance::Critical,
            });
        }

        changes
    }

    fn calculate_score_changes(
        baseline: &AuditReport,
        current: &AuditReport,
    ) -> Result<Option<ScoreChanges>> {
        // Calculate scores for both reports
        let baseline_score = PrivacyScorer::calculate_score(baseline, ThreatModel::Balanced);
        let current_score = PrivacyScorer::calculate_score(current, ThreatModel::Balanced);

        let difference = current_score.overall_score - baseline_score.overall_score;

        let grade_changed = baseline_score.grade != current_score.grade;

        Ok(Some(ScoreChanges {
            baseline_score,
            current_score,
            score_difference: difference,
            grade_changed,
        }))
    }

    fn generate_summary(
        telemetry: &TelemetryChanges,
        bloat: &BloatChanges,
        permissions: &PermissionsChanges,
        score_changes: &Option<ScoreChanges>,
    ) -> ComparisonSummary {
        let mut total_changes = 0;
        let mut critical_changes = 0;
        let mut significant_changes = 0;
        let mut minor_changes = 0;
        let mut key_highlights = Vec::new();

        // Count telemetry changes
        total_changes += telemetry.new_findings.len();
        total_changes += telemetry.removed_findings.len();
        total_changes += telemetry.changed_findings.len();

        if !telemetry.new_findings.is_empty() {
            critical_changes += telemetry
                .new_findings
                .iter()
                .filter(|f| f.severity == Severity::Critical || f.severity == Severity::High)
                .count();
            key_highlights.push(format!(
                "✗ New telemetry detected for {} processes",
                telemetry.new_findings.len()
            ));
        }

        if !telemetry.removed_findings.is_empty() {
            key_highlights.push(format!(
                "✓ Telemetry removed for {} processes",
                telemetry.removed_findings.len()
            ));
        }

        for change in &telemetry.changed_findings {
            for field_change in &change.changes {
                match field_change.significance {
                    ChangeSignificance::Critical => critical_changes += 1,
                    ChangeSignificance::Significant => significant_changes += 1,
                    ChangeSignificance::Minor => minor_changes += 1,
                    ChangeSignificance::Informational => {}
                }
            }
        }

        // Count bloat changes
        total_changes += bloat.new_findings.len();
        total_changes += bloat.removed_findings.len();
        total_changes += bloat.changed_findings.len();

        if !bloat.new_findings.is_empty() {
            key_highlights.push(format!(
                "✗ New bloated applications detected: {}",
                bloat.new_findings.len()
            ));
        }

        // Count permissions changes
        total_changes += permissions.new_findings.len();
        total_changes += permissions.removed_findings.len();
        total_changes += permissions.changed_findings.len();

        // Determine improvements
        let telemetry_improvement = telemetry.removed_findings.len() > telemetry.new_findings.len();
        let bloat_improvement = bloat.removed_findings.len() > bloat.new_findings.len();
        let permissions_improvement =
            permissions.removed_findings.len() > permissions.new_findings.len();

        // Overall trend
        let overall_trend = if let Some(ref scores) = score_changes {
            if scores.score_difference > 5.0 {
                ChangeTrend::Improved {
                    points: scores.score_difference,
                }
            } else if scores.score_difference < -5.0 {
                ChangeTrend::Degraded {
                    points: scores.score_difference.abs(),
                }
            } else {
                ChangeTrend::Stable
            }
        } else {
            ChangeTrend::Stable
        };

        ComparisonSummary {
            total_changes,
            critical_changes,
            significant_changes,
            minor_changes,
            telemetry_improvement,
            bloat_improvement,
            permissions_improvement,
            overall_trend,
            key_highlights,
        }
    }

    fn determine_telemetry_change_type(changes: &[FieldChange]) -> ChangeType {
        for change in changes {
            if change.field == "severity" {
                if change.new_value > change.old_value {
                    return ChangeType::SeverityIncreased;
                } else {
                    return ChangeType::SeverityDecreased;
                }
            } else if change.field == "connections" || change.field == "domains" {
                if change.new_value.parse::<i64>().unwrap_or(0)
                    > change.old_value.parse::<i64>().unwrap_or(0)
                {
                    return ChangeType::Increased;
                } else {
                    return ChangeType::Decreased;
                }
            }
        }
        ChangeType::Increased
    }

    fn normalize_process_name(name: &str) -> String {
        name.split('.')
            .next()
            .unwrap_or(name)
            .split('_')
            .next()
            .unwrap_or(name)
            .to_lowercase()
            .trim()
            .to_string()
    }
}

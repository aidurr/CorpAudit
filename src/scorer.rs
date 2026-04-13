use crate::audit::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyScore {
    pub overall_score: f64,
    pub grade: PrivacyGrade,
    pub telemetry_subscore: f64,
    pub bloat_subscore: f64,
    pub permissions_subscore: f64,
    pub network_subscore: f64,
    pub data_exposure_subscore: f64,
    pub category_scores: HashMap<String, f64>,
    pub scoring_metadata: ScoringMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PrivacyGrade {
    APlus,
    A,
    B,
    C,
    D,
    F,
}

impl PrivacyGrade {
    pub fn from_score(score: f64) -> Self {
        match score {
            90.0..=100.0 => PrivacyGrade::APlus,
            80.0..=89.9 => PrivacyGrade::A,
            70.0..=79.9 => PrivacyGrade::B,
            60.0..=69.9 => PrivacyGrade::C,
            50.0..=59.9 => PrivacyGrade::D,
            _ => PrivacyGrade::F,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PrivacyGrade::APlus => "A+",
            PrivacyGrade::A => "A",
            PrivacyGrade::B => "B",
            PrivacyGrade::C => "C",
            PrivacyGrade::D => "D",
            PrivacyGrade::F => "F",
        }
    }

    pub fn color_name(&self) -> &'static str {
        match self {
            PrivacyGrade::APlus | PrivacyGrade::A => "green",
            PrivacyGrade::B => "yellow",
            PrivacyGrade::C => "bright yellow",
            PrivacyGrade::D => "bright red",
            PrivacyGrade::F => "red",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringMetadata {
    pub version: String,
    pub threat_model: ThreatModel,
    pub weights: ScoringWeights,
    pub baseline_system_score: f64,
    pub percentil_rank: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatModel {
    Balanced,
    Paranoid,
    Casual,
    Enterprise,
    Gaming,
}

impl ThreatModel {
    pub fn get_weights(&self) -> ScoringWeights {
        match self {
            ThreatModel::Balanced => ScoringWeights {
                telemetry_weight: 0.35,
                bloat_weight: 0.20,
                permissions_weight: 0.25,
                network_weight: 0.15,
                data_exposure_weight: 0.05,
                severity_multipliers: Self::default_severity_multipliers(),
            },
            ThreatModel::Paranoid => ScoringWeights {
                telemetry_weight: 0.50,
                bloat_weight: 0.10,
                permissions_weight: 0.20,
                network_weight: 0.15,
                data_exposure_weight: 0.05,
                severity_multipliers: Self::paranoid_severity_multipliers(),
            },
            ThreatModel::Casual => ScoringWeights {
                telemetry_weight: 0.25,
                bloat_weight: 0.25,
                permissions_weight: 0.20,
                network_weight: 0.20,
                data_exposure_weight: 0.10,
                severity_multipliers: Self::casual_severity_multipliers(),
            },
            ThreatModel::Enterprise => ScoringWeights {
                telemetry_weight: 0.30,
                bloat_weight: 0.15,
                permissions_weight: 0.20,
                network_weight: 0.20,
                data_exposure_weight: 0.15,
                severity_multipliers: Self::enterprise_severity_multipliers(),
            },
            ThreatModel::Gaming => ScoringWeights {
                telemetry_weight: 0.20,
                bloat_weight: 0.40,
                permissions_weight: 0.15,
                network_weight: 0.15,
                data_exposure_weight: 0.10,
                severity_multipliers: Self::default_severity_multipliers(),
            },
        }
    }

    fn default_severity_multipliers() -> HashMap<String, f64> {
        let mut map = HashMap::new();
        map.insert("Low".to_string(), 1.0);
        map.insert("Medium".to_string(), 2.0);
        map.insert("High".to_string(), 3.0);
        map.insert("Critical".to_string(), 5.0);
        map
    }

    fn paranoid_severity_multipliers() -> HashMap<String, f64> {
        let mut map = HashMap::new();
        map.insert("Low".to_string(), 1.5);
        map.insert("Medium".to_string(), 2.5);
        map.insert("High".to_string(), 4.0);
        map.insert("Critical".to_string(), 6.0);
        map
    }

    fn casual_severity_multipliers() -> HashMap<String, f64> {
        let mut map = HashMap::new();
        map.insert("Low".to_string(), 0.5);
        map.insert("Medium".to_string(), 1.5);
        map.insert("High".to_string(), 2.5);
        map.insert("Critical".to_string(), 4.0);
        map
    }

    fn enterprise_severity_multipliers() -> HashMap<String, f64> {
        let mut map = HashMap::new();
        map.insert("Low".to_string(), 1.2);
        map.insert("Medium".to_string(), 2.2);
        map.insert("High".to_string(), 3.5);
        map.insert("Critical".to_string(), 5.5);
        map
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringWeights {
    pub telemetry_weight: f64,
    pub bloat_weight: f64,
    pub permissions_weight: f64,
    pub network_weight: f64,
    pub data_exposure_weight: f64,
    pub severity_multipliers: HashMap<String, f64>,
}

pub struct PrivacyScorer;

impl PrivacyScorer {
    pub fn calculate_score(report: &AuditReport, threat_model: ThreatModel) -> PrivacyScore {
        let weights = threat_model.get_weights();

        let telemetry_score = Self::calculate_telemetry_score(report, &weights);
        let bloat_score = Self::calculate_bloat_score(report, &weights);
        let permissions_score = Self::calculate_permissions_score(report, &weights);
        let network_score = Self::calculate_network_score(report, &weights);
        let data_exposure_score = Self::calculate_data_exposure_score(report, &weights);

        let overall = (telemetry_score * weights.telemetry_weight
            + bloat_score * weights.bloat_weight
            + permissions_score * weights.permissions_weight
            + network_score * weights.network_weight
            + data_exposure_score * weights.data_exposure_weight)
            / (weights.telemetry_weight
                + weights.bloat_weight
                + weights.permissions_weight
                + weights.network_weight
                + weights.data_exposure_weight);

        let mut category_scores = HashMap::new();
        category_scores.insert("telemetry".to_string(), telemetry_score);
        category_scores.insert("bloat".to_string(), bloat_score);
        category_scores.insert("permissions".to_string(), permissions_score);
        category_scores.insert("network".to_string(), network_score);
        category_scores.insert("data_exposure".to_string(), data_exposure_score);

        PrivacyScore {
            overall_score: overall.clamp(0.0, 100.0),
            grade: PrivacyGrade::from_score(overall),
            telemetry_subscore: telemetry_score,
            bloat_subscore: bloat_score,
            permissions_subscore: permissions_score,
            network_subscore: network_score,
            data_exposure_subscore: data_exposure_score,
            category_scores,
            scoring_metadata: ScoringMetadata {
                version: "1.0.0".to_string(),
                threat_model: threat_model.clone(),
                weights,
                baseline_system_score: 100.0,
                percentil_rank: None,
            },
        }
    }

    fn calculate_telemetry_score(report: &AuditReport, weights: &ScoringWeights) -> f64 {
        let mut score = 100.0;

        if let Some(ref telemetry) = report.telemetry {
            for finding in &telemetry.findings {
                let multiplier = weights
                    .severity_multipliers
                    .get(&format!("{:?}", finding.severity))
                    .unwrap_or(&1.0);

                match finding.severity {
                    Severity::Critical => score -= 15.0 * multiplier,
                    Severity::High => score -= 10.0 * multiplier,
                    Severity::Medium => score -= 5.0 * multiplier,
                    Severity::Low => score -= 2.0 * multiplier,
                }

                // Additional penalty for known aggressive telemetry apps
                let known_telemetry_apps = [
                    "chrome", "firefox", "edge", "brave", "vscode", "idea", "pycharm", "slack",
                    "discord", "teams", "spotify", "steam",
                ];

                if known_telemetry_apps.iter().any(|app| {
                    finding.process_name.to_lowercase().contains(app)
                }) {
                    score -= 5.0;
                }

                // Data volume penalty: -1 point per 10MB sent
                if let Some(data_sent) = finding.data_sent {
                    score -= (data_sent as f64 / 10_485_760.0) as f64;
                }
            }
        }

        score.max(0.0)
    }

    fn calculate_bloat_score(report: &AuditReport, weights: &ScoringWeights) -> f64 {
        let mut score = 100.0;

        if let Some(ref bloat) = report.bloat {
            for finding in &bloat.findings {
                let multiplier = weights
                    .severity_multipliers
                    .get(&format!("{:?}", finding.severity))
                    .unwrap_or(&1.0);

                match finding.severity {
                    Severity::Critical => score -= 15.0 * multiplier,
                    Severity::High => score -= 10.0 * multiplier,
                    Severity::Medium => score -= 5.0 * multiplier,
                    Severity::Low => score -= 2.0 * multiplier,
                }

                // Memory penalty: -1 point per 100MB over threshold
                if finding.memory_mb > 1000.0 {
                    score -= ((finding.memory_mb - 1000.0) / 100.0) as f64;
                }

                // CPU penalty: -1 point per 10% over threshold
                if finding.cpu_percent > 50.0 {
                    score -= ((finding.cpu_percent - 50.0) / 10.0) as f64;
                }
            }
        }

        score.max(0.0)
    }

    fn calculate_permissions_score(report: &AuditReport, weights: &ScoringWeights) -> f64 {
        let mut score = 100.0;

        if let Some(ref permissions) = report.permissions {
            for finding in &permissions.findings {
                let multiplier = weights
                    .severity_multipliers
                    .get(&format!("{:?}", finding.severity))
                    .unwrap_or(&1.0);

                match finding.severity {
                    Severity::Critical => score -= 20.0 * multiplier,
                    Severity::High => score -= 10.0 * multiplier,
                    Severity::Medium => score -= 5.0 * multiplier,
                    Severity::Low => score -= 2.0 * multiplier,
                }

                // Critical permission penalties
                let critical_perms = ["camera", "microphone", "location", "contacts"];
                for perm in &finding.permissions {
                    if critical_perms.iter().any(|p| {
                        perm.permission_type.to_lowercase().contains(p)
                    }) {
                        score -= 5.0;
                    }
                }
            }
        }

        score.max(0.0)
    }

    fn calculate_network_score(report: &AuditReport, weights: &ScoringWeights) -> f64 {
        let mut score: f64 = 100.0;

        if let Some(ref telemetry) = report.telemetry {
            // Count unique remote hosts
            let mut unique_hosts = std::collections::HashSet::new();
            for finding in &telemetry.findings {
                for conn in &finding.connections {
                    unique_hosts.insert(conn.remote_address.clone());
                }
            }

            // Penalty for many unique hosts
            if unique_hosts.len() > 50 {
                score -= 20.0;
            } else if unique_hosts.len() > 20 {
                score -= 10.0;
            } else if unique_hosts.len() > 10 {
                score -= 5.0;
            }

            // Data transmission penalty
            let total_data: u64 = telemetry
                .findings
                .iter()
                .map(|f| f.data_sent.unwrap_or(0) + f.data_received.unwrap_or(0))
                .sum();

            if total_data > 100_000_000 {
                // >100MB
                score -= 15.0;
            } else if total_data > 10_000_000 {
                // >10MB
                score -= 10.0;
            } else if total_data > 1_000_000 {
                // >1MB
                score -= 5.0;
            }
        }

        score.max(0.0)
    }

    fn calculate_data_exposure_score(report: &AuditReport, _weights: &ScoringWeights) -> f64 {
        let mut score: f64 = 100.0;

        if let Some(ref telemetry) = report.telemetry {
            // Calculate total data sent
            let total_sent: u64 = telemetry
                .findings
                .iter()
                .map(|f| f.data_sent.unwrap_or(0))
                .sum();

            // Check for known data broker domains
            let data_brokers = [
                "doubleclick.net",
                "google-analytics.com",
                "facebook.com/tr",
                "scorecardresearch.com",
                "analytics.google.com",
            ];

            for finding in &telemetry.findings {
                for domain in &finding.domains {
                    if data_brokers
                        .iter()
                        .any(|broker| domain.contains(broker))
                    {
                        score -= 10.0;
                    }
                }
            }

            // Data volume penalties
            if total_sent > 50_000_000 {
                // >50MB
                score -= 20.0;
            } else if total_sent > 10_000_000 {
                // >10MB
                score -= 10.0;
            } else if total_sent > 1_000_000 {
                // >1MB
                score -= 5.0;
            }
        }

        score.max(0.0)
    }

    pub fn generate_recommendations(score: &PrivacyScore) -> Vec<String> {
        let mut recommendations = Vec::new();

        // Recommendations based on lowest subscores
        let mut subscores: Vec<_> = vec![
            ("Telemetry", score.telemetry_subscore),
            ("Bloat", score.bloat_subscore),
            ("Permissions", score.permissions_subscore),
            ("Network", score.network_subscore),
            ("Data Exposure", score.data_exposure_subscore),
        ];

        subscores.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

        // Recommend fixes for lowest scoring categories
        for (category, subscore) in subscores.iter() {
            if *subscore < 50.0 {
                recommendations.push(format!(
                    "{} score is critically low ({:.0}/100). Apply fixes for {} issues.",
                    category, subscore, category.to_lowercase()
                ));
            } else if *subscore < 70.0 {
                recommendations.push(format!(
                    "{} score is below average ({:.0}/100). Consider addressing {} issues.",
                    category, subscore, category.to_lowercase()
                ));
            }
        }

        // Grade-specific recommendations
        match score.grade {
            PrivacyGrade::F => {
                recommendations.push(
                    "Your privacy score is critically low. Immediate action recommended.".to_string(),
                );
            }
            PrivacyGrade::D => {
                recommendations.push(
                    "Significant privacy issues detected. Review and apply recommended fixes.".to_string(),
                );
            }
            PrivacyGrade::C => {
                recommendations.push(
                    "Moderate privacy issues detected. Consider applying fixes to improve score.".to_string(),
                );
            }
            _ => {
                recommendations.push(
                    "Good privacy posture maintained. Continue monitoring for changes.".to_string(),
                );
            }
        }

        recommendations
    }

    pub fn calculate_improvement_potential(score: &PrivacyScore) -> f64 {
        // Calculate max possible score if all fixes applied
        // This is a simplified estimation
        let current = score.overall_score;
        let potential = 100.0;

        (potential - current).max(0.0)
    }
}

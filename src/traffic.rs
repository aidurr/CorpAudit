use crate::audit::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficReport {
    pub timestamp: String,
    pub scan_duration_seconds: u64,
    pub processes: Vec<ProcessTraffic>,
    pub summary: TrafficSummary,
    pub top_domains: Vec<DomainTraffic>,
    pub protocol_breakdown: ProtocolBreakdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTraffic {
    pub process_name: String,
    pub pid: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub total_bytes: u64,
    pub connections: usize,
    pub domains: Vec<String>,
    pub traffic_type: TrafficType,
    pub is_suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrafficType {
    Normal,
    Telemetry,
    Updates,
    Streaming,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainTraffic {
    pub domain: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub total_bytes: u64,
    pub process_count: usize,
    pub processes: Vec<String>,
    pub category: DomainCategory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DomainCategory {
    Telemetry,
    Advertising,
    Content,
    Updates,
    CDN,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficSummary {
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub total_bytes: u64,
    pub unique_domains: usize,
    pub suspicious_domains: usize,
    pub telemetry_bytes: u64,
    pub normal_bytes: u64,
    pub telemetry_percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolBreakdown {
    pub tcp_bytes: u64,
    pub udp_bytes: u64,
    pub other_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct TrafficTimeline {
    pub process_name: String,
    pub data_points: Vec<TrafficDataPoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct TrafficDataPoint {
    pub timestamp: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

pub struct TrafficAnalyzer;

impl TrafficAnalyzer {
    pub fn analyze_traffic(
        telemetry_report: &Option<TelemetryReport>,
        _bloat_report: &Option<BloatReport>,
    ) -> TrafficReport {
        let mut processes = Vec::new();
        let mut domain_map: HashMap<String, DomainTraffic> = HashMap::new();
        let mut summary = TrafficSummary {
            total_bytes_sent: 0,
            total_bytes_received: 0,
            total_bytes: 0,
            unique_domains: 0,
            suspicious_domains: 0,
            telemetry_bytes: 0,
            normal_bytes: 0,
            telemetry_percentage: 0.0,
        };

        // Analyze telemetry connections
        if let Some(report) = telemetry_report {
            for finding in &report.findings {
                let bytes_sent = finding.data_sent.unwrap_or(0);
                let bytes_received = finding.data_received.unwrap_or(0);
                let total = bytes_sent + bytes_received;

                let traffic_type = Self::classify_traffic(&finding.process_name, &finding.domains);
                let is_suspicious = Self::is_suspicious_traffic(&finding.domains);

                // Update summary
                summary.total_bytes_sent += bytes_sent;
                summary.total_bytes_received += bytes_received;
                summary.total_bytes += total;

                if traffic_type == TrafficType::Telemetry {
                    summary.telemetry_bytes += total;
                } else {
                    summary.normal_bytes += total;
                }

                let process_traffic = ProcessTraffic {
                    process_name: finding.process_name.clone(),
                    pid: finding.pid,
                    bytes_sent,
                    bytes_received,
                    total_bytes: total,
                    connections: finding.connections.len(),
                    domains: finding.domains.clone(),
                    traffic_type,
                    is_suspicious,
                };

                processes.push(process_traffic);

                // Update domain map
                let domains_count = finding.domains.len().max(1);
                for domain in &finding.domains {
                    let entry = domain_map
                        .entry(domain.clone())
                        .or_insert_with(|| DomainTraffic {
                            domain: domain.clone(),
                            bytes_sent: 0,
                            bytes_received: 0,
                            total_bytes: 0,
                            process_count: 0,
                            processes: Vec::new(),
                            category: Self::classify_domain(domain),
                        });

                    entry.bytes_sent += bytes_sent / domains_count as u64;
                    entry.bytes_received += bytes_received / domains_count as u64;
                    entry.total_bytes += total / domains_count as u64;

                    if !entry.processes.contains(&finding.process_name) {
                        entry.processes.push(finding.process_name.clone());
                        entry.process_count += 1;
                    }
                }
            }
        }

        // Calculate percentages
        if summary.total_bytes > 0 {
            summary.telemetry_percentage =
                (summary.telemetry_bytes as f64 / summary.total_bytes as f64) * 100.0;
        }

        // Count unique and suspicious domains
        let all_domains: HashSet<_> = processes
            .iter()
            .flat_map(|p| p.domains.iter().cloned())
            .collect();
        summary.unique_domains = all_domains.len();
        summary.suspicious_domains = all_domains
            .iter()
            .filter(|d| Self::is_suspicious_domain(d))
            .count();

        // Get top domains
        let mut top_domains: Vec<_> = domain_map.into_values().collect();
        top_domains.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes));
        top_domains.truncate(20);

        // Protocol breakdown
        let protocol_breakdown = Self::analyze_protocols(telemetry_report);

        TrafficReport {
            timestamp: chrono::Utc::now().to_rfc3339(),
            scan_duration_seconds: 0,
            processes,
            summary,
            top_domains,
            protocol_breakdown,
        }
    }

    fn classify_traffic(process_name: &str, domains: &[String]) -> TrafficType {
        let known_telemetry = domains.iter().any(|d| {
            let d = d.to_lowercase();
            d.contains("telemetry")
                || d.contains("analytics")
                || d.contains("tracking")
                || d.contains("metrics")
        });

        let telemetry_apps = [
            "chrome", "firefox", "edge", "brave", "vscode", "idea", "pycharm", "slack", "discord",
            "teams", "spotify", "steam",
        ];

        if known_telemetry {
            TrafficType::Telemetry
        } else if telemetry_apps
            .iter()
            .any(|app| process_name.to_lowercase().contains(app))
        {
            TrafficType::Telemetry
        } else {
            TrafficType::Normal
        }
    }

    fn is_suspicious_traffic(domains: &[String]) -> bool {
        let suspicious_indicators = [
            "telemetry",
            "analytics",
            "tracking",
            "stats",
            "metrics",
            "doubleclick",
            "scorecardresearch",
        ];

        domains.iter().any(|domain| {
            suspicious_indicators
                .iter()
                .any(|indicator| domain.to_lowercase().contains(indicator))
        })
    }

    fn classify_domain(domain: &str) -> DomainCategory {
        let d = domain.to_lowercase();

        if d.contains("telemetry") || d.contains("analytics") || d.contains("tracking") {
            DomainCategory::Telemetry
        } else if d.contains("doubleclick") || d.contains("ads") || d.contains("advertising") {
            DomainCategory::Advertising
        } else if d.contains("cdn") || d.contains("cloudfront") || d.contains("akamai") {
            DomainCategory::CDN
        } else if d.contains("update") || d.contains("download") {
            DomainCategory::Updates
        } else {
            DomainCategory::Unknown
        }
    }

    fn is_suspicious_domain(domain: &str) -> bool {
        let suspicious_domains = [
            "telemetry",
            "analytics",
            "tracking",
            "doubleclick",
            "scorecardresearch",
            "facebook.com/tr",
        ];

        suspicious_domains
            .iter()
            .any(|s| domain.to_lowercase().contains(s))
    }

    fn analyze_protocols(telemetry_report: &Option<TelemetryReport>) -> ProtocolBreakdown {
        let mut tcp_bytes = 0u64;
        let mut udp_bytes = 0u64;
        let mut other_bytes = 0u64;

        if let Some(report) = telemetry_report {
            for finding in &report.findings {
                for conn in &finding.connections {
                    let data = finding.data_sent.unwrap_or(0) + finding.data_received.unwrap_or(0);

                    match conn.protocol.to_uppercase().as_str() {
                        "TCP" => tcp_bytes += data,
                        "UDP" => udp_bytes += data,
                        _ => other_bytes += data,
                    }
                }
            }
        }

        ProtocolBreakdown {
            tcp_bytes,
            udp_bytes,
            other_bytes,
        }
    }
}

use crate::comparison::ReportComparison;
use crate::scorer::PrivacyScore;
use crate::traffic::*;

pub struct TrafficVisualizer;

impl TrafficVisualizer {
    pub fn render_traffic_report(report: &TrafficReport) -> String {
        let mut output = String::new();

        // Overall traffic summary bar
        output.push_str(&Self::render_summary_chart(&report.summary));
        output.push_str("\n");

        // Top processes by traffic
        output.push_str(&Self::render_process_chart(&report.processes));
        output.push_str("\n");

        // Domain breakdown
        output.push_str(&Self::render_domain_chart(&report.top_domains));
        output.push_str("\n");

        // Protocol breakdown
        output.push_str(&Self::render_protocol_chart(&report.protocol_breakdown));

        output
    }

    pub fn render_score_display(score: &PrivacyScore) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "Privacy Score: {}/100 [{}]\n",
            score.overall_score as usize,
            score.grade.as_str()
        ));
        output.push_str(&"═".repeat(50));
        output.push_str("\n\n");

        output.push_str("Score Breakdown:\n");
        output.push_str(&Self::render_score_bar(
            "Telemetry",
            score.telemetry_subscore,
        ));
        output.push_str(&Self::render_score_bar("Bloat", score.bloat_subscore));
        output.push_str(&Self::render_score_bar(
            "Permissions",
            score.permissions_subscore,
        ));
        output.push_str(&Self::render_score_bar("Network", score.network_subscore));
        output.push_str(&Self::render_score_bar(
            "Data Exposure",
            score.data_exposure_subscore,
        ));

        output
    }

    pub fn render_comparison_summary(comparison: &ReportComparison) -> String {
        let mut output = String::new();

        output.push_str("Comparison Report\n");
        output.push_str("═════════════════\n\n");

        output.push_str(&format!("Baseline: {}\n", comparison.baseline_timestamp));
        output.push_str(&format!("Current:  {}\n\n", comparison.current_timestamp));

        let summary = &comparison.summary;
        output.push_str(&format!(
            "Summary: {} changes detected\n",
            summary.total_changes
        ));
        output.push_str(&format!(
            "  Critical: {} | Significant: {} | Minor: {}\n",
            summary.critical_changes, summary.significant_changes, summary.minor_changes
        ));

        match &summary.overall_trend {
            crate::comparison::ChangeTrend::Improved { points } => {
                output.push_str(&format!(
                    "  Overall Trend: ↑ Improved (+{:.0} points)\n\n",
                    points
                ));
            }
            crate::comparison::ChangeTrend::Degraded { points } => {
                output.push_str(&format!(
                    "  Overall Trend: ↓ Degraded (-{:.0} points)\n\n",
                    points
                ));
            }
            crate::comparison::ChangeTrend::Stable => {
                output.push_str("  Overall Trend: → Stable\n\n");
            }
        }

        if !summary.key_highlights.is_empty() {
            output.push_str("Key Highlights:\n");
            for highlight in &summary.key_highlights {
                output.push_str(&format!("  {}\n", highlight));
            }
            output.push_str("\n");
        }

        // Telemetry changes
        output.push_str("Telemetry Changes\n");
        output.push_str("─────────────────\n");

        if !comparison.telemetry_changes.new_findings.is_empty() {
            output.push_str(&format!(
                "\nNew Findings ({}):\n",
                comparison.telemetry_changes.new_findings.len()
            ));
            for finding in &comparison.telemetry_changes.new_findings {
                output.push_str(&format!(
                    "  [{}] ✗ {} (PID: {})\n",
                    format!("{:?}", finding.severity).to_uppercase(),
                    finding.process_name,
                    finding.pid
                ));
                if !finding.domains.is_empty() {
                    output.push_str(&format!(
                        "    - {} telemetry domains detected\n",
                        finding.domains.len()
                    ));
                }
            }
        }

        if !comparison.telemetry_changes.removed_findings.is_empty() {
            output.push_str(&format!(
                "\nRemoved Findings ({}):\n",
                comparison.telemetry_changes.removed_findings.len()
            ));
            for finding in &comparison.telemetry_changes.removed_findings {
                output.push_str(&format!(
                    "  [{}] ✓ {} (PID: {})\n",
                    format!("{:?}", finding.severity).to_uppercase(),
                    finding.process_name,
                    finding.pid
                ));
                output.push_str("    - No longer making telemetry connections\n");
            }
        }

        if !comparison.telemetry_changes.changed_findings.is_empty() {
            output.push_str(&format!(
                "\nChanged Findings ({}):\n",
                comparison.telemetry_changes.changed_findings.len()
            ));
            for change in &comparison.telemetry_changes.changed_findings {
                for field_change in &change.changes {
                    output.push_str(&format!(
                        "  [{}→{}] ✗ {}\n",
                        field_change.old_value, field_change.new_value, change.process_name
                    ));
                    output.push_str(&format!(
                        "    - {}: {} → {}\n",
                        field_change.field, field_change.old_value, field_change.new_value
                    ));
                }
            }
        }

        output
    }

    fn render_summary_chart(summary: &TrafficSummary) -> String {
        let mut output = String::new();

        output.push_str("Traffic Summary\n");
        output.push_str("═══════════════\n\n");

        // Total traffic
        output.push_str(&format!(
            "Total Traffic: {}\n",
            Self::format_bytes(summary.total_bytes)
        ));

        // Telemetry vs Normal bar
        let bar_width = 50;
        let telemetry_width = if summary.telemetry_percentage > 100.0 {
            bar_width
        } else {
            (summary.telemetry_percentage / 100.0 * bar_width as f64) as usize
        };
        let normal_width = bar_width.saturating_sub(telemetry_width);

        output.push_str(&format!(
            "Telemetry: [{}{}] {:.1}%\n",
            "█".repeat(telemetry_width),
            "░".repeat(normal_width),
            summary.telemetry_percentage
        ));

        // Bytes breakdown
        output.push_str(&format!(
            "  Sent: {} | Received: {}\n",
            Self::format_bytes(summary.total_bytes_sent),
            Self::format_bytes(summary.total_bytes_received)
        ));

        output.push_str(&format!(
            "  Unique Domains: {} | Suspicious: {}\n",
            summary.unique_domains, summary.suspicious_domains
        ));

        output
    }

    fn render_process_chart(processes: &[ProcessTraffic]) -> String {
        let mut output = String::new();

        output.push_str("Top Processes by Traffic\n");
        output.push_str("═══════════════════════\n\n");

        // Sort by total bytes
        let mut sorted = processes.to_vec();
        sorted.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes));
        sorted.truncate(15);

        if sorted.is_empty() {
            output.push_str("No traffic detected\n");
            return output;
        }

        let max_bytes = sorted[0].total_bytes;
        let bar_width = 40;

        for process in &sorted {
            let bar_length = if max_bytes > 0 {
                (process.total_bytes as f64 / max_bytes as f64 * bar_width as f64) as usize
            } else {
                0
            };

            let indicator = if process.is_suspicious { "⚠ " } else { "  " };

            output.push_str(&format!(
                "{}{} {} {}\n",
                indicator,
                process.process_name,
                Self::format_bytes(process.total_bytes),
                "█".repeat(bar_length.max(1))
            ));

            // Show domains if suspicious
            if process.is_suspicious && !process.domains.is_empty() {
                let domains_str = process
                    .domains
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ");
                output.push_str(&format!("    Domains: {}\n", domains_str));
            }
        }

        output
    }

    fn render_domain_chart(domains: &[DomainTraffic]) -> String {
        let mut output = String::new();

        output.push_str("Top Domains by Traffic\n");
        output.push_str("═════════════════════\n\n");

        if domains.is_empty() {
            output.push_str("No domains detected\n");
            return output;
        }

        let max_bytes = domains[0].total_bytes;
        let bar_width = 35;

        for domain in domains.iter().take(15) {
            let bar_length = if max_bytes > 0 {
                (domain.total_bytes as f64 / max_bytes as f64 * bar_width as f64) as usize
            } else {
                0
            };

            let category_indicator = match domain.category {
                DomainCategory::Telemetry => "[TELEMETRY] ",
                DomainCategory::Advertising => "[AD] ",
                DomainCategory::CDN => "[CDN] ",
                _ => "",
            };

            output.push_str(&format!(
                "{}{} {}\n",
                category_indicator,
                domain.domain,
                Self::format_bytes(domain.total_bytes)
            ));
            output.push_str(&format!(
                "  {} {}\n",
                "█".repeat(bar_length.max(1)),
                format!("({} processes)", domain.process_count)
            ));
        }

        output
    }

    fn render_protocol_chart(breakdown: &ProtocolBreakdown) -> String {
        let mut output = String::new();

        output.push_str("Protocol Breakdown\n");
        output.push_str("══════════════════\n\n");

        let total = breakdown.tcp_bytes + breakdown.udp_bytes + breakdown.other_bytes;
        if total == 0 {
            output.push_str("No protocol data available\n");
            return output;
        }

        let bar_width = 40;

        // TCP
        let tcp_percent = breakdown.tcp_bytes as f64 / total as f64;
        let tcp_width = (tcp_percent * bar_width as f64) as usize;
        output.push_str(&format!(
            "TCP: [{}] {} ({:.1}%)\n",
            "█".repeat(tcp_width.max(1)),
            Self::format_bytes(breakdown.tcp_bytes),
            tcp_percent * 100.0
        ));

        // UDP
        let udp_percent = breakdown.udp_bytes as f64 / total as f64;
        let udp_width = (udp_percent * bar_width as f64) as usize;
        output.push_str(&format!(
            "UDP: [{}] {} ({:.1}%)\n",
            "█".repeat(udp_width.max(1)),
            Self::format_bytes(breakdown.udp_bytes),
            udp_percent * 100.0
        ));

        // Other
        if breakdown.other_bytes > 0 {
            let other_percent = breakdown.other_bytes as f64 / total as f64;
            let other_width = (other_percent * bar_width as f64) as usize;
            output.push_str(&format!(
                "Other: [{}] {} ({:.1}%)\n",
                "█".repeat(other_width.max(1)),
                Self::format_bytes(breakdown.other_bytes),
                other_percent * 100.0
            ));
        }

        output
    }

    fn render_score_bar(label: &str, score: f64) -> String {
        let bar_width = 30;
        let filled = (score / 100.0 * bar_width as f64) as usize;
        let empty = bar_width - filled;

        let (filled_char, empty_char) = if score >= 70.0 {
            ("█", "░")
        } else if score >= 50.0 {
            ("▓", "░")
        } else {
            ("▒", "░")
        };

        format!(
            "  {:<15} [{}{}] {}/100\n",
            label,
            filled_char.repeat(filled),
            empty_char.repeat(empty),
            score as usize
        )
    }

    pub fn render_sparkline(values: &[u64]) -> String {
        if values.is_empty() {
            return "No data".to_string();
        }

        let max = *values.iter().max().unwrap_or(&1);
        let min = *values.iter().min().unwrap_or(&0);

        if max == min {
            return "▁".repeat(values.len());
        }

        let spark_chars = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
        let range = (max - min) as f64;

        values
            .iter()
            .map(|v| {
                let idx =
                    (((*v as f64 - min as f64) / range) * (spark_chars.len() - 1) as f64) as usize;
                spark_chars[idx.min(spark_chars.len() - 1)]
            })
            .collect()
    }

    pub fn render_history_table(histories: &[crate::history::ScanHistory]) -> String {
        let mut output = String::new();

        output.push_str("Scan History\n");
        output.push_str("════════════\n\n");

        if histories.is_empty() {
            output.push_str("No scan history available\n");
            return output;
        }

        // Header
        output.push_str(&format!(
            "{:<20} {:<10} {:<10} {:<12} {:<10}\n",
            "Timestamp", "Telemetry", "Bloat", "Permissions", "Score"
        ));
        output.push_str(&"-".repeat(65));
        output.push_str("\n");

        // Data
        for history in histories.iter().take(10) {
            let total_findings =
                history.telemetry_count + history.bloat_count + history.permissions_count;

            let grade = if total_findings == 0 {
                "A+"
            } else if total_findings < 3 {
                "B"
            } else if total_findings < 10 {
                "C"
            } else {
                "D"
            };

            output.push_str(&format!(
                "{:<20} {:<10} {:<10} {:<12} {:<10}\n",
                &history.timestamp[..19],
                history.telemetry_count,
                history.bloat_count,
                history.permissions_count,
                grade
            ));
        }

        output
    }

    pub fn render_trend_analysis(analysis: &crate::history::TrendAnalysis) -> String {
        let mut output = String::new();

        output.push_str("Trend Analysis\n");
        output.push_str("══════════════\n\n");

        output.push_str(&format!("Period: {} days\n", analysis.period_days));
        output.push_str(&format!("Scans analyzed: {}\n\n", analysis.scan_count));

        if analysis.scan_count == 0 {
            output.push_str("Insufficient data for trend analysis.\n");
            output.push_str("Run multiple scans to generate trend data.\n");
            return output;
        }

        // Telemetry trend
        output.push_str("Telemetry Trend: ");
        match &analysis.telemetry_trend {
            crate::history::TrendDirection::Increasing { percentage } => {
                output.push_str(&format!("↑ Increasing by {:.1}%\n", percentage));
            }
            crate::history::TrendDirection::Decreasing { percentage } => {
                output.push_str(&format!("↓ Decreasing by {:.1}%\n", percentage));
            }
            crate::history::TrendDirection::Stable { .. } => {
                output.push_str("→ Stable\n");
            }
        }

        // Bloat trend
        output.push_str("Bloat Trend: ");
        match &analysis.bloat_trend {
            crate::history::TrendDirection::Increasing { percentage } => {
                output.push_str(&format!("↑ Increasing by {:.1}%\n", percentage));
            }
            crate::history::TrendDirection::Decreasing { percentage } => {
                output.push_str(&format!("↓ Decreasing by {:.1}%\n", percentage));
            }
            crate::history::TrendDirection::Stable { .. } => {
                output.push_str("→ Stable\n");
            }
        }

        // Privacy trend
        output.push_str("Privacy Trend: ");
        match &analysis.privacy_trend {
            crate::history::TrendDirection::Increasing { percentage } => {
                output.push_str(&format!("↑ Improving by {:.1}%\n", percentage));
            }
            crate::history::TrendDirection::Decreasing { percentage } => {
                output.push_str(&format!("↓ Degrading by {:.1}%\n", percentage));
            }
            crate::history::TrendDirection::Stable { .. } => {
                output.push_str("→ Stable\n");
            }
        }

        output.push_str("\n");

        // Changes
        if !analysis.changes.is_empty() {
            output.push_str("Recent Changes:\n");
            for change in &analysis.changes {
                let ts_short: String = change.timestamp.chars().take(10).collect();
                output.push_str(&format!("  [{}] {}\n", ts_short, change.description));
            }
            output.push_str("\n");
        }

        // Recommendations
        if !analysis.recommendations.is_empty() {
            output.push_str("Recommendations:\n");
            for rec in &analysis.recommendations {
                output.push_str(&format!("  • {}\n", rec));
            }
        }

        output
    }

    fn format_bytes(bytes: u64) -> String {
        if bytes >= 1_073_741_824 {
            format!("{:.2} GB", bytes as f64 / 1_073_741_824.0)
        } else if bytes >= 1_048_576 {
            format!("{:.2} MB", bytes as f64 / 1_048_576.0)
        } else if bytes >= 1_024 {
            format!("{:.2} KB", bytes as f64 / 1_024.0)
        } else {
            format!("{} B", bytes)
        }
    }

    pub fn render_timeline(data: &[(String, usize, usize, usize)]) -> String {
        let mut output = String::new();

        output.push_str("Resource Usage Timeline\n");
        output.push_str("═══════════════════════\n\n");

        if data.is_empty() {
            output.push_str("No timeline data available.\n");
            return output;
        }

        let max_findings = data.iter().map(|(_, t, b, p)| t + b + p).max().unwrap_or(1);
        let bar_width = 40;

        for (timestamp, telemetry, bloat, permissions) in data.iter().take(20) {
            let total = telemetry + bloat + permissions;
            let bar_len = if max_findings > 0 {
                (total as f64 / max_findings as f64 * bar_width as f64) as usize
            } else {
                0
            };

            let date_short = if timestamp.len() >= 10 {
                &timestamp[..10]
            } else {
                timestamp
            };

            output.push_str(&format!(
                "{} T:{} B:{} P:{} {}\n",
                date_short,
                telemetry,
                bloat,
                permissions,
                "█".repeat(bar_len.max(1))
            ));
        }

        output.push_str(&format!("\nTotal scans: {}\n", data.len()));
        output.push_str("T=Telemetry, B=Bloat, P=Permissions\n");

        output
    }
}

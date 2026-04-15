use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub timestamp: String,
    pub hostname: String,
    pub telemetry: Option<TelemetryReport>,
    pub bloat: Option<BloatReport>,
    pub permissions: Option<PermissionsReport>,
    pub startup: Option<StartupReport>,
    pub fixes: Option<Vec<Fix>>,
}

impl AuditReport {
    pub fn new() -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            hostname: gethostname::gethostname().to_string_lossy().to_string(),
            telemetry: None,
            bloat: None,
            permissions: None,
            startup: None,
            fixes: None,
        }
    }

    pub fn has_critical_issues(&self) -> bool {
        self.telemetry.as_ref().map_or(false, |t| t.has_critical())
            || self.bloat.as_ref().map_or(false, |b| b.has_critical())
            || self
                .permissions
                .as_ref()
                .map_or(false, |p| p.has_critical())
    }

    pub fn has_issues(&self) -> bool {
        self.telemetry
            .as_ref()
            .map_or(false, |t| !t.findings.is_empty())
            || self
                .bloat
                .as_ref()
                .map_or(false, |b| !b.findings.is_empty())
            || self
                .permissions
                .as_ref()
                .map_or(false, |p| !p.findings.is_empty())
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!("CorpAudit Report\n"));
        output.push_str(&format!("===============\n"));
        output.push_str(&format!("Timestamp: {}\n", self.timestamp));
        output.push_str(&format!("Hostname: {}\n\n", self.hostname));

        if let Some(ref telemetry) = self.telemetry {
            output.push_str(&telemetry.to_text());
        }

        if let Some(ref bloat) = self.bloat {
            output.push_str(&bloat.to_text());
        }

        if let Some(ref permissions) = self.permissions {
            output.push_str(&permissions.to_text());
        }

        if let Some(ref startup) = self.startup {
            output.push_str(&startup.to_text());
        }

        if let Some(ref fixes) = self.fixes {
            output.push_str("\nRecommended Fixes\n");
            output.push_str(&format!("================\n"));
            for fix in fixes {
                output.push_str(&fix.to_text());
            }
        }

        output
    }

    pub fn to_markdown(&self) -> String {
        let mut output = String::new();

        output.push_str("# CorpAudit Report\n\n");
        output.push_str(&format!("**Timestamp:** {}\n", self.timestamp));
        output.push_str(&format!("**Hostname:** {}\n\n", self.hostname));

        if let Some(ref telemetry) = self.telemetry {
            output.push_str(&telemetry.to_markdown());
        }

        if let Some(ref bloat) = self.bloat {
            output.push_str(&bloat.to_markdown());
        }

        if let Some(ref permissions) = self.permissions {
            output.push_str(&permissions.to_markdown());
        }

        if let Some(ref startup) = self.startup {
            output.push_str(&startup.to_markdown());
        }

        if let Some(ref fixes) = self.fixes {
            output.push_str("## Recommended Fixes\n\n");
            for fix in fixes {
                output.push_str(&fix.to_markdown());
            }
        }

        output
    }

    pub fn to_html(&self) -> String {
        let mut output = String::new();

        output.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
        output.push_str("<meta charset=\"UTF-8\">\n");
        output.push_str(
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n",
        );
        output.push_str("<title>CorpAudit Report</title>\n");
        output.push_str("<style>\n");
        output.push_str("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 2rem; background: #f5f5f5; color: #333; }\n");
        output.push_str(".container { max-width: 900px; margin: 0 auto; background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n");
        output.push_str(
            "h1 { color: #2563eb; border-bottom: 2px solid #2563eb; padding-bottom: 0.5rem; }\n",
        );
        output.push_str("h2 { color: #1e40af; margin-top: 2rem; }\n");
        output.push_str("h3 { color: #374151; }\n");
        output.push_str(".meta { color: #6b7280; margin-bottom: 1rem; }\n");
        output.push_str(".critical { color: #dc2626; font-weight: bold; }\n");
        output.push_str(".high { color: #ea580c; }\n");
        output.push_str(".medium { color: #ca8a04; }\n");
        output.push_str(".low { color: #16a34a; }\n");
        output.push_str(".finding { background: #f9fafb; padding: 1rem; margin: 0.5rem 0; border-left: 4px solid #2563eb; border-radius: 4px; }\n");
        output.push_str("table { width: 100%; border-collapse: collapse; margin: 1rem 0; }\n");
        output.push_str(
            "th, td { padding: 0.5rem; text-align: left; border-bottom: 1px solid #e5e7eb; }\n",
        );
        output.push_str("th { background: #f3f4f6; }\n");
        output.push_str(".badge { display: inline-block; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.875rem; font-weight: 500; }\n");
        output.push_str("</style>\n</head>\n<body>\n");
        output.push_str("<div class=\"container\">\n");

        output.push_str(&format!("<h1>CorpAudit Report</h1>\n"));
        output.push_str(&format!(
            "<div class=\"meta\"><strong>Timestamp:</strong> {}</div>\n",
            self.timestamp
        ));
        output.push_str(&format!(
            "<div class=\"meta\"><strong>Hostname:</strong> {}</div>\n",
            self.hostname
        ));

        if let Some(ref telemetry) = self.telemetry {
            output.push_str("<h2>Telemetry & Data Collection</h2>\n");
            output.push_str(&format!(
                "<p>Total findings: <span class=\"badge critical\">{}</span></p>\n",
                telemetry.findings.len()
            ));
            for finding in &telemetry.findings {
                output.push_str("<div class=\"finding\">\n");
                output.push_str(&format!("<h3>{}</h3>\n", finding.process_name));
                output.push_str(&format!(
                    "<p><span class=\"badge {}\">{:?}</span></p>\n",
                    match finding.severity {
                        Severity::Critical => "critical",
                        Severity::High => "high",
                        Severity::Medium => "medium",
                        Severity::Low => "low",
                    },
                    finding.severity
                ));
                output.push_str(&format!("<p>{}</p>\n", finding.description));
                if !finding.domains.is_empty() {
                    output.push_str(&format!(
                        "<p><strong>Domains:</strong> {}</p>\n",
                        finding.domains.join(", ")
                    ));
                }
                output.push_str(&format!("<p><em>{}</em></p>\n", finding.recommendation));
                output.push_str("</div>\n");
            }
        }

        if let Some(ref bloat) = self.bloat {
            output.push_str("<h2>Application Bloat</h2>\n");
            output.push_str(&format!(
                "<p>Total findings: <span class=\"badge high\">{}</span></p>\n",
                bloat.findings.len()
            ));
            for finding in &bloat.findings {
                output.push_str("<div class=\"finding\">\n");
                output.push_str(&format!("<h3>{}</h3>\n", finding.process_name));
                output.push_str(&format!(
                    "<p><span class=\"badge {}\">{:?}</span></p>\n",
                    match finding.severity {
                        Severity::Critical => "critical",
                        Severity::High => "high",
                        Severity::Medium => "medium",
                        Severity::Low => "low",
                    },
                    finding.severity
                ));
                output.push_str(&format!(
                    "<p>Memory: {:.2} MB | CPU: {:.2}%</p>\n",
                    finding.memory_mb, finding.cpu_percent
                ));
                output.push_str(&format!("<p>{}</p>\n", finding.description));
                if let Some(ref alt) = finding.alternative {
                    output.push_str(&format!("<p><strong>Alternative:</strong> {}</p>\n", alt));
                }
                output.push_str("</div>\n");
            }
        }

        if let Some(ref permissions) = self.permissions {
            output.push_str("<h2>Application Permissions</h2>\n");
            output.push_str(&format!(
                "<p>Total findings: <span class=\"badge medium\">{}</span></p>\n",
                permissions.findings.len()
            ));
            for finding in &permissions.findings {
                output.push_str("<div class=\"finding\">\n");
                output.push_str(&format!("<h3>{}</h3>\n", finding.process_name));
                output.push_str(&format!(
                    "<p><span class=\"badge {}\">{:?}</span></p>\n",
                    match finding.severity {
                        Severity::Critical => "critical",
                        Severity::High => "high",
                        Severity::Medium => "medium",
                        Severity::Low => "low",
                    },
                    finding.severity
                ));
                output.push_str(&format!("<p>{}</p>\n", finding.description));
                output.push_str("</div>\n");
            }
        }

        if let Some(ref startup) = self.startup {
            output.push_str("<h2>Startup Services</h2>\n");
            output.push_str(&format!(
                "<p>Total findings: <span class=\"badge low\">{}</span></p>\n",
                startup.findings.len()
            ));
            for finding in &startup.findings {
                output.push_str("<div class=\"finding\">\n");
                output.push_str(&format!("<h3>{}</h3>\n", finding.name));
                output.push_str(&format!(
                    "<p><span class=\"badge {}\">{:?}</span></p>\n",
                    match finding.severity {
                        Severity::Critical => "critical",
                        Severity::High => "high",
                        Severity::Medium => "medium",
                        Severity::Low => "low",
                    },
                    finding.severity
                ));
                output.push_str(&format!("<p><strong>Path:</strong> {}</p>\n", finding.path));
                output.push_str(&format!("<p>{}</p>\n", finding.description));
                output.push_str("</div>\n");
            }
        }

        output.push_str("</div>\n</body>\n</html>");

        output
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryReport {
    pub findings: Vec<TelemetryFinding>,
    pub summary: TelemetrySummary,
}

impl TelemetryReport {
    pub fn has_critical(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == Severity::Critical)
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();

        output.push_str("Telemetry & Data Collection\n");
        output.push_str("===========================\n");
        output.push_str(&format!("Total findings: {}\n", self.findings.len()));
        output.push_str(&format!(
            "Critical: {}, High: {}, Medium: {}, Low: {}\n\n",
            self.summary.critical, self.summary.high, self.summary.medium, self.summary.low
        ));

        for finding in &self.findings {
            output.push_str(&finding.to_text());
        }

        output.push_str("\n");
        output
    }

    pub fn to_markdown(&self) -> String {
        let mut output = String::new();

        output.push_str("## Telemetry & Data Collection\n\n");
        output.push_str(&format!("- **Total findings:** {}\n", self.findings.len()));
        output.push_str(&format!(
            "- **Critical:** {}, **High:** {}, **Medium:** {}, **Low:** {}\n\n",
            self.summary.critical, self.summary.high, self.summary.medium, self.summary.low
        ));

        for finding in &self.findings {
            output.push_str(&finding.to_markdown());
        }

        output.push_str("\n");
        output
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryFinding {
    pub process_name: String,
    pub pid: u32,
    pub connections: Vec<NetworkConnection>,
    pub data_sent: Option<u64>,
    pub data_received: Option<u64>,
    pub domains: Vec<String>,
    pub severity: Severity,
    pub description: String,
    pub recommendation: String,
}

impl TelemetryFinding {
    pub fn to_text(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "Process: {} (PID: {})\n",
            self.process_name, self.pid
        ));
        output.push_str(&format!("Severity: {:?}\n", self.severity));
        output.push_str(&format!("Description: {}\n", self.description));
        output.push_str(&format!("Connections: {}\n", self.connections.len()));

        for conn in &self.connections {
            output.push_str(&format!(
                "  - {}:{} -> {}:{} ({})\n",
                conn.local_address,
                conn.local_port,
                conn.remote_address,
                conn.remote_port,
                conn.protocol
            ));
        }

        if !self.domains.is_empty() {
            output.push_str(&format!("Domains contacted: {}\n", self.domains.join(", ")));
        }

        output.push_str(&format!("Recommendation: {}\n\n", self.recommendation));

        output
    }

    pub fn to_markdown(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "### {} (PID: {})\n\n",
            self.process_name, self.pid
        ));
        output.push_str(&format!("- **Severity:** {:?}\n", self.severity));
        output.push_str(&format!("- **Description:** {}\n", self.description));
        output.push_str(&format!("- **Connections:** {}\n", self.connections.len()));

        for conn in &self.connections {
            output.push_str(&format!(
                "  - `{}:{} -> {}:{} ({})`\n",
                conn.local_address,
                conn.local_port,
                conn.remote_address,
                conn.remote_port,
                conn.protocol
            ));
        }

        if !self.domains.is_empty() {
            output.push_str(&format!("- **Domains:** {}\n", self.domains.join(", ")));
        }

        output.push_str(&format!(
            "- **Recommendation:** {}\n\n",
            self.recommendation
        ));

        output
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloatReport {
    pub findings: Vec<BloatFinding>,
    pub summary: BloatSummary,
}

impl BloatReport {
    pub fn has_critical(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == Severity::Critical)
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();

        output.push_str("Application Bloat\n");
        output.push_str("=================\n");
        output.push_str(&format!("Total findings: {}\n", self.findings.len()));
        output.push_str(&format!(
            "Critical: {}, High: {}, Medium: {}, Low: {}\n\n",
            self.summary.critical, self.summary.high, self.summary.medium, self.summary.low
        ));

        for finding in &self.findings {
            output.push_str(&finding.to_text());
        }

        output.push_str("\n");
        output
    }

    pub fn to_markdown(&self) -> String {
        let mut output = String::new();

        output.push_str("## Application Bloat\n\n");
        output.push_str(&format!("- **Total findings:** {}\n", self.findings.len()));
        output.push_str(&format!(
            "- **Critical:** {}, **High:** {}, **Medium:** {}, **Low:** {}\n\n",
            self.summary.critical, self.summary.high, self.summary.medium, self.summary.low
        ));

        for finding in &self.findings {
            output.push_str(&finding.to_markdown());
        }

        output.push_str("\n");
        output
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloatFinding {
    pub process_name: String,
    pub pid: u32,
    pub memory_mb: f64,
    pub cpu_percent: f64,
    pub startup_time_ms: u64,
    pub dependencies: Vec<String>,
    pub severity: Severity,
    pub description: String,
    pub recommendation: String,
    pub alternative: Option<String>,
}

impl BloatFinding {
    pub fn to_text(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "Process: {} (PID: {})\n",
            self.process_name, self.pid
        ));
        output.push_str(&format!("Severity: {:?}\n", self.severity));
        output.push_str(&format!("Memory: {:.2} MB\n", self.memory_mb));
        output.push_str(&format!("CPU: {:.2}%\n", self.cpu_percent));
        output.push_str(&format!("Startup time: {} ms\n", self.startup_time_ms));
        output.push_str(&format!("Dependencies: {}\n", self.dependencies.len()));
        output.push_str(&format!("Description: {}\n", self.description));
        output.push_str(&format!("Recommendation: {}\n", self.recommendation));

        if let Some(ref alt) = self.alternative {
            output.push_str(&format!("Alternative: {}\n", alt));
        }

        output.push_str("\n");

        output
    }

    pub fn to_markdown(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "### {} (PID: {})\n\n",
            self.process_name, self.pid
        ));
        output.push_str(&format!("- **Severity:** {:?}\n", self.severity));
        output.push_str(&format!("- **Memory:** {:.2} MB\n", self.memory_mb));
        output.push_str(&format!("- **CPU:** {:.2}%\n", self.cpu_percent));
        output.push_str(&format!(
            "- **Startup time:** {} ms\n",
            self.startup_time_ms
        ));
        output.push_str(&format!(
            "- **Dependencies:** {}\n",
            self.dependencies.len()
        ));
        output.push_str(&format!("- **Description:** {}\n", self.description));
        output.push_str(&format!("- **Recommendation:** {}\n", self.recommendation));

        if let Some(ref alt) = self.alternative {
            output.push_str(&format!("- **Alternative:** {}\n", alt));
        }

        output.push_str("\n");

        output
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloatSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionsReport {
    pub findings: Vec<PermissionsFinding>,
    pub summary: PermissionsSummary,
}

impl PermissionsReport {
    pub fn has_critical(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == Severity::Critical)
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();

        output.push_str("Application Permissions\n");
        output.push_str("=======================\n");
        output.push_str(&format!("Total findings: {}\n", self.findings.len()));
        output.push_str(&format!(
            "Critical: {}, High: {}, Medium: {}, Low: {}\n\n",
            self.summary.critical, self.summary.high, self.summary.medium, self.summary.low
        ));

        for finding in &self.findings {
            output.push_str(&finding.to_text());
        }

        output.push_str("\n");
        output
    }

    pub fn to_markdown(&self) -> String {
        let mut output = String::new();

        output.push_str("## Application Permissions\n\n");
        output.push_str(&format!("- **Total findings:** {}\n", self.findings.len()));
        output.push_str(&format!(
            "- **Critical:** {}, **High:** {}, **Medium:** {}, **Low:** {}\n\n",
            self.summary.critical, self.summary.high, self.summary.medium, self.summary.low
        ));

        for finding in &self.findings {
            output.push_str(&finding.to_markdown());
        }

        output.push_str("\n");
        output
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionsFinding {
    pub process_name: String,
    pub pid: u32,
    pub permissions: Vec<Permission>,
    pub severity: Severity,
    pub description: String,
    pub recommendation: String,
}

impl PermissionsFinding {
    pub fn to_text(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "Process: {} (PID: {})\n",
            self.process_name, self.pid
        ));
        output.push_str(&format!("Severity: {:?}\n", self.severity));
        output.push_str(&format!("Permissions: {}\n", self.permissions.len()));

        for perm in &self.permissions {
            output.push_str(&format!(
                "  - {}: {}\n",
                perm.permission_type, perm.description
            ));
        }

        output.push_str(&format!("Description: {}\n", self.description));
        output.push_str(&format!("Recommendation: {}\n\n", self.recommendation));

        output
    }

    pub fn to_markdown(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "### {} (PID: {})\n\n",
            self.process_name, self.pid
        ));
        output.push_str(&format!("- **Severity:** {:?}\n", self.severity));
        output.push_str(&format!("- **Permissions:** {}\n", self.permissions.len()));

        for perm in &self.permissions {
            output.push_str(&format!(
                "  - **{}:** {}\n",
                perm.permission_type, perm.description
            ));
        }

        output.push_str(&format!("- **Description:** {}\n", self.description));
        output.push_str(&format!(
            "- **Recommendation:** {}\n\n",
            self.recommendation
        ));

        output
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub permission_type: String,
    pub description: String,
    pub granted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionsSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub protocol: String,
    pub state: String,
    pub data_sent: Option<u64>,
    pub data_received: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fix {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub commands: Vec<String>,
    pub rollback_commands: Vec<String>,
    pub safe: bool,
}

impl Fix {
    pub fn to_text(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!("Fix: {}\n", self.title));
        output.push_str(&format!("Severity: {:?}\n", self.severity));
        output.push_str(&format!("Description: {}\n", self.description));
        output.push_str(&format!("Safe: {}\n", self.safe));
        output.push_str("Commands:\n");

        for cmd in &self.commands {
            output.push_str(&format!("  {}\n", cmd));
        }

        if !self.rollback_commands.is_empty() {
            output.push_str("Rollback:\n");
            for cmd in &self.rollback_commands {
                output.push_str(&format!("  {}\n", cmd));
            }
        }

        output.push_str("\n");

        output
    }

    pub fn to_markdown(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!("### {}\n\n", self.title));
        output.push_str(&format!("- **Severity:** {:?}\n", self.severity));
        output.push_str(&format!("- **Description:** {}\n", self.description));
        output.push_str(&format!("- **Safe:** {}\n", self.safe));
        output.push_str("**Commands:**\n");
        output.push_str("```bash\n");

        for cmd in &self.commands {
            output.push_str(&format!("{}\n", cmd));
        }

        output.push_str("```\n");

        if !self.rollback_commands.is_empty() {
            output.push_str("**Rollback:**\n");
            output.push_str("```bash\n");

            for cmd in &self.rollback_commands {
                output.push_str(&format!("{}\n", cmd));
            }

            output.push_str("```\n");
        }

        output.push_str("\n");

        output
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartupReport {
    pub findings: Vec<StartupFinding>,
    pub summary: StartupSummary,
}

impl StartupReport {
    #[allow(dead_code)]
    pub fn has_critical(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == Severity::Critical)
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();
        output.push_str("Startup Services\n");
        output.push_str("==================\n");
        output.push_str(&format!("Total findings: {}\n", self.findings.len()));
        output.push_str(&format!(
            "Critical: {}, High: {}, Medium: {}, Low: {}\n\n",
            self.summary.critical, self.summary.high, self.summary.medium, self.summary.low
        ));
        for finding in &self.findings {
            output.push_str(&finding.to_text());
        }
        output.push_str("\n");
        output
    }

    pub fn to_markdown(&self) -> String {
        let mut output = String::new();
        output.push_str("## Startup Services\n\n");
        output.push_str(&format!("- **Total findings:** {}\n", self.findings.len()));
        output.push_str(&format!(
            "- **Critical:** {}, **High:** {}, **Medium:** {}, **Low:** {}\n\n",
            self.summary.critical, self.summary.high, self.summary.medium, self.summary.low
        ));
        for finding in &self.findings {
            output.push_str(&finding.to_markdown());
        }
        output.push_str("\n");
        output
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartupFinding {
    pub name: String,
    pub path: String,
    pub enabled: bool,
    pub impact: String,
    pub severity: Severity,
    pub description: String,
    pub recommendation: String,
}

impl StartupFinding {
    pub fn to_text(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("Service: {}\n", self.name));
        output.push_str(&format!("Path: {}\n", self.path));
        output.push_str(&format!("Enabled: {}\n", self.enabled));
        output.push_str(&format!("Impact: {}\n", self.impact));
        output.push_str(&format!("Severity: {:?}\n", self.severity));
        output.push_str(&format!("Description: {}\n", self.description));
        output.push_str(&format!("Recommendation: {}\n\n", self.recommendation));
        output
    }

    pub fn to_markdown(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("### {}\n\n", self.name));
        output.push_str(&format!("- **Path:** {}\n", self.path));
        output.push_str(&format!("- **Enabled:** {}\n", self.enabled));
        output.push_str(&format!("- **Impact:** {}\n", self.impact));
        output.push_str(&format!("- **Severity:** {:?}\n", self.severity));
        output.push_str(&format!("- **Description:** {}\n", self.description));
        output.push_str(&format!(
            "- **Recommendation:** {}\n\n",
            self.recommendation
        ));
        output
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartupSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

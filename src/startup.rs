use crate::audit::*;
use anyhow::Result;

pub struct StartupScanner;

impl StartupScanner {
    pub fn scan() -> Result<Option<StartupReport>> {
        let mut findings = Vec::new();
        let mut summary = StartupSummary {
            total: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
        };

        #[cfg(unix)]
        {
            findings.extend(Self::scan_systemd_services()?);
            findings.extend(Self::scan_cron_jobs()?);
            findings.extend(Self::scan_init_d_scripts()?);
        }

        #[cfg(windows)]
        {
            findings.extend(Self::scan_windows_startup()?);
        }

        for finding in &findings {
            summary.total += 1;
            match finding.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
            }
        }

        if findings.is_empty() {
            Ok(None)
        } else {
            Ok(Some(StartupReport { findings, summary }))
        }
    }

    #[cfg(unix)]
    fn scan_systemd_services() -> Result<Vec<StartupFinding>> {
        let mut findings = Vec::new();

        let output = std::process::Command::new("systemctl")
            .args([
                "list-unit-files",
                "--type=service",
                "--state=enabled",
                "--no-pager",
                "--no-legend",
            ])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let service_name = parts[0];
                    let state = parts[1];

                    if state == "enabled" {
                        let severity = Self::assess_service_severity(service_name);

                        findings.push(StartupFinding {
                            name: service_name.to_string(),
                            path: format!("/etc/systemd/system/{}", service_name),
                            enabled: true,
                            impact: "Starts at boot".to_string(),
                            severity,
                            description: format!("{} is enabled to start at boot", service_name),
                            recommendation: format!(
                                "Review if {} is necessary. Disable with: systemctl disable {}",
                                service_name, service_name
                            ),
                        });
                    }
                }
            }
        }

        Ok(findings)
    }

    #[cfg(unix)]
    fn scan_cron_jobs() -> Result<Vec<StartupFinding>> {
        let mut findings = Vec::new();

        let cron_paths = [
            "/etc/crontab",
            "/var/spool/cron",
            "/etc/cron.d",
            "/etc/cron.daily",
            "/etc/cron.hourly",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
        ];

        for path in &cron_paths {
            if std::path::Path::new(path).exists() {
                findings.push(StartupFinding {
                    name: format!("cron:{}", path),
                    path: path.to_string(),
                    enabled: true,
                    impact: "Runs periodically".to_string(),
                    severity: Severity::Low,
                    description: format!("Cron jobs found in {}", path),
                    recommendation: format!("Review cron jobs in {} for unnecessary tasks", path),
                });
            }
        }

        Ok(findings)
    }

    #[cfg(unix)]
    fn scan_init_d_scripts() -> Result<Vec<StartupFinding>> {
        let mut findings = Vec::new();

        let init_d = std::path::Path::new("/etc/init.d");
        if init_d.exists() {
            if let Ok(entries) = std::fs::read_dir(init_d) {
                for entry in entries.flatten() {
                    if let Ok(name) = entry.file_name().into_string() {
                        findings.push(StartupFinding {
                            name: format!("init.d:{}", name),
                            path: format!("/etc/init.d/{}", name),
                            enabled: true,
                            impact: "Legacy init script".to_string(),
                            severity: Severity::Medium,
                            description: format!("Legacy init script found: {}", name),
                            recommendation: format!(
                                "Consider migrating {} to systemd or removing if unnecessary",
                                name
                            ),
                        });
                    }
                }
            }
        }

        Ok(findings)
    }

    #[cfg(windows)]
    fn scan_windows_startup() -> Result<Vec<StartupFinding>> {
        let mut findings = Vec::new();

        let startup_keys = [
            (
                winreg::enums::HKEY_CURRENT_USER,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            ),
            (
                winreg::enums::HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            ),
            (
                winreg::enums::HKEY_LOCAL_MACHINE,
                "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
            ),
        ];

        for (hive, path) in &startup_keys {
            if let Ok(key) = winreg::RegKey::predef(*hive).open_subkey(path) {
                for (name, value) in key.enum_values().flatten() {
                    let value_str = value.to_string();
                    let severity = Self::assess_windows_startup_severity(&name, &value_str);

                    findings.push(StartupFinding {
                        name: name.clone(),
                        path: value_str.clone(),
                        enabled: true,
                        impact: "Runs at user login".to_string(),
                        severity,
                        description: format!("Startup entry: {} -> {}", name, value_str),
                        recommendation: format!(
                            "Review if {} is necessary. Remove via msconfig or Autoruns",
                            name
                        ),
                    });
                }
            }
        }

        Ok(findings)
    }

    fn assess_service_severity(service_name: &str) -> Severity {
        let known_telemetry_services = [
            "telemetry",
            "diagnostics",
            "feedback",
            "update",
            "cloud",
            "sync",
            "analytics",
            "tracking",
            "reporting",
        ];

        let name_lower = service_name.to_lowercase();

        if known_telemetry_services
            .iter()
            .any(|s| name_lower.contains(s))
        {
            return Severity::High;
        }

        if name_lower.contains("ssh")
            || name_lower.contains("docker")
            || name_lower.contains("network")
        {
            return Severity::Low;
        }

        Severity::Medium
    }

    #[cfg(windows)]
    fn assess_windows_startup_severity(name: &str, path: &str) -> Severity {
        let telemetry_indicators = [
            "telemetry",
            "diagnostic",
            "feedback",
            "update",
            "cloud",
            "sync",
            "analytics",
            "tracking",
            "reporting",
            "crash",
        ];

        let combined = format!("{} {}", name, path).to_lowercase();

        if telemetry_indicators.iter().any(|s| combined.contains(s)) {
            return Severity::High;
        }

        if combined.contains("steam") || combined.contains("epic") || combined.contains("origin") {
            return Severity::Medium;
        }

        Severity::Low
    }
}

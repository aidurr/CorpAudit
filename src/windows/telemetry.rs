#[cfg(windows)]
use crate::audit::{Severity, TelemetryFinding};

#[cfg(windows)]
use anyhow::Result;

use winreg::enums::*;
#[cfg(windows)]
use winreg::RegKey;

#[allow(dead_code)]
pub struct WindowsTelemetryDetector {
    watched_registry_keys: Vec<String>,
}

#[allow(dead_code)]
impl WindowsTelemetryDetector {
    pub fn new() -> Self {
        Self {
            watched_registry_keys: vec![
                // Windows telemetry settings
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection".to_string(),
                r"SOFTWARE\Microsoft\SQMClient\Windows".to_string(),
                r"SOFTWARE\Policies\Microsoft\Windows\DataCollection".to_string(),
                // Windows diagnostics
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack".to_string(),
                // Windows feedback
                r"SOFTWARE\Microsoft\Siuf\Rules".to_string(),
                // Office telemetry
                r"SOFTWARE\Microsoft\Office\Common\ClientTelemetry".to_string(),
                r"SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry".to_string(),
                // .NET telemetry
                r"SOFTWARE\Microsoft\.NETFramework\Telemetry".to_string(),
                // Edge telemetry
                r"SOFTWARE\Policies\Microsoft\Edge".to_string(),
                // Windows Update telemetry
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\Pending\7971f918-a847-4430-9279-4a52d1efe18d".to_string(),
                // Cortana
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Search".to_string(),
                r"SOFTWARE\Policies\Microsoft\Windows\Windows Search".to_string(),
                // Advertising ID
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo".to_string(),
                r"SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo".to_string(),
                // Tailored experiences
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy".to_string(),
                r"SOFTWARE\Policies\Microsoft\Windows\Personalization".to_string(),
                // App diagnostics
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options".to_string(),
                // Windows error reporting
                r"SOFTWARE\Microsoft\Windows\Windows Error Reporting".to_string(),
                r"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting".to_string(),
            ],
        }
    }

    pub fn check_registry_telemetry(&self) -> Result<Vec<TelemetryFinding>> {
        let mut findings = Vec::new();

        for key_path in &self.watched_registry_keys {
            if let Ok(finding) = self.check_registry_key(key_path) {
                if let Some(f) = finding {
                    findings.push(f);
                }
            }
        }

        // Check for telemetry services
        if let Ok(service_findings) = self.check_telemetry_services() {
            findings.extend(service_findings);
        }

        // Check for telemetry scheduled tasks
        if let Ok(task_findings) = self.check_diagnostic_tasks() {
            findings.extend(task_findings);
        }

        Ok(findings)
    }

    fn check_registry_key(&self, key_path: &str) -> Result<Option<TelemetryFinding>> {
        // Parse the registry key path
        let parts: Vec<&str> = key_path.split('\\').collect();
        if parts.len() < 2 {
            return Ok(None);
        }

        // Determine hive and subkey
        let hive_str = parts[0];
        let subkey = parts[1..].join("\\");

        let hive = match hive_str {
            "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
            "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
            "HKCR" | "HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
            _ => return Ok(None),
        };

        // Open the registry key
        let hklm = RegKey::predef(hive);

        if let Ok(key) = hklm.open_subkey(&subkey) {
            // Check for telemetry-related values with comprehensive list
            let telemetry_values = [
                "AllowTelemetry",
                "TelemetryEnabled",
                "MicrosoftEdgeTelemetry",
                "CEIPEnable",
                "DisableTelemetryOptIn",
                "FeedbackEnabled",
                "TailoredExperiencesWithDiagnosticDataEnabled",
                "AdvertisingInfoEnabled",
                "EnableCortana",
                "SendInverted",
                "ConnectedAccountState",
                "DisableWindowsConsumerFeatures",
                "AllowConsumerFeatures",
                "DiagnosticDataLevel",
                "EnableWebContentEvaluation",
                "PreLaunchState",
            ];

            for value_name in &telemetry_values {
                if let Ok(value) = key.get_value::<u32, _>(value_name) {
                    // Check if telemetry is ENABLED (non-zero means enabled)
                    let is_enabled = match *value_name {
                        // Some values are inverted: 0 means enabled, 1 means disabled
                        "DisableTelemetryOptIn" | "DisableWindowsConsumerFeatures" => value == 0,
                        // Normal: non-zero means enabled
                        _ => value > 0,
                    };

                    if is_enabled {
                        let severity = self.determine_telemetry_severity(key_path, value_name, value);
                        let recommendation = self.get_registry_recommendation(key_path, value_name);

                        return Ok(Some(TelemetryFinding {
                            process_name: "Windows".to_string(),
                            pid: 0,
                            connections: Vec::new(),
                            data_sent: None,
                            data_received: None,
                            domains: vec![format!("Registry: {}", key_path)],
                            severity,
                            description: format!(
                                "Windows telemetry/policy enabled in registry: {}\\{} (value: {})",
                                key_path, value_name, value
                            ),
                            recommendation,
                        }));
                    }
                }
            }
        }

        Ok(None)
    }

    fn determine_telemetry_severity(&self, key_path: &str, value_name: &str, value: u32) -> Severity {
        // Critical: Core diagnostic data collection
        let critical_keys = [
            r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack",
        ];

        let critical_values = ["AllowTelemetry", "DiagnosticDataLevel", "TelemetryEnabled"];

        if critical_keys.iter().any(|k| key_path.contains(k))
            && critical_values.iter().any(|v| value_name.contains(v))
            && value > 0
        {
            return if value >= 3 {
                Severity::Critical
            } else {
                Severity::High
            };
        }

        // High: Cortana, feedback, advertising
        let high_values = [
            "EnableCortana",
            "FeedbackEnabled",
            "AdvertisingInfoEnabled",
            "TailoredExperiencesWithDiagnosticDataEnabled",
        ];

        if high_values.iter().any(|v| value_name.contains(v)) && value > 0 {
            return Severity::High;
        }

        // Medium: Other telemetry settings
        Severity::Medium
    }

    fn get_registry_recommendation(&self, key_path: &str, value_name: &str) -> String {
        if key_path.contains("DataCollection") {
            return "Set AllowTelemetry=0 or DiagnosticDataLevel=0 in registry, or use Group Policy to set 'Diagnostic Data Collection' to 'Disabled' (Security/Enterprise only)".to_string();
        }
        if key_path.contains("Cortana") || key_path.contains("Search") {
            return "Disable Cortana and cloud search via Group Policy or registry: Set 'Allow Cortana' and 'Allow Cloud Search' to Disabled".to_string();
        }
        if key_path.contains("AdvertisingInfo") {
            return "Disable Advertising ID via Settings > Privacy > Advertising, or set registry value to 0".to_string();
        }
        if key_path.contains("Windows Error Reporting") {
            return "Configure Windows Error Reporting via Group Policy: Computer Configuration > Administrative Templates > Windows Components > Windows Error Reporting".to_string();
        }
        if key_path.contains("Office") {
            return "Disable Office telemetry via Office Privacy Settings: File > Options > Trust Center > Trust Center Settings > Privacy Options > 'Send additional information to Microsoft' = unchecked".to_string();
        }

        format!(
            "Review registry setting {}\\{} and disable if not required for your use case",
            key_path, value_name
        )
    }

    pub fn check_telemetry_services(&self) -> Result<Vec<TelemetryFinding>> {
        let mut findings = Vec::new();

        // List of telemetry services to check
        let telemetry_services = [
            ("DiagTrack", "Connected User Experiences and Telemetry", Severity::High),
            ("dmwappushservice", "WAP Push Message Routing Service", Severity::Medium),
            ("diagnosticshub.standardcollector.service", "Microsoft (R) Diagnostics Hub Standard Collector Service", Severity::High),
            ("WdiServiceHost", "Diagnostic Service Host", Severity::Medium),
            ("DPS", "Diagnostic Policy Service", Severity::Medium),
        ];

        for (service_name, display_name, base_severity) in &telemetry_services {
            // Use sc.exe to query service status
            if let Ok(output) = std::process::Command::new("sc")
                .args(["query", service_name])
                .output()
            {
                let output_str = String::from_utf8_lossy(&output.stdout);
                if output_str.contains(service_name) && output_str.contains("RUNNING") {
                    findings.push(TelemetryFinding {
                        process_name: "Windows Services".to_string(),
                        pid: 0,
                        connections: Vec::new(),
                        data_sent: None,
                        data_received: None,
                        domains: vec![format!("Service: {}", service_name)],
                        severity: *base_severity,
                        description: format!(
                            "Telemetry/diagnostic service is running: {} ({})",
                            service_name, display_name
                        ),
                        recommendation: format!(
                            "Consider disabling service '{}' if not needed. Use 'sc config {} start= disabled' and 'sc stop {}' (requires admin)",
                            display_name, service_name, service_name
                        ),
                    });
                }
            }
        }

        Ok(findings)
    }

    pub fn check_diagnostic_tasks(&self) -> Result<Vec<TelemetryFinding>> {
        let mut findings = Vec::new();

        // Known telemetry-related scheduled tasks
        let telemetry_tasks = [
            (
                r"Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
                "Collects program telemetry data",
                Severity::High,
            ),
            (
                r"Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
                "Sends CEIP data to Microsoft",
                Severity::High,
            ),
            (
                r"Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
                "Collects USB device telemetry",
                Severity::Medium,
            ),
            (
                r"Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
                "Collects disk diagnostic data",
                Severity::Medium,
            ),
            (
                r"Microsoft\Windows\Application Experience\ProgramDataUpdater",
                "Updates program telemetry data",
                Severity::Medium,
            ),
            (
                r"Microsoft\Windows\Autochk\Proxy",
                "Disk check proxy for telemetry",
                Severity::Medium,
            ),
            (
                r"Microsoft\Windows\Shell\FamilySafetyMonitor",
                "Family safety monitoring",
                Severity::High,
            ),
            (
                r"Microsoft\Windows\Shell\FamilySafetyRefresh",
                "Family safety refresh",
                Severity::Medium,
            ),
        ];

        for (task_path, description, severity) in &telemetry_tasks {
            // Use schtasks.exe to query task status
            if let Ok(output) = std::process::Command::new("schtasks")
                .args(["/Query", "/TN", task_path, "/V", "/FO", "CSV", "/NH"])
                .output()
            {
                let output_str = String::from_utf8_lossy(&output.stdout);
                // Check if task exists and is enabled
                if !output_str.contains("ERROR") && !output_str.contains("Unable") {
                    findings.push(TelemetryFinding {
                        process_name: "Windows Task Scheduler".to_string(),
                        pid: 0,
                        connections: Vec::new(),
                        data_sent: None,
                        data_received: None,
                        domains: vec![format!("Task: {}", task_path)],
                        severity: *severity,
                        description: format!(
                            "Telemetry-related scheduled task is configured: {} - {}",
                            task_path, description
                        ),
                        recommendation: format!(
                            "Consider disabling task '{}' using 'schtasks /Change /TN \"{}\" /Disable' (requires admin)",
                            task_path, task_path
                        ),
                    });
                }
            }
        }

        Ok(findings)
    }
}

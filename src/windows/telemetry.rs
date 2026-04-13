#[cfg(windows)]
use crate::audit::{Severity, TelemetryFinding};

#[cfg(windows)]
use anyhow::Result;

#[cfg(windows)]
use winreg::RegKey;
use winreg::enums::*;

pub struct WindowsTelemetryDetector {
    watched_registry_keys: Vec<String>,
}

impl WindowsTelemetryDetector {
    pub fn new() -> Self {
        Self {
            watched_registry_keys: vec![
                // Windows telemetry settings
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection".to_string(),
                r"SOFTWARE\Microsoft\SQMClient\Windows".to_string(),
                r"SOFTWARE\Policies\Microsoft\Windows\DataCollection".to_string(),
                // Office telemetry
                r"SOFTWARE\Microsoft\Office\Common\ClientTelemetry".to_string(),
                // .NET telemetry
                r"SOFTWARE\Microsoft\.NETFramework\Telemetry".to_string(),
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
            // Check for telemetry-related values
            let telemetry_values = [
                "AllowTelemetry",
                "TelemetryEnabled",
                "MicrosoftEdgeTelemetry",
                "CEIPEnable",
            ];

            for value_name in &telemetry_values {
                if let Ok(value) = key.get_value::<u32, _>(value_name) {
                    if value > 0 {
                        // Telemetry is enabled
                        return Ok(Some(TelemetryFinding {
                            process_name: "Windows".to_string(),
                            pid: 0,
                            connections: Vec::new(),
                            data_sent: None,
                            data_received: None,
                            domains: vec![format!("Windows Registry: {}", key_path)],
                            severity: if value >= 3 {
                                Severity::Critical
                            } else {
                                Severity::High
                            },
                            description: format!(
                                "Windows telemetry enabled in registry: {}\\{}",
                                key_path, value_name
                            ),
                            recommendation: "Disable Windows telemetry via registry or group policy".to_string(),
                        }));
                    }
                }
            }
        }

        Ok(None)
    }

    pub fn check_diagnostic_tasks(&self) -> Result<Vec<TelemetryFinding>> {
        let findings = Vec::new();

        // Check for scheduled tasks related to telemetry
        let telemetry_tasks = [
            r"Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
            r"Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
            r"Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
            r"Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
        ];

        for _task in &telemetry_tasks {
            // Check if task exists and is enabled
            // This would require Task Scheduler API integration
            // For now, we'll just note that these tasks exist
        }

        Ok(findings)
    }
}

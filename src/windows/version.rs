use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsVersion {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub display_version: String,
    pub edition: String,
    pub is_windows_11: bool,
}

impl WindowsVersion {
    pub fn detect() -> Result<Self> {
        let edition = get_registry_string(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "ProductName",
        )
        .unwrap_or_else(|| "Windows".to_string());

        let display_version = get_registry_string(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "DisplayVersion",
        )
        .unwrap_or_else(|| "Unknown".to_string());

        let build_str = get_registry_string(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "CurrentBuildNumber",
        )
        .unwrap_or_else(|| "0".to_string());

        let build: u32 = build_str.parse().unwrap_or(0);

        // Parse major.minor from version
        let version_str = get_registry_string(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "CurrentVersion",
        )
        .unwrap_or_else(|| "10.0".to_string());

        let parts: Vec<&str> = version_str.split('.').collect();
        let major = parts.first().and_then(|s| s.parse().ok()).unwrap_or(10);
        let minor = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

        let is_windows_11 = build >= 22000;

        Ok(Self {
            major,
            minor,
            build,
            display_version,
            edition,
            is_windows_11,
        })
    }

    pub fn get_telemetry_profile(&self) -> String {
        if !self.is_windows_11 {
            return "Windows 10 detected - telemetry behavior differs from Win11".to_string();
        }

        if self.build >= 26100 {
            format!(
                "Windows 11 24H2 (Build {}) - Enhanced telemetry controls, AI features active",
                self.build
            )
        } else if self.build >= 22631 {
            format!(
                "Windows 11 23H2 (Build {}) - Standard telemetry, Copilot integration",
                self.build
            )
        } else if self.build >= 22621 {
            format!(
                "Windows 11 22H2 (Build {}) - Base Win11 telemetry profile",
                self.build
            )
        } else {
            format!(
                "Windows 11 (Build {}) - Unrecognized build, using default profile",
                self.build
            )
        }
    }

    pub fn get_recommended_actions(&self) -> Vec<String> {
        let mut actions = Vec::new();

        if !self.is_windows_11 {
            actions.push("Not Windows 11 - some fixes may not apply".to_string());
            return actions;
        }

        if self.build >= 26100 {
            // 24H2 specific
            actions.push("24H2: Disable Copilot telemetry in Settings > Privacy > General".to_string());
            actions.push("24H2: Review Recall settings for enhanced data collection".to_string());
            actions.push("24H2: Check AI features under Settings > Privacy > Inking & Typing".to_string());
        } else if self.build >= 22631 {
            // 23H2 specific
            actions.push("23H2: Disable Copilot if not needed (adds telemetry)".to_string());
            actions.push("23H2: Review Widgets data collection".to_string());
        }

        actions.push("All versions: Apply core telemetry disables via Safe fixes".to_string());
        actions
    }
}

fn get_registry_string(path: &str, value_name: &str) -> Option<String> {
    use winreg::enums::*;
    use winreg::RegKey;

    // Parse HKLM path
    if !path.starts_with("HKLM\\") {
        return None;
    }

    let subkey = &path[5..];
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    if let Ok(key) = hklm.open_subkey(subkey) {
        key.get_value::<String, _>(value_name).ok()
    } else {
        None
    }
}

pub fn create_system_restore_point(name: &str) -> Result<bool> {
    // Uses PowerShell to create a system restore point
    let powershell_script = format!(
        r#"
$restorePointName = "{}"
$description = "CorpAudit Restore Point - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {{
    Write-Error "Administrator privileges required to create restore point"
    exit 1
}}

# Enable system restore if disabled
Enable-ComputerRestore -Drive "$env:SystemDrive"

# Create restore point
Checkpoint-Computer -Description $description -RestorePointType "MODIFY_SETTINGS"

if ($?) {{
    Write-Output "Restore point created successfully: $restorePointName"
    exit 0
}} else {{
    Write-Error "Failed to create restore point"
    exit 1
}}
"#,
        name
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", &powershell_script])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        Ok(true)
    } else {
        eprintln!("Failed to create restore point:");
        eprintln!("stdout: {}", stdout);
        eprintln!("stderr: {}", stderr);
        Ok(false)
    }
}

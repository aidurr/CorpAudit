#[cfg(windows)]
use crate::audit::{BloatFinding, Fix, PermissionsFinding, TelemetryFinding};

#[cfg(windows)]
pub fn generate_windows_telemetry_fix(finding: &TelemetryFinding) -> Option<Fix> {
    let process_name = &finding.process_name;

    match process_name.to_lowercase().as_str() {
        name if name.contains("chrome") => {
            Some(Fix {
                id: format!("telemetry-{}", process_name.replace(' ', "-").to_lowercase()),
                title: format!("Disable telemetry for {}", process_name),
                description: finding.description.clone(),
                severity: finding.severity,
                commands: vec![
                    "# Disable Chrome telemetry via PowerShell".to_string(),
                    "powershell -Command \"New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Google\\Chrome' -Force -ErrorAction SilentlyContinue\"".to_string(),
                    "powershell -Command \"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Google\\Chrome' -Name 'MetricsReportingEnabled' -Value 0 -ErrorAction SilentlyContinue\"".to_string(),
                    "powershell -Command \"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Google\\Chrome' -Name 'SendWebRTCConnectionDetailsToGoogle' -Value 0 -ErrorAction SilentlyContinue\"".to_string(),
                ],
                rollback_commands: vec![
                    "# Remove Chrome telemetry policy".to_string(),
                    "powershell -Command \"Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Google\\Chrome' -Name 'MetricsReportingEnabled' -ErrorAction SilentlyContinue\"".to_string(),
                ],
                safe: true,
            })
        }
        name if name.contains("firefox") => {
            Some(Fix {
                id: format!("telemetry-{}", process_name.replace(' ', "-").to_lowercase()),
                title: format!("Disable telemetry for {}", process_name),
                description: finding.description.clone(),
                severity: finding.severity,
                commands: vec![
                    "# Disable Firefox telemetry via preferences".to_string(),
                    "powershell -Command \"$firefox_path = Get-ChildItem -Path '$env:APPDATA\\Mozilla\\Firefox\\Profiles' -Directory | Select-Object -First 1; if ($firefox_path) { $prefs_file = Join-Path $firefox_path.FullName 'user.js'; @('user_pref(\\\"datareporting.healthreport.uploadEnabled\\\", false);', 'user_pref(\\\"datareporting.policy.dataSubmissionEnabled\\\", false);', 'user_pref(\\\"toolkit.telemetry.enabled\\\", false);') | Set-Content -Path $prefs_file }\"".to_string(),
                ],
                rollback_commands: vec![
                    "# Remove Firefox telemetry configuration".to_string(),
                    "powershell -Command \"$firefox_path = Get-ChildItem -Path '$env:APPDATA\\Mozilla\\Firefox\\Profiles' -Directory | Select-Object -First 1; if ($firefox_path) { $prefs_file = Join-Path $firefox_path.FullName 'user.js'; if (Test-Path $prefs_file) { Remove-Item $prefs_file } }\"".to_string(),
                ],
                safe: true,
            })
        }
        name if name.contains("vscode") => {
            Some(Fix {
                id: format!("telemetry-{}", process_name.replace(' ', "-").to_lowercase()),
                title: format!("Disable telemetry for {}", process_name),
                description: finding.description.clone(),
                severity: finding.severity,
                commands: vec![
                    "# Disable VS Code telemetry via settings".to_string(),
                    "powershell -Command \"$settings_path = Join-Path $env:APPDATA 'Code\\User\\settings.json'; $settings = @{ 'telemetry.enableTelemetry' = $false; 'telemetry.telemetryLevel' = 'off' }; $settings | ConvertTo-Json | Set-Content -Path $settings_path\"".to_string(),
                ],
                rollback_commands: vec![
                    "# Remove VS Code telemetry settings".to_string(),
                    "powershell -Command \"$settings_path = Join-Path $env:APPDATA 'Code\\User\\settings.json'; if (Test-Path $settings_path) { Remove-Item $settings_path }\"".to_string(),
                ],
                safe: true,
            })
        }
        name if name.contains("edge") => {
            Some(Fix {
                id: format!("telemetry-{}", process_name.replace(' ', "-").to_lowercase()),
                title: format!("Disable telemetry for {}", process_name),
                description: finding.description.clone(),
                severity: finding.severity,
                commands: vec![
                    "# Disable Edge telemetry via registry".to_string(),
                    "powershell -Command \"New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge' -Force -ErrorAction SilentlyContinue\"".to_string(),
                    "powershell -Command \"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge' -Name 'MetricsReportingEnabled' -Value 0 -ErrorAction SilentlyContinue\"".to_string(),
                ],
                rollback_commands: vec![
                    "# Remove Edge telemetry policy".to_string(),
                    "powershell -Command \"Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge' -Name 'MetricsReportingEnabled' -ErrorAction SilentlyContinue\"".to_string(),
                ],
                safe: true,
            })
        }
        name if name.contains("windows") || finding.pid == 0 => {
            // Windows OS telemetry
            Some(Fix {
                id: "telemetry-windows".to_string(),
                title: "Disable Windows telemetry".to_string(),
                description: "Windows OS telemetry services are enabled".to_string(),
                severity: finding.severity,
                commands: vec![
                    "# Disable Windows telemetry services".to_string(),
                    "powershell -Command \"Set-Service -Name 'DiagTrack' -StartupType Disabled -ErrorAction SilentlyContinue\"".to_string(),
                    "powershell -Command \"Stop-Service -Name 'DiagTrack' -Force -ErrorAction SilentlyContinue\"".to_string(),
                    "powershell -Command \"Set-Service -Name 'dmwappushservice' -StartupType Disabled -ErrorAction SilentlyContinue\"".to_string(),
                    "powershell -Command \"Stop-Service -Name 'dmwappushservice' -Force -ErrorAction SilentlyContinue\"".to_string(),
                    "# Disable telemetry via registry".to_string(),
                    "powershell -Command \"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' -Name 'AllowTelemetry' -Value 0 -ErrorAction SilentlyContinue\"".to_string(),
                ],
                rollback_commands: vec![
                    "# Re-enable Windows telemetry services".to_string(),
                    "powershell -Command \"Set-Service -Name 'DiagTrack' -StartupType Automatic\"".to_string(),
                    "powershell -Command \"Start-Service -Name 'DiagTrack'\"".to_string(),
                    "powershell -Command \"Set-Service -Name 'dmwappushservice' -StartupType Manual\"".to_string(),
                    "# Re-enable telemetry via registry".to_string(),
                    "powershell -Command \"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' -Name 'AllowTelemetry' -Value 1\"".to_string(),
                ],
                safe: false,
            })
        }
        _ => {
            // Generic fix
            Some(Fix {
                id: format!("telemetry-{}", process_name.replace(' ', "-").to_lowercase()),
                title: format!("Block telemetry for {}", process_name),
                description: finding.description.clone(),
                severity: finding.severity,
                commands: vec![
                    format!("# Generic telemetry block for {}", process_name),
                    "# Block telemetry via hosts file".to_string(),
                    "powershell -Command \"$hosts_path = 'C:\\Windows\\System32\\drivers\\etc\\hosts'; $domains = @('google-analytics.com', 'analytics.google.com', 'doubleclick.net'); foreach ($domain in $domains) { if (!(Select-String -Path $hosts_path -Pattern $domain)) { Add-Content -Path $hosts_path -Value \"127.0.0.1 $domain\" } }\"".to_string(),
                ],
                rollback_commands: vec![
                    "# Remove hosts file entries".to_string(),
                    "powershell -Command \"$hosts_path = 'C:\\Windows\\System32\\drivers\\etc\\hosts'; $domains = @('google-analytics.com', 'analytics.google.com', 'doubleclick.net'); $content = Get-Content $hosts_path; foreach ($domain in $domains) { $content = $content | Where-Object { $_ -notmatch $domain }; }; $content | Set-Content $hosts_path\"".to_string(),
                ],
                safe: true,
            })
        }
    }
}

#[cfg(windows)]
pub fn generate_windows_bloat_fix(finding: &BloatFinding) -> Option<Fix> {
    let process_name = &finding.process_name;

    Some(Fix {
        id: format!("bloat-{}", process_name.replace(' ', "-").to_lowercase()),
        title: format!("Optimize {}", process_name),
        description: finding.description.clone(),
        severity: finding.severity,
        commands: vec![
            format!("# Optimize {} resource usage", process_name),
            "# Consider using lightweight alternatives".to_string(),
            "# Review application settings for performance options".to_string(),
        ],
        rollback_commands: vec!["# No rollback needed for informational fix".to_string()],
        safe: true,
    })
}

#[cfg(windows)]
pub fn generate_windows_permissions_fix(finding: &PermissionsFinding) -> Option<Fix> {
    let process_name = &finding.process_name;

    Some(Fix {
        id: format!(
            "permissions-{}",
            process_name.replace(' ', "-").to_lowercase()
        ),
        title: format!("Restrict permissions for {}", process_name),
        description: finding.description.clone(),
        severity: finding.severity,
        commands: vec![
            format!("# Review permissions for {}", process_name),
            "# Use Windows AppContainer or restricted tokens".to_string(),
            "# Review application privacy settings".to_string(),
        ],
        rollback_commands: vec!["# No rollback needed for informational fix".to_string()],
        safe: true,
    })
}

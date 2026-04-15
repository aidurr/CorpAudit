use crate::audit::*;
use anyhow::{Context, Result};
use log::{info, warn};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::NamedTempFile;

pub fn generate_fixes(report: &AuditReport, safe: bool) -> Result<Vec<Fix>> {
    let mut fixes = Vec::new();

    // Generate fixes for telemetry findings
    if let Some(ref telemetry) = report.telemetry {
        for finding in &telemetry.findings {
            if let Some(fix) = generate_telemetry_fix(finding, safe) {
                fixes.push(fix);
            }
        }
    }

    // Generate fixes for bloat findings
    if let Some(ref bloat) = report.bloat {
        for finding in &bloat.findings {
            if let Some(fix) = generate_bloat_fix(finding, safe) {
                fixes.push(fix);
            }
        }
    }

    // Generate fixes for permissions findings
    if let Some(ref permissions) = report.permissions {
        for finding in &permissions.findings {
            if let Some(fix) = generate_permissions_fix(finding, safe) {
                fixes.push(fix);
            }
        }
    }

    Ok(fixes)
}

pub fn apply_fixes(fixes: &[Fix]) -> Result<()> {
    let mut success_count = 0;
    let mut failure_count = 0;

    for fix in fixes {
        info!("Applying fix: {}", fix.title);

        match apply_fix(fix) {
            Ok(_) => {
                success_count += 1;
                info!("✓ Successfully applied: {}", fix.title);
            }
            Err(e) => {
                failure_count += 1;
                warn!("✗ Failed to apply {}: {}", fix.title, e);
            }
        }
    }

    info!(
        "Fix application complete: {} succeeded, {} failed",
        success_count, failure_count
    );

    if failure_count > 0 {
        anyhow::bail!("Some fixes failed to apply");
    }

    Ok(())
}

fn apply_fix(fix: &Fix) -> Result<()> {
    // SAFETY GUARD: Never apply unsafe fixes without explicit confirmation
    if !fix.safe {
        warn!("⚠ Fix '{}' is marked as UNSAFE. Skipping automatic application.", fix.title);
        warn!("  This fix requires manual review and administrator privileges.");
        warn!("  Review the fix commands and apply manually if appropriate.");
        return Ok(());
    }

    // Create a temporary file for the fix script
    #[cfg(unix)]
    let temp_file = NamedTempFile::new().context("Failed to create temporary file")?;

    #[cfg(windows)]
    let temp_file =
        NamedTempFile::with_suffix(".bat").context("Failed to create temporary file")?;

    // Write the fix commands to the script
    let mut script_content = String::new();

    #[cfg(unix)]
    {
        script_content.push_str("#!/bin/bash\n");
        script_content.push_str("set -euo pipefail\n\n");  // Fail fast, treat unset vars as error
    }

    #[cfg(windows)]
    {
        script_content.push_str("@echo off\n");
        script_content.push_str("setlocal EnableDelayedExpansion\n\n");
    }

    script_content.push_str("# CorpAudit Fix Script\n");
    script_content.push_str(&format!("# Fix: {}\n", fix.title));
    script_content.push_str(&format!("# Description: {}\n", fix.description));
    script_content.push_str(&format!("# Safety: {}\n", if fix.safe { "Safe" } else { "UNSAFE - Requires Review" }));
    script_content.push_str("\n");

    for cmd in &fix.commands {
        script_content.push_str(cmd);
        script_content.push_str("\n");
    }

    fs::write(temp_file.path(), script_content).context("Failed to write fix script")?;

    // Make the script executable (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(temp_file.path())?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(temp_file.path(), perms)?;
    }

    // Execute the fix script with appropriate shell
    #[cfg(unix)]
    let output = Command::new("bash")
        .arg(temp_file.path())
        .output()
        .context("Failed to execute fix script")?;

    #[cfg(windows)]
    let output = Command::new("cmd")
        .args(["/C", &temp_file.path().to_string_lossy()])
        .output()
        .context("Failed to execute fix script")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!(
            "Fix script failed (exit code {})\nstdout: {}\nstderr: {}",
            output.status,
            stdout,
            stderr
        );
    }

    Ok(())
}

fn generate_telemetry_fix(finding: &TelemetryFinding, safe: bool) -> Option<Fix> {
    let process_name = &finding.process_name;

    let mut commands = Vec::new();
    let mut rollback_commands = Vec::new();

    // Generate commands based on the process
    match process_name.to_lowercase().as_str() {
        // Windows telemetry
        name if name == "windows" || finding.pid == 0 => {
            // Check if this is a registry-based telemetry finding
            if finding.domains.iter().any(|d| d.contains("Registry")) {
                commands.push(format!(
                    "# Disable Windows telemetry via registry (requires admin)\n\
                     # IMPORTANT: This requires administrator privileges\n\
                     # Backup current settings before making changes\n\
                     \n\
                     # Set AllowTelemetry to 0 (Security/Enterprise only)\n\
                     reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v AllowTelemetry /t REG_DWORD /d 0 /f\n\
                     \n\
                     # Disable diagnostic tracking\n\
                     reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v AllowDeviceNameInTelemetry /t REG_DWORD /d 0 /f\n\
                     \n\
                     # Note: Some settings require Windows Enterprise or Education edition"
                ));

                rollback_commands.push(format!(
                    "# Restore Windows telemetry settings\n\
                     reg delete \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v AllowTelemetry /f\n\
                     reg delete \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v AllowDeviceNameInTelemetry /f"
                ));
            } else if finding.domains.iter().any(|d| d.contains("Service")) {
                commands.push(format!(
                    "# Disable Windows telemetry services (requires admin)\n\
                     # WARNING: This may affect system functionality\n\
                     \n\
                     # Stop and disable Connected User Experiences and Telemetry\n\
                     sc stop DiagTrack\n\
                     sc config DiagTrack start= disabled\n\
                     \n\
                     # Stop and disable WAP Push service\n\
                     sc stop dmwappushservice\n\
                     sc config dmwappushservice start= disabled\n\
                     \n\
                     # Note: Services can be re-enabled by changing 'disabled' to 'auto'"
                ));

                rollback_commands.push(format!(
                    "# Re-enable Windows telemetry services\n\
                     sc config DiagTrack start= auto\n\
                     sc start DiagTrack\n\
                     sc config dmwappushservice start= demand\n\
                     sc start dmwappushservice"
                ));
            } else if finding.domains.iter().any(|d| d.contains("Task")) {
                commands.push(format!(
                    "# Disable telemetry scheduled tasks (requires admin)\n\
                     \n\
                     # Disable Customer Experience Improvement Program tasks\n\
                     schtasks /Change /TN \"Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator\" /Disable\n\
                     schtasks /Change /TN \"Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip\" /Disable\n\
                     \n\
                     # Disable Application Experience tasks\n\
                     schtasks /Change /TN \"Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser\" /Disable\n\
                     schtasks /Change /TN \"Microsoft\\Windows\\Application Experience\\ProgramDataUpdater\" /Disable\n\
                     \n\
                     # Note: Tasks can be re-enabled with /Enable flag"
                ));

                rollback_commands.push(format!(
                    "# Re-enable telemetry scheduled tasks\n\
                     schtasks /Change /TN \"Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator\" /Enable\n\
                     schtasks /Change /TN \"Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip\" /Enable\n\
                     schtasks /Change /TN \"Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser\" /Enable\n\
                     schtasks /Change /TN \"Microsoft\\Windows\\Application Experience\\ProgramDataUpdater\" /Enable"
                ));
            }
        }
        name if name.contains("chrome") => {
            commands.push(format!(
                "# Disable Chrome telemetry\n\
                 # Create Chrome policies directory\n\
                 sudo mkdir -p /etc/opt/chrome/policies/managed\n\
                 \n\
                 # Create policy file to disable telemetry\n\
                 cat <<EOF | sudo tee /etc/opt/chrome/policies/managed/telemetry.json > /dev/null\n\
                 {{\n\
                   \"MetricsReportingEnabled\": false,\n\
                   \"SendWebRTCConnectionDetailsToGoogle\": false,\n\
                   \"SafeBrowsingExtendedReportingEnabled\": false,\n\
                   \"SearchSuggestEnabled\": false,\n\
                   \"UrlKeyedAnonymizedDataCollectionEnabled\": false,\n\
                   \"ReportingEnabled\": false\n\
                 }}\n\
                 EOF\n\
                 \n\
                 # Block telemetry domains in hosts file\n\
                 sudo sed -i '/google-analytics.com/d' /etc/hosts\n\
                 sudo sed -i '/analytics.google.com/d' /etc/hosts\n\
                 echo '127.0.0.1 google-analytics.com' | sudo tee -a /etc/hosts\n\
                 echo '127.0.0.1 analytics.google.com' | sudo tee -a /etc/hosts"
            ));

            rollback_commands.push(format!(
                "# Remove Chrome telemetry policy\n\
                 sudo rm -f /etc/opt/chrome/policies/managed/telemetry.json\n\
                 \n\
                 # Remove hosts file entries\n\
                 sudo sed -i '/google-analytics.com/d' /etc/hosts\n\
                 sudo sed -i '/analytics.google.com/d' /etc/hosts"
            ));
        }
        name if name.contains("firefox") => {
            commands.push(format!(
                "# Disable Firefox telemetry\n\
                 # Create Firefox configuration directory\n\
                 mkdir -p ~/.mozilla/firefox/*.default-release\n\
                 \n\
                 # Create user.js to disable telemetry\n\
                 cat <<EOF > ~/.mozilla/firefox/*.default-release/user.js\n\
                 user_pref(\"datareporting.healthreport.uploadEnabled\", false);\n\
                 user_pref(\"datareporting.policy.dataSubmissionEnabled\", false);\n\
                 user_pref(\"toolkit.telemetry.enabled\", false);\n\
                 user_pref(\"toolkit.telemetry.unified\", false);\n\
                 user_pref(\"browser.pingCentre.telemetry\", false);\n\
                 user_pref(\"browser.newtabpage.activity-stream.feeds.telemetry\", false);\n\
                 user_pref(\"browser.newtabpage.activity-stream.telemetry\", false);\n\
                 user_pref(\"app.shield.optoutstudies.enabled\", false);\n\
                 user_pref(\"breakpad.reportURL\", \"\");\n\
                 user_pref(\"browser.tabs.crashReporting.sendReport\", false);\n\
                 user_pref(\"browser.crashReports.unsubmittedCheck.autoSubmit\", false);\n\
                 EOF"
            ));

            rollback_commands.push(format!(
                "# Remove Firefox telemetry configuration\n\
                 rm -f ~/.mozilla/firefox/*.default-release/user.js"
            ));
        }
        name if name.contains("vscode") => {
            commands.push(format!(
                "# Disable VS Code telemetry\n\
                 # Create VS Code settings directory\n\
                 mkdir -p ~/.config/Code/User\n\
                 \n\
                 # Create settings.json to disable telemetry\n\
                 cat <<EOF > ~/.config/Code/User/settings.json\n\
                 {{\n\
                   \"telemetry.enableTelemetry\": false,\n\
                   \"telemetry.telemetryLevel\": \"off\",\n\
                   \"extensions.autoUpdate\": false,\n\
                   \"update.mode\": \"none\"\n\
                 }}\n\
                 EOF\n\
                 \n\
                 # Block telemetry domains\n\
                 sudo sed -i '/vscode-sync.azurewebsites.net/d' /etc/hosts\n\
                 echo '127.0.0.1 vscode-sync.azurewebsites.net' | sudo tee -a /etc/hosts"
            ));

            rollback_commands.push(format!(
                "# Remove VS Code telemetry configuration\n\
                 rm -f ~/.config/Code/User/settings.json\n\
                 \n\
                 # Remove hosts file entries\n\
                 sudo sed -i '/vscode-sync.azurewebsites.net/d' /etc/hosts"
            ));
        }
        _ => {
            // Generic fix for unknown processes
            commands.push(format!(
                "# Generic telemetry fix for {}\n\
                 # Block known telemetry domains in hosts file\n\
                 for domain in google-analytics.com analytics.google.com doubleclick.net; do\n\
                   if ! grep -q \"$domain\" /etc/hosts; then\n\
                     echo \"127.0.0.1 $domain\" | sudo tee -a /etc/hosts\n\
                   fi\n\
                 done\n\
                 \n\
                 # Note: Review process-specific settings to disable telemetry",
                process_name
            ));

            rollback_commands.push(format!(
                "# Remove generic telemetry blocks\n\
                 for domain in google-analytics.com analytics.google.com doubleclick.net; do\n\
                   sudo sed -i \"/$domain/d\" /etc/hosts\n\
                 done"
            ));
        }
    }

    Some(Fix {
        id: format!(
            "telemetry-{}",
            process_name.replace(' ', "-").to_lowercase()
        ),
        title: format!("Disable telemetry for {}", process_name),
        description: finding.description.clone(),
        severity: finding.severity,
        commands,
        rollback_commands,
        safe,
    })
}

fn generate_bloat_fix(finding: &BloatFinding, safe: bool) -> Option<Fix> {
    let process_name = &finding.process_name;

    let mut commands = Vec::new();
    let mut rollback_commands = Vec::new();

    // Generate commands based on the process
    match process_name.to_lowercase().as_str() {
        name if name.contains("chrome") => {
            commands.push(format!(
                "# Optimize Chrome memory usage\n\
                 # Create Chrome flags file\n\
                 mkdir -p ~/.config/google-chrome-flags-default\n\
                 cat <<EOF > ~/.config/google-chrome-flags-default/flags.conf\n\
                 --enable-low-res-tiling\n\
                 --enable-low-end-device-mode\n\
                 --disable-gpu-compositing\n\
                 --disable-software-rasterizer\n\
                 --max-tiles-for-interest-area=32\n\
                 --enable-zero-copy\n\
                 --num-raster-threads=2\n\
                 EOF"
            ));

            rollback_commands.push(format!(
                "# Remove Chrome optimization flags\n\
                 rm -f ~/.config/google-chrome-flags-default/flags.conf"
            ));
        }
        name if name.contains("slack") => {
            commands.push(format!(
                "# Optimize Slack resource usage\n\
                 # Create Slack configuration\n\
                 mkdir -p ~/.config/Slack\n\
                 cat <<EOF > ~/.config/Slack/settings.json\n\
                 {{\n\
                   \"bootAnimationEnabled\": false,\n\
                   \"renderEmojiGlow\": false,\n\
                   \"sidebarRosterEnabled\": false,\n\
                   \"showPreviews\": false,\n\
                   \"showTypingIndicator\": false\n\
                 }}\n\
                 EOF"
            ));

            rollback_commands.push(format!(
                "# Remove Slack optimization configuration\n\
                 rm -f ~/.config/Slack/settings.json"
            ));
        }
        name if name.contains("discord") => {
            commands.push(format!(
                "# Optimize Discord resource usage
# Enable Discord hardware acceleration (reduces CPU usage)
# Note: This may increase GPU usage but overall reduces system load
mkdir -p ~/.config/discord
cat <<EOF > ~/.config/discord/settings.json
{{
  \"openHardwareAcceleration\": true,
  \"minimizeToTray\": true,
  \"closeToTray\": true
}}
EOF"
            ));

            rollback_commands.push(format!(
                "# Remove Discord optimization configuration\n\
                 rm -f ~/.config/discord/settings.json"
            ));
        }
        _ => {
            // Generic bloat fix
            commands.push(format!(
                "# Generic optimization for {}\n\
                 # Consider the following:\n\
                 # 1. Check for unnecessary background processes\n\
                 # 2. Review application settings for performance options\n\
                 # 3. Consider using lightweight alternatives\n\
                 # 4. Disable unnecessary plugins/extensions\n\
                 # 5. Clear application cache\n\
                 \n\
                 # Current resource usage:\n\
                 # Memory: {:.2} MB\n\
                 # CPU: {:.2}%\n\
                 # Startup: {} ms",
                process_name, finding.memory_mb, finding.cpu_percent, finding.startup_time_ms
            ));

            rollback_commands.push(String::from("# No rollback needed for informational fix"));
        }
    }

    Some(Fix {
        id: format!("bloat-{}", process_name.replace(' ', "-").to_lowercase()),
        title: format!("Optimize {}", process_name),
        description: finding.description.clone(),
        severity: finding.severity,
        commands,
        rollback_commands,
        safe,
    })
}

fn generate_permissions_fix(finding: &PermissionsFinding, safe: bool) -> Option<Fix> {
    let process_name = &finding.process_name;

    let mut commands = Vec::new();
    let mut rollback_commands = Vec::new();

    // Generate commands based on permissions
    let has_camera = finding
        .permissions
        .iter()
        .any(|p| p.permission_type.contains("camera"));
    let has_microphone = finding
        .permissions
        .iter()
        .any(|p| p.permission_type.contains("microphone"));
    let has_filesystem = finding
        .permissions
        .iter()
        .any(|p| p.permission_type.contains("filesystem"));

    if has_camera || has_microphone {
        commands.push(format!(
            "# Restrict camera/microphone access for {}\n\
             # Check system privacy settings\n\
             \n\
             # On Linux with Flatpak:\n\
             flatpak permission-reset {}\n\
             \n\
             # On Linux with Firejail:\n\
             # sudo firejail --private --noprofile --net=none {}\n\
             \n\
             # Review application permissions in system settings",
            process_name, process_name, process_name
        ));

        rollback_commands.push(String::from(
            "# Reset permissions may require manual intervention",
        ));
    }

    if has_filesystem {
        commands.push(format!(
            "# Restrict filesystem access for {}\n\
             # Create AppArmor profile (if available)\n\
             \n\
             # Example AppArmor profile:\n\
             # sudo tee /etc/apparmor.d/{} <<EOF\n\
             # #include <tunables/global>\n\
             # \n\
             # profile {} {{\n\
             #   deny /home/** rw,\n\
             #   deny /root/** rw,\n\
             #   /usr/share/** r,\n\
             #   /etc/** r,\n\
             # }}\n\
             # EOF\n\
             # \n\
             # sudo apparmor_parser -r /etc/apparmor.d/{}\n\
             # \n\
             # Note: Review and customize profile based on application needs",
            process_name,
            process_name.replace(' ', "_"),
            process_name.replace(' ', "_"),
            process_name.replace(' ', "_")
        ));

        rollback_commands.push(format!(
            "# Remove AppArmor profile\n\
             sudo rm -f /etc/apparmor.d/{}\n\
             sudo apparmor_parser -R /etc/apparmor.d/{}",
            process_name.replace(' ', "_"),
            process_name.replace(' ', "_")
        ));
    }

    if commands.is_empty() {
        // Generic permissions fix
        commands.push(format!(
            "# Review permissions for {}\n\
             # Current permissions:\n",
            process_name
        ));

        for perm in &finding.permissions {
            commands.push(format!(
                "# - {}: {}",
                perm.permission_type, perm.description
            ));
        }

        commands.push(String::from(
            "\n# Recommendations:\n\
             # 1. Review application settings to disable unnecessary permissions\n\
             # 2. Use system privacy controls to restrict access\n\
             # 3. Consider sandboxing the application\n\
             # 4. Use privacy-focused alternatives",
        ));

        rollback_commands.push(String::from("# No rollback needed for informational fix"));
    }

    Some(Fix {
        id: format!(
            "permissions-{}",
            process_name.replace(' ', "-").to_lowercase()
        ),
        title: format!("Restrict permissions for {}", process_name),
        description: finding.description.clone(),
        severity: finding.severity,
        commands,
        rollback_commands,
        safe,
    })
}

#[allow(dead_code)]
pub fn create_fix_script(fixes: &[Fix], output_path: &PathBuf) -> Result<()> {
    let mut script_content = String::new();

    script_content.push_str("#!/bin/bash\n");
    script_content.push_str("# CorpAudit Fix Script\n");
    script_content.push_str("# Generated by CorpAudit\n");
    script_content.push_str("# Run with: bash fix_script.sh\n");
    script_content.push_str("#\n");
    script_content.push_str("# WARNING: Review this script before running!\n");
    script_content.push_str("# Make backups of important data before applying fixes.\n");
    script_content.push_str("\n");

    script_content.push_str("set -e  # Exit on error\n");
    script_content.push_str("\n");

    script_content.push_str("echo \"CorpAudit Fix Script\"\n");
    script_content.push_str("echo \"====================\"\n");
    script_content.push_str("echo \"\"\n");
    script_content.push_str("echo \"This script will apply the following fixes:\"\n");
    script_content.push_str("echo \"\"\n");

    for (i, fix) in fixes.iter().enumerate() {
        script_content.push_str(&format!("echo \"{}. {}\"\n", i + 1, fix.title));
    }

    script_content.push_str("echo \"\"\n");
    script_content.push_str("read -p \"Continue? (y/N) \" -n 1 -r\n");
    script_content.push_str("echo \"\"\n");
    script_content.push_str("if [[ ! $REPLY =~ ^[Yy]$ ]]; then\n");
    script_content.push_str("    echo \"Aborted.\"\n");
    script_content.push_str("    exit 1\n");
    script_content.push_str("fi\n");
    script_content.push_str("echo \"\"\n");

    for fix in fixes {
        script_content.push_str(&format!("echo \"Applying: {}\"\n", fix.title));

        for cmd in &fix.commands {
            script_content.push_str(cmd);
            script_content.push_str("\n");
        }

        script_content.push_str("echo \"✓ Done\"\n");
        script_content.push_str("echo \"\"\n");
    }

    script_content.push_str("echo \"All fixes applied successfully!\"\n");
    script_content.push_str("echo \"\"\n");
    script_content
        .push_str("echo \"To rollback changes, review the rollback commands in the report.\"\n");

    fs::write(output_path, script_content).context(format!(
        "Failed to write fix script to {}",
        output_path.display()
    ))?;

    // Make the script executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(output_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(output_path, perms)?;
    }

    Ok(())
}

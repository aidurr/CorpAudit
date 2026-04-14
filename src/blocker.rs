use crate::audit::*;
use anyhow::Result;
use std::collections::HashSet;

pub fn generate_block_rules(report: &AuditReport) -> Result<String> {
    let mut output = String::new();

    #[cfg(unix)]
    {
        output.push_str("#!/bin/bash\n");
        output.push_str("# CorpAudit - Firewall Rules to Block Telemetry\n");
        output.push_str("# Generated: ");
        output.push_str(&chrono::Utc::now().to_rfc3339());
        output.push_str("\n#\n");
        output.push_str("# WARNING: Review these rules before applying!\n");
        output.push_str("# Run with: sudo bash block_telemetry.sh\n\n");
        output.push_str("set -e\n\n");
        output.push_str("echo \"Applying telemetry block rules...\"\n\n");
    }

    #[cfg(windows)]
    {
        output.push_str("@echo off\n");
        output.push_str("REM CorpAudit - Windows Firewall Rules to Block Telemetry\n");
        output.push_str("REM Generated: ");
        output.push_str(&chrono::Utc::now().to_rfc3339());
        output.push_str("\nREM\n");
        output.push_str("REM WARNING: Review these rules before applying!\n");
        output.push_str("REM Run as Administrator\n\n");
        output.push_str("echo Applying telemetry block rules...\n\n");
    }

    let telemetry_domains = report.telemetry.as_ref().map_or(HashSet::new(), |t| {
        t.findings
            .iter()
            .flat_map(|f| f.domains.iter().cloned())
            .collect()
    });

    if telemetry_domains.is_empty() {
        output.push_str("# No telemetry domains detected to block.\n");
        return Ok(output);
    }

    #[cfg(unix)]
    {
        output.push_str("# Block domains using iptables\n");
        for domain in &telemetry_domains {
            output.push_str(&format!("echo \"Blocking {}...\"\n", domain));
            output.push_str(&format!(
                "iptables -A OUTPUT -d {} -j DROP 2>/dev/null || true\n",
                domain
            ));
            output.push_str(&format!(
                "ip6tables -A OUTPUT -d {} -j DROP 2>/dev/null || true\n",
                domain
            ));
        }
        output.push_str("\necho \"Done! Telemetry domains blocked.\"\n");
        output.push_str(
            "echo \"To undo these rules, run: iptables -F OUTPUT && ip6tables -F OUTPUT\"\n",
        );
    }

    #[cfg(windows)]
    {
        output.push_str("REM Block domains using Windows Firewall\n");
        for domain in &telemetry_domains {
            let rule_name = format!("CorpAudit_Block_{}", domain.replace('.', "_"));
            output.push_str(&format!(
                "netsh advfirewall firewall add rule name=\"{}\" dir=out action=block remoteip={} protocol=any >nul 2>&1\n",
                rule_name, domain
            ));
        }
        output.push_str("\necho Done! Telemetry domains blocked.\n");
        output.push_str("echo To undo these rules, run the following for each rule:\n");
        for domain in &telemetry_domains {
            let rule_name = format!("CorpAudit_Block_{}", domain.replace('.', "_"));
            output.push_str(&format!(
                "echo netsh advfirewall firewall delete rule name=\"{}\"\n",
                rule_name
            ));
        }
    }

    Ok(output)
}

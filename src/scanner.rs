use crate::audit::*;
use crate::config::Config;
use crate::startup;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::process::Command;
use sysinfo::System;

#[cfg(windows)]
use crate::windows;

pub struct Scanner {
    config: Config,
    include_system: bool,
    min_severity: Severity,
    system: System,
}

impl Scanner {
    pub fn new(config: Config, include_system: bool, min_severity: String) -> Self {
        let severity = match min_severity.as_str() {
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => Severity::Medium,
        };

        let mut system = System::new_all();
        system.refresh_all();

        Self {
            config,
            include_system,
            min_severity: severity,
            system,
        }
    }

    pub fn scan_telemetry(&mut self) -> Result<Option<TelemetryReport>> {
        let mut findings = Vec::new();
        let mut summary = TelemetrySummary {
            total: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
        };

        let telemetry_domains = self.config.get_telemetry_domains();

        #[cfg(windows)]
        {
            let win_telemetry = windows::telemetry::WindowsTelemetryDetector::new();
            if let Ok(reg_findings) = win_telemetry.check_registry_telemetry() {
                for f in reg_findings {
                    if f.severity >= self.min_severity {
                        summary.total += 1;
                        match f.severity {
                            Severity::Critical => summary.critical += 1,
                            Severity::High => summary.high += 1,
                            Severity::Medium => summary.medium += 1,
                            Severity::Low => summary.low += 1,
                        }
                        findings.push(f);
                    }
                }
            }
        }

        for (pid, process) in self.system.processes() {
            let process_name = process.name().to_string_lossy().to_string();

            if !self.include_system && is_system_process(&process_name) {
                continue;
            }

            if self.config.is_process_whitelisted(&process_name) {
                continue;
            }

            if let Some(connections) = self.get_process_connections(pid.as_u32())? {
                let mut telemetry_connections = Vec::new();
                let mut domains = Vec::new();
                let mut data_sent = 0u64;
                let mut data_received = 0u64;

                for conn in connections {
                    if is_telemetry_connection(&conn, &telemetry_domains) {
                        let is_whitelisted = conn
                            .remote_address
                            .split('.')
                            .last()
                            .map(|d| self.config.is_domain_whitelisted(d))
                            .unwrap_or(false);

                        if is_whitelisted {
                            continue;
                        }

                        telemetry_connections.push(conn.clone());

                        if let Some(domain) = resolve_domain(&conn.remote_address) {
                            if !self.config.is_domain_whitelisted(&domain)
                                && !domains.contains(&domain)
                            {
                                domains.push(domain);
                            }
                        }

                        data_sent += conn.data_sent.unwrap_or(0);
                        data_received += conn.data_received.unwrap_or(0);
                    }
                }

                if !telemetry_connections.is_empty() {
                    let severity = self.determine_telemetry_severity(&process_name, &domains);

                    if severity >= self.min_severity {
                        let finding = TelemetryFinding {
                            process_name: process_name.clone(),
                            pid: pid.as_u32(),
                            connections: telemetry_connections,
                            data_sent: if data_sent > 0 { Some(data_sent) } else { None },
                            data_received: if data_received > 0 {
                                Some(data_received)
                            } else {
                                None
                            },
                            domains,
                            severity,
                            description: self.get_telemetry_description(&process_name),
                            recommendation: self.get_telemetry_recommendation(&process_name),
                        };

                        summary.total += 1;
                        match severity {
                            Severity::Critical => summary.critical += 1,
                            Severity::High => summary.high += 1,
                            Severity::Medium => summary.medium += 1,
                            Severity::Low => summary.low += 1,
                        }

                        findings.push(finding);
                    }
                }
            }
        }

        if findings.is_empty() {
            Ok(None)
        } else {
            Ok(Some(TelemetryReport { findings, summary }))
        }
    }

    pub fn scan_bloat(&mut self) -> Result<Option<BloatReport>> {
        let mut findings = Vec::new();
        let mut summary = BloatSummary {
            total: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
        };

        let memory_threshold_mb = self.config.get_memory_threshold_mb();
        let cpu_threshold_percent = self.config.get_cpu_threshold_percent();

        let logical_cores = self
            .system
            .physical_core_count()
            .unwrap_or(self.system.cpus().len().max(1)) as f64;

        let mut process_families: HashMap<String, Vec<(u32, String, f64, f64)>> = HashMap::new();

        for (pid, process) in self.system.processes() {
            let process_name = process.name().to_string_lossy().to_string();

            if !self.include_system && is_system_process(&process_name) {
                continue;
            }

            if self.config.is_process_whitelisted(&process_name) {
                continue;
            }

            if is_known_safe_process(&process_name) {
                continue;
            }

            let memory_mb = process.memory() as f64 / 1_048_576.0;
            let cpu_percent = (process.cpu_usage() as f64 / logical_cores).min(100.0);

            let family_key = get_process_family(&process_name);
            process_families.entry(family_key).or_default().push((
                pid.as_u32(),
                process_name,
                memory_mb,
                cpu_percent,
            ));
        }

        for (_family_key, members) in process_families {
            let is_multiprocess_family = members.len() > 1;

            let total_memory: f64 = members.iter().map(|(_, _, m, _)| *m).sum();
            let max_cpu: f64 = members
                .iter()
                .map(|(_, _, _, c)| *c)
                .fold(0.0_f64, f64::max);
            let total_cpu: f64 = members.iter().map(|(_, _, _, c)| *c).sum();

            if is_multiprocess_family {
                let primary = &members[0];
                let is_bloated = total_memory > memory_threshold_mb * 2.0
                    || (total_cpu > cpu_threshold_percent * 1.5 && max_cpu > 30.0);

                if is_bloated {
                    let severity = self.determine_bloat_severity(total_memory, max_cpu);
                    if severity >= self.min_severity {
                        let description = format!(
                            "{} (multi-process family, {} processes) uses {:.2} MB total memory and {:.2}% peak CPU per process ({:.2}% total).",
                            primary.1, members.len(), total_memory, max_cpu, total_cpu
                        );
                        let recommendation = get_context_aware_recommendation(&primary.1);

                        let finding = BloatFinding {
                            process_name: primary.1.clone(),
                            pid: primary.0,
                            memory_mb: total_memory,
                            cpu_percent: max_cpu,
                            startup_time_ms: 0,
                            dependencies: Vec::new(),
                            severity,
                            description,
                            recommendation,
                            alternative: None,
                        };

                        summary.total += 1;
                        match severity {
                            Severity::Critical => summary.critical += 1,
                            Severity::High => summary.high += 1,
                            Severity::Medium => summary.medium += 1,
                            Severity::Low => summary.low += 1,
                        }
                        findings.push(finding);
                    }
                }
            } else {
                let member = &members[0];
                let memory_mb = member.2;
                let cpu_percent = member.3;

                let is_bloated =
                    memory_mb > memory_threshold_mb || cpu_percent > cpu_threshold_percent;

                if is_bloated {
                    let severity = self.determine_bloat_severity(memory_mb, cpu_percent);
                    if severity >= self.min_severity {
                        let description = format!(
                            "{} is using {:.2} MB of memory and {:.2}% CPU.",
                            member.1, memory_mb, cpu_percent
                        );
                        let recommendation = get_context_aware_recommendation(&member.1);
                        let alternative = self.config.get_alternative(&member.1);

                        let finding = BloatFinding {
                            process_name: member.1.clone(),
                            pid: member.0,
                            memory_mb,
                            cpu_percent,
                            startup_time_ms: 0,
                            dependencies: Vec::new(),
                            severity,
                            description,
                            recommendation,
                            alternative,
                        };

                        summary.total += 1;
                        match severity {
                            Severity::Critical => summary.critical += 1,
                            Severity::High => summary.high += 1,
                            Severity::Medium => summary.medium += 1,
                            Severity::Low => summary.low += 1,
                        }
                        findings.push(finding);
                    }
                }
            }
        }

        if findings.is_empty() {
            Ok(None)
        } else {
            Ok(Some(BloatReport { findings, summary }))
        }
    }

    pub fn scan_permissions(&mut self) -> Result<Option<PermissionsReport>> {
        let mut findings = Vec::new();
        let mut summary = PermissionsSummary {
            total: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
        };

        let permission_patterns = self.config.get_permission_patterns();

        for (pid, process) in self.system.processes() {
            let process_name = process.name().to_string_lossy().to_string();

            if !self.include_system && is_system_process(&process_name) {
                continue;
            }

            if self.config.is_process_whitelisted(&process_name) {
                continue;
            }

            let permissions = self.check_process_permissions(pid.as_u32(), &permission_patterns)?;

            if !permissions.is_empty() {
                let severity = self.determine_permissions_severity(&permissions);

                if severity >= self.min_severity {
                    let finding = PermissionsFinding {
                        process_name: process_name.clone(),
                        pid: pid.as_u32(),
                        permissions,
                        severity,
                        description: self.get_permissions_description(&process_name),
                        recommendation: self.get_permissions_recommendation(&process_name),
                    };

                    summary.total += 1;
                    match severity {
                        Severity::Critical => summary.critical += 1,
                        Severity::High => summary.high += 1,
                        Severity::Medium => summary.medium += 1,
                        Severity::Low => summary.low += 1,
                    }

                    findings.push(finding);
                }
            }
        }

        if findings.is_empty() {
            Ok(None)
        } else {
            Ok(Some(PermissionsReport { findings, summary }))
        }
    }

    pub fn scan_startup(&mut self) -> Result<Option<StartupReport>> {
        startup::StartupScanner::scan()
    }

    fn get_process_connections(&self, pid: u32) -> Result<Option<Vec<NetworkConnection>>> {
        let mut connections = Vec::new();

        #[cfg(unix)]
        {
            let tcp_path = format!("/proc/{}/net/tcp", pid);
            if let Ok(content) = fs::read_to_string(&tcp_path) {
                for line in content.lines().skip(1) {
                    if let Some(conn) = parse_tcp_line(line) {
                        connections.push(conn);
                    }
                }
            }

            let udp_path = format!("/proc/{}/net/udp", pid);
            if let Ok(content) = fs::read_to_string(&udp_path) {
                for line in content.lines().skip(1) {
                    if let Some(conn) = parse_udp_line(line) {
                        connections.push(conn);
                    }
                }
            }
        }

        #[cfg(windows)]
        {
            if let Ok(conns) = windows::network::get_process_connections(pid) {
                connections = conns;
            }
        }

        if connections.is_empty() {
            Ok(None)
        } else {
            Ok(Some(connections))
        }
    }

    #[allow(dead_code)]
    fn get_process_dependencies(&self, pid: u32) -> Result<Vec<String>> {
        let dependencies = Vec::new();

        #[cfg(unix)]
        {
            let maps_path = format!("/proc/{}/maps", pid);
            if let Ok(content) = fs::read_to_string(&maps_path) {
                for line in content.lines() {
                    if let Some(path) = line.split_whitespace().nth(5) {
                        if path.contains(".so") && !dependencies.contains(&path.to_string()) {
                            dependencies.push(path.to_string());
                        }
                    }
                }
            }
        }

        #[cfg(windows)]
        {
            let _ = pid;
        }

        Ok(dependencies)
    }

    #[cfg(unix)]
    fn check_process_permissions(
        &self,
        pid: u32,
        patterns: &HashMap<String, Vec<String>>,
    ) -> Result<Vec<Permission>> {
        let mut seen: HashSet<String> = HashSet::new();
        let mut permissions: Vec<Permission> = Vec::new();

        let fd_path = format!("/proc/{}/fd", pid);
        if let Ok(entries) = fs::read_dir(&fd_path) {
            for entry in entries.flatten() {
                if let Ok(link) = fs::read_link(entry.path()) {
                    let link_str = link.to_string_lossy();

                    for (perm_type, perm_patterns) in patterns {
                        for pattern in perm_patterns {
                            if link_str.contains(pattern) {
                                let key = format!("{}:{}", perm_type, link_str);
                                if seen.insert(key) {
                                    permissions.push(Permission {
                                        permission_type: perm_type.clone(),
                                        description: format!("Accessing: {}", link_str),
                                        granted: true,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(permissions)
    }

    #[cfg(windows)]
    fn check_process_permissions(
        &self,
        _pid: u32,
        _patterns: &HashMap<String, Vec<String>>,
    ) -> Result<Vec<Permission>> {
        Ok(Vec::new())
    }

    fn determine_telemetry_severity(&self, process_name: &str, domains: &[String]) -> Severity {
        let known_telemetry_apps = vec![
            "chrome", "firefox", "edge", "brave", "vscode", "idea", "pycharm", "slack", "discord",
            "teams", "spotify", "steam",
        ];

        if known_telemetry_apps
            .iter()
            .any(|app| process_name.to_lowercase().contains(app))
        {
            if domains.len() > 5 {
                return Severity::Critical;
            } else if domains.len() > 2 {
                return Severity::High;
            }
        }

        if domains.len() > 10 {
            Severity::Critical
        } else if domains.len() > 5 {
            Severity::High
        } else if domains.len() > 2 {
            Severity::Medium
        } else {
            Severity::Low
        }
    }

    fn determine_bloat_severity(&self, memory_mb: f64, cpu_percent: f64) -> Severity {
        let memory_score = if memory_mb > 2000.0 {
            3
        } else if memory_mb > 1000.0 {
            2
        } else if memory_mb > 500.0 {
            1
        } else {
            0
        };
        let cpu_score = if cpu_percent > 80.0 {
            3
        } else if cpu_percent > 50.0 {
            2
        } else if cpu_percent > 20.0 {
            1
        } else {
            0
        };

        let total_score = memory_score + cpu_score;

        if total_score >= 5 {
            Severity::Critical
        } else if total_score >= 3 {
            Severity::High
        } else if total_score >= 1 {
            Severity::Medium
        } else {
            Severity::Low
        }
    }

    fn determine_permissions_severity(&self, permissions: &[Permission]) -> Severity {
        let critical_perms = vec!["camera", "microphone", "location", "contacts"];
        let high_perms = vec!["filesystem", "network", "clipboard"];

        let mut critical_count = 0;
        let mut high_count = 0;

        for perm in permissions {
            if critical_perms
                .iter()
                .any(|p| perm.permission_type.contains(p))
            {
                critical_count += 1;
            } else if high_perms.iter().any(|p| perm.permission_type.contains(p)) {
                high_count += 1;
            }
        }

        if critical_count > 0 {
            Severity::Critical
        } else if high_count > 2 {
            Severity::High
        } else if high_count > 0 {
            Severity::Medium
        } else {
            Severity::Low
        }
    }

    fn get_telemetry_description(&self, process_name: &str) -> String {
        format!(
            "{} is making connections to known telemetry domains and may be collecting usage data.",
            process_name
        )
    }

    fn get_telemetry_recommendation(&self, process_name: &str) -> String {
        format!(
            "Review {}'s privacy settings and disable telemetry if possible. Consider using privacy-focused alternatives.",
            process_name
        )
    }

    #[allow(dead_code)]
    fn get_bloat_description(
        &self,
        process_name: &str,
        memory_mb: f64,
        cpu_percent: f64,
    ) -> String {
        format!(
            "{} is using {:.2} MB of memory and {:.2}% CPU (per-core normalized).",
            process_name, memory_mb, cpu_percent
        )
    }

    #[allow(dead_code)]
    fn get_bloat_recommendation(&self, process_name: &str) -> String {
        get_context_aware_recommendation(process_name)
    }

    fn get_permissions_description(&self, process_name: &str) -> String {
        format!(
            "{} has access to sensitive resources that may not be necessary for its function.",
            process_name
        )
    }

    fn get_permissions_recommendation(&self, process_name: &str) -> String {
        format!(
            "Review {}'s permissions and revoke any unnecessary access through system settings.",
            process_name
        )
    }
}

fn is_system_process(process_name: &str) -> bool {
    #[cfg(unix)]
    {
        let system_processes = vec![
            "systemd",
            "init",
            "kthreadd",
            "ksoftirqd",
            "migration",
            "rcu_",
            "watchdog",
            "kworker",
            "kswapd",
            "ksmd",
            "khugepaged",
        ];
        system_processes.iter().any(|p| process_name.starts_with(p))
    }
    #[cfg(windows)]
    {
        let system_processes = vec![
            "System",
            "smss.exe",
            "csrss.exe",
            "wininit.exe",
            "services.exe",
            "lsass.exe",
            "svchost.exe",
            "winlogon.exe",
            "dwm.exe",
            "explorer.exe",
        ];
        system_processes.iter().any(|p| process_name == *p)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = process_name;
        false
    }
}

fn is_known_safe_process(process_name: &str) -> bool {
    let lower = process_name.to_lowercase();

    let known_safe = [
        "msmpeng.exe",
        "antimalware service executable",
        "memory compression",
        "csrss.exe",
        "wininit.exe",
        "lsass.exe",
        "services.exe",
        "svchost.exe",
        "corpaudit.exe",
        "corpaudit",
        "taskmgr.exe",
        "perfmon.exe",
        "conhost.exe",
        "runtimebroker.exe",
        "searchindexer.exe",
        "searchui.exe",
        "shellinfrastructurehost.exe",
        "startmenuexperiencehost.exe",
        "textinputhost.exe",
        "widgethost.exe",
        "fontdrvhost.exe",
        "sihost.exe",
        "ctfmon.exe",
        "dllhost.exe",
    ];

    known_safe.iter().any(|s| lower.contains(s))
}

fn get_process_family(process_name: &str) -> String {
    let lower = process_name.to_lowercase();

    let chromium_families = ["chrome", "brave", "edge", "opera", "vivaldi", "chromium"];
    for app in &chromium_families {
        if lower.contains(app) {
            return app.to_string();
        }
    }

    let electron_families = [
        "code",
        "code-insiders",
        "slack",
        "discord",
        "teams",
        "signal",
        "whatsapp",
        "obsidian",
        "notion",
    ];
    for app in &electron_families {
        if lower.contains(app) {
            return app.to_string();
        }
    }

    process_name.to_string()
}

fn get_context_aware_recommendation(process_name: &str) -> String {
    let lower = process_name.to_lowercase();

    // Chromium-based browsers
    let chromium_apps = ["chrome", "brave", "edge", "opera", "vivaldi", "chromium"];
    if chromium_apps.iter().any(|a| lower.contains(a)) {
        return format!(
            "{} uses a multi-process architecture for security and stability.\n\
             This is normal behavior, not bloat.\n\n\
             Actionable steps:\n\
             - Suspend unused tabs (right-click > 'Save memory')\n\
             - Disable unnecessary extensions (Settings > Extensions)\n\
             - Enable Memory Saver mode (Settings > Performance)\n\
             - Use 'Efficiency mode' for background tabs\n\
             - Consider reducing open tab count",
            process_name
        );
    }

    // Electron apps
    let electron_apps = [
        "code", "slack", "discord", "teams", "signal", "obsidian", "notion",
    ];
    if electron_apps.iter().any(|a| lower.contains(a)) {
        return format!(
            "{} is Electron-based and uses multiple processes by design.\n\
             This provides better security through process isolation.\n\n\
             Actionable steps:\n\
             - Disable unused extensions/plugins\n\
             - Close idle workspaces/channels\n\
             - Enable hardware acceleration (reduces CPU usage)\n\
             - Check for memory leaks in specific extensions\n\
             - Restart the app periodically to clear memory\n\
             - Consider native alternatives if resource usage is critical",
            process_name
        );
    }

    // Windows Defender
    if lower.contains("msmpeng") || lower.contains("defender") {
        return format!(
            "{} is Windows Defender's core security process.\n\
             WARNING: DO NOT DISABLE - this compromises system security.\n\n\
             To reduce impact legitimately:\n\
             - Add build/dev folder exclusions in Windows Security settings\n\
             - Schedule scans during off-hours\n\
             - Exclude source code folders from real-time scanning\n\
             - Consider 'Performance mode' in Windows Security settings",
            process_name
        );
    }

    // Memory Compression
    if lower.contains("memory compression") {
        return format!(
            "{} is a Windows optimization feature.\n\
             It compresses inactive memory pages to improve performance.\n\
             WARNING: Disabling it will WORSE performance, not improve it.\n\
             This is NOT bloat - it's a core Windows feature.",
            process_name
        );
    }

    // System services
    let safe_services = ["svchost", "runtimebroker", "searchindexer", "sihost", "csrss"];
    if safe_services.iter().any(|s| lower.contains(s)) {
        return format!(
            "{} is a core Windows system process.\n\
             WARNING: This is required for Windows to function properly.\n\
             Do not attempt to disable or modify this process.\n\n\
             If experiencing issues:\n\
             - Run 'sfc /scannow' to check for system file corruption\n\
             - Check for Windows Updates\n\
             - Scan for malware (legitimate processes shouldn't use excessive resources)",
            process_name
        );
    }

    // Generic recommendation
    format!(
        "Monitor {} over time to confirm sustained high usage.\n\
         Single snapshots may reflect temporary workload spikes.\n\n\
         General steps:\n\
         - Check if process is performing updates or background tasks\n\
         - Review process-specific settings for performance options\n\
         - Consider if the process is necessary for your workflow\n\
         - Look for lightweight alternatives if appropriate",
        process_name
    )
}

fn is_telemetry_connection(conn: &NetworkConnection, telemetry_domains: &[String]) -> bool {
    let resolved = resolve_domain(&conn.remote_address);
    if let Some(domain) = resolved {
        telemetry_domains
            .iter()
            .any(|d| domain.contains(d) || domain.to_lowercase().contains(&d.to_lowercase()))
    } else {
        false
    }
}

fn resolve_domain(address: &str) -> Option<String> {
    if address.parse::<std::net::IpAddr>().is_ok() {
        #[cfg(unix)]
        {
            Command::new("dig")
                .args(["-x", address, "+short"])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(|s| {
                    let trimmed = s.trim();
                    if trimmed.is_empty() {
                        // Fallback: return the IP address if dig fails or returns empty
                        Some(address.to_string())
                    } else {
                        Some(trimmed.to_string())
                    }
                })
                // Fallback if dig command fails entirely
                .or_else(|| Some(address.to_string()))
        }
        #[cfg(windows)]
        {
            Command::new("nslookup")
                .arg(address)
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(|s| {
                    s.lines()
                        .find(|l| l.to_lowercase().contains("name ="))
                        .and_then(|l| {
                            l.split('=')
                                .last()
                                .map(|s| s.trim().trim_end_matches('.').to_string())
                        })
                })
                // Fallback: return the IP address if nslookup fails
                .or_else(|| Some(address.to_string()))
        }
        #[cfg(not(any(unix, windows)))]
        {
            // Fallback for unknown platforms: just return the address
            Some(address.to_string())
        }
    } else {
        Some(address.to_string())
    }
}

#[allow(dead_code)]
fn parse_tcp_line(line: &str) -> Option<NetworkConnection> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }

    let local_addr = parse_socket_address(parts[1])?;
    let remote_addr = parse_socket_address(parts[2])?;

    Some(NetworkConnection {
        local_address: local_addr.0,
        local_port: local_addr.1,
        remote_address: remote_addr.0,
        remote_port: remote_addr.1,
        protocol: "TCP".to_string(),
        state: parts[3].to_string(),
        data_sent: None,
        data_received: None,
    })
}

#[allow(dead_code)]
fn parse_udp_line(line: &str) -> Option<NetworkConnection> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }

    let local_addr = parse_socket_address(parts[1])?;
    let remote_addr = parse_socket_address(parts[2])?;

    Some(NetworkConnection {
        local_address: local_addr.0,
        local_port: local_addr.1,
        remote_address: remote_addr.0,
        remote_port: remote_addr.1,
        protocol: "UDP".to_string(),
        state: parts[3].to_string(),
        data_sent: None,
        data_received: None,
    })
}

#[allow(dead_code)]
fn parse_socket_address(addr: &str) -> Option<(String, u16)> {
    let colon_pos = addr.rfind(':')?;
    let ip_hex = &addr[..colon_pos];
    let port_hex = &addr[colon_pos + 1..];

    let ip = if ip_hex.contains(':') {
        hex_to_ipv6(ip_hex)?
    } else {
        hex_to_ip(ip_hex)?
    };
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    Some((ip, port))
}

#[allow(dead_code)]
fn hex_to_ip(hex: &str) -> Option<String> {
    if hex.len() != 8 {
        return None;
    }

    let mut octets = [0u8; 4];
    for i in 0..4 {
        let start = i * 2;
        octets[3 - i] = u8::from_str_radix(&hex[start..start + 2], 16).ok()?;
    }

    Some(format!(
        "{}.{}.{}.{}",
        octets[0], octets[1], octets[2], octets[3]
    ))
}

#[allow(dead_code)]
fn hex_to_ipv6(hex: &str) -> Option<String> {
    if hex.len() != 32 {
        return None;
    }

    let mut groups = Vec::new();
    for i in 0..8 {
        let start = i * 4;
        let group = u16::from_str_radix(&hex[start..start + 4], 16).ok()?;
        groups.push(format!("{:x}", group));
    }

    Some(groups.join(":"))
}

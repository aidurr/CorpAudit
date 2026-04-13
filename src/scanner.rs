use crate::audit::*;
use crate::config::Config;
use anyhow::Result;
use std::collections::HashMap;
use std::collections::HashSet;
use std::process::Command;
use sysinfo::System;
use std::fs;

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

        for (pid, process) in self.system.processes() {
            let process_name = process.name().to_string_lossy().to_string();

            if !self.include_system && is_system_process(&process_name) {
                continue;
            }

            if let Some(connections) = self.get_process_connections(pid.as_u32())? {
                let mut telemetry_connections = Vec::new();
                let mut domains = Vec::new();
                let mut data_sent = 0u64;
                let mut data_received = 0u64;

                for conn in connections {
                    if is_telemetry_connection(&conn, &telemetry_domains) {
                        telemetry_connections.push(conn.clone());

                        if let Some(domain) = resolve_domain(&conn.remote_address) {
                            if !domains.contains(&domain) {
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

        for (pid, process) in self.system.processes() {
            let process_name = process.name().to_string_lossy().to_string();

            if !self.include_system && is_system_process(&process_name) {
                continue;
            }

            let memory_mb = process.memory() as f64 / 1_048_576.0; // Convert bytes to MB
            let cpu_percent = process.cpu_usage() as f64;

            let dependencies = self.get_process_dependencies(pid.as_u32())?;

            let is_bloated = memory_mb > memory_threshold_mb || cpu_percent > cpu_threshold_percent;

            if is_bloated {
                let severity = self.determine_bloat_severity(memory_mb, cpu_percent);

                if severity >= self.min_severity {
                    let alternative = self.config.get_alternative(&process_name);

                    let finding = BloatFinding {
                        process_name: process_name.clone(),
                        pid: pid.as_u32(),
                        memory_mb,
                        cpu_percent,
                        startup_time_ms: 0,
                        dependencies,
                        severity,
                        description: self.get_bloat_description(
                            &process_name,
                            memory_mb,
                            cpu_percent,
                        ),
                        recommendation: self.get_bloat_recommendation(&process_name),
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
            let _ = pid;
        }

        if connections.is_empty() {
            Ok(None)
        } else {
            Ok(Some(connections))
        }
    }

    fn get_process_dependencies(&self, pid: u32) -> Result<Vec<String>> {
        let mut dependencies = Vec::new();

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
        let memory_score = if memory_mb > 1000.0 {
            3
        } else if memory_mb > 500.0 {
            2
        } else if memory_mb > 200.0 {
            1
        } else {
            0
        };
        let cpu_score = if cpu_percent > 50.0 {
            3
        } else if cpu_percent > 20.0 {
            2
        } else if cpu_percent > 10.0 {
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

    fn get_bloat_description(
        &self,
        process_name: &str,
        memory_mb: f64,
        cpu_percent: f64,
    ) -> String {
        format!(
            "{} is using {:.2} MB of memory and {:.2}% CPU, indicating potential resource bloat.",
            process_name, memory_mb, cpu_percent
        )
    }

    fn get_bloat_recommendation(&self, process_name: &str) -> String {
        format!(
            "Consider optimizing {}'s settings or replacing it with a more efficient alternative.",
            process_name
        )
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
        // Default: don't filter any processes on unknown platforms
        let _ = process_name;
        false
    }
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

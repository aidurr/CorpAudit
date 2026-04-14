use crate::audit::*;
use crate::config::Config;
use crate::scanner::Scanner;
use anyhow::Result;
use chrono::Utc;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    pub scan_interval_seconds: u64,
    pub quick_scan_interval_seconds: u64,
    pub enable_notifications: bool,
    pub notification_method: NotificationType,
    pub alert_threshold: AlertThreshold,
    pub excluded_processes: HashSet<String>,
    pub watched_domains: Vec<String>,
    pub max_memory_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationType {
    Terminal,
    Log,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThreshold {
    pub new_telemetry_alert: bool,
    pub critical_telemetry_alert: bool,
    pub memory_spike_threshold_mb: f64,
    pub cpu_spike_threshold_percent: f64,
    pub new_process_alert: bool,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            scan_interval_seconds: 300,      // 5 minutes
            quick_scan_interval_seconds: 60, // 1 minute
            enable_notifications: true,
            notification_method: NotificationType::Terminal,
            alert_threshold: AlertThreshold {
                new_telemetry_alert: true,
                critical_telemetry_alert: true,
                memory_spike_threshold_mb: 100.0,
                cpu_spike_threshold_percent: 20.0,
                new_process_alert: false,
            },
            excluded_processes: HashSet::new(),
            watched_domains: Vec::new(),
            max_memory_percent: 5.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MonitorEvent {
    pub timestamp: String,
    pub event_type: MonitorEventType,
    pub process_name: String,
    pub pid: u32,
    pub details: String,
    pub severity: Severity,
}

#[derive(Debug, Clone)]
pub enum MonitorEventType {
    NewTelemetryDetected,
    TelemetryRemoved,
    MemorySpike,
    CPUSpike,
    NewProcessDetected,
    ProcessTerminated,
    CriticalFinding,
}

pub struct Monitor {
    config: MonitorConfig,
    scanner: Scanner,
    previous_report: Option<AuditReport>,
    known_pids: HashSet<u32>,
    last_scan_time: Option<Instant>,
}

impl Monitor {
    pub fn new(config: MonitorConfig, audit_config: Config) -> Result<Self> {
        let scanner = Scanner::new(
            audit_config,
            false,                // include_system
            "medium".to_string(), // min_severity
        );

        Ok(Self {
            config,
            scanner,
            previous_report: None,
            known_pids: HashSet::new(),
            last_scan_time: None,
        })
    }

    pub fn run(&mut self) -> Result<()> {
        info!("Starting CorpAudit monitor...");

        loop {
            let scan_start = Instant::now();

            match self.perform_scan() {
                Ok(report) => {
                    let events = self.detect_changes(&report);
                    self.dispatch_alerts(&events)?;
                    self.previous_report = Some(report);
                }
                Err(e) => {
                    warn!("Scan failed: {}", e);
                }
            }

            let elapsed = scan_start.elapsed();
            let interval = Duration::from_secs(self.config.scan_interval_seconds);

            if elapsed < interval {
                let sleep_time = interval - elapsed;
                info!("Next scan in {:.0} seconds", sleep_time.as_secs_f64());
                std::thread::sleep(sleep_time);
            }
        }
    }

    fn perform_scan(&mut self) -> Result<AuditReport> {
        info!("Performing scan...");

        let mut report = AuditReport::new();

        // Run all audits
        if let Some(telemetry_report) = self.scanner.scan_telemetry()? {
            report.telemetry = Some(telemetry_report);
        }

        if let Some(bloat_report) = self.scanner.scan_bloat()? {
            report.bloat = Some(bloat_report);
        }

        if let Some(permissions_report) = self.scanner.scan_permissions()? {
            report.permissions = Some(permissions_report);
        }

        self.last_scan_time = Some(Instant::now());

        Ok(report)
    }

    fn detect_changes(&mut self, current_report: &AuditReport) -> Vec<MonitorEvent> {
        let mut events = Vec::new();

        // Get current PIDs
        let current_pids: HashSet<u32> = self.get_current_pids(current_report);

        // Detect new processes
        if self.config.alert_threshold.new_process_alert {
            for pid in &current_pids {
                if !self.known_pids.contains(pid) {
                    if let Some(process_name) = self.get_process_name(current_report, *pid) {
                        events.push(MonitorEvent {
                            timestamp: Utc::now().to_rfc3339(),
                            event_type: MonitorEventType::NewProcessDetected,
                            process_name,
                            pid: *pid,
                            details: "New process detected".to_string(),
                            severity: Severity::Low,
                        });
                    }
                }
            }
        }

        // Detect telemetry changes
        if let (Some(prev), Some(curr)) = (&self.previous_report, &current_report.telemetry) {
            let prev_processes: HashSet<_> = prev.telemetry.as_ref().map_or(HashSet::new(), |t| {
                t.findings.iter().map(|f| f.process_name.clone()).collect()
            });

            let curr_processes: HashSet<_> = curr
                .findings
                .iter()
                .map(|f| f.process_name.clone())
                .collect();

            // New telemetry
            for process in &curr_processes {
                if !prev_processes.contains(process)
                    && self.config.alert_threshold.new_telemetry_alert
                {
                    if let Some(finding) = curr.findings.iter().find(|f| &f.process_name == process)
                    {
                        events.push(MonitorEvent {
                            timestamp: Utc::now().to_rfc3339(),
                            event_type: MonitorEventType::NewTelemetryDetected,
                            process_name: process.clone(),
                            pid: finding.pid,
                            details: format!(
                                "New telemetry detected: {} domains",
                                finding.domains.len()
                            ),
                            severity: finding.severity,
                        });
                    }
                }
            }

            // Removed telemetry
            for process in &prev_processes {
                if !curr_processes.contains(process) {
                    if let Some(finding) = prev
                        .telemetry
                        .as_ref()
                        .unwrap()
                        .findings
                        .iter()
                        .find(|f| &f.process_name == process)
                    {
                        events.push(MonitorEvent {
                            timestamp: Utc::now().to_rfc3339(),
                            event_type: MonitorEventType::TelemetryRemoved,
                            process_name: process.clone(),
                            pid: finding.pid,
                            details: "Telemetry connections removed".to_string(),
                            severity: Severity::Low,
                        });
                    }
                }
            }
        }

        // Detect critical findings
        if current_report.has_critical_issues()
            && self.config.alert_threshold.critical_telemetry_alert
        {
            if let Some(ref telemetry) = current_report.telemetry {
                for finding in &telemetry.findings {
                    if finding.severity == Severity::Critical {
                        events.push(MonitorEvent {
                            timestamp: Utc::now().to_rfc3339(),
                            event_type: MonitorEventType::CriticalFinding,
                            process_name: finding.process_name.clone(),
                            pid: finding.pid,
                            details: "Critical telemetry finding detected".to_string(),
                            severity: Severity::Critical,
                        });
                    }
                }
            }
        }

        // Update known PIDs
        self.known_pids = current_pids;

        events
    }

    fn dispatch_alerts(&self, events: &[MonitorEvent]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        match self.config.notification_method {
            NotificationType::Terminal => {
                self.print_terminal_alerts(events);
            }
            NotificationType::Log => {
                self.log_alerts(events)?;
            }
        }

        Ok(())
    }

    fn print_terminal_alerts(&self, events: &[MonitorEvent]) {
        use colored::Colorize;

        println!(
            "\n{}",
            "══════════════════════════════════════════════════".cyan()
        );
        println!("{}", "CorpAudit Monitor Alert".cyan().bold());
        println!(
            "{}",
            "══════════════════════════════════════════════════".cyan()
        );

        for event in events {
            let severity_str = match event.severity {
                Severity::Critical => "[CRITICAL]".red().bold().to_string(),
                Severity::High => "[HIGH]".bright_red().to_string(),
                Severity::Medium => "[MEDIUM]".yellow().to_string(),
                Severity::Low => "[LOW]".green().to_string(),
            };

            let event_type_str = match event.event_type {
                MonitorEventType::NewTelemetryDetected => "New Telemetry",
                MonitorEventType::TelemetryRemoved => "Telemetry Removed",
                MonitorEventType::MemorySpike => "Memory Spike",
                MonitorEventType::CPUSpike => "CPU Spike",
                MonitorEventType::NewProcessDetected => "New Process",
                MonitorEventType::ProcessTerminated => "Process Terminated",
                MonitorEventType::CriticalFinding => "Critical Finding",
            };

            println!("\n{} {}", severity_str, event_type_str);
            println!("  Process: {} (PID: {})", event.process_name, event.pid);
            println!("  Details: {}", event.details);
            println!("  Time: {}", &event.timestamp[..19]);
        }

        println!(
            "\n{}",
            "══════════════════════════════════════════════════\n".cyan()
        );
    }

    fn log_alerts(&self, events: &[MonitorEvent]) -> Result<()> {
        for event in events {
            info!(
                "[{:?}] {} - {} (PID: {}): {}",
                event.severity,
                match event.event_type {
                    MonitorEventType::NewTelemetryDetected => "New Telemetry",
                    MonitorEventType::TelemetryRemoved => "Telemetry Removed",
                    MonitorEventType::MemorySpike => "Memory Spike",
                    MonitorEventType::CPUSpike => "CPU Spike",
                    MonitorEventType::NewProcessDetected => "New Process",
                    MonitorEventType::ProcessTerminated => "Process Terminated",
                    MonitorEventType::CriticalFinding => "Critical Finding",
                },
                event.process_name,
                event.pid,
                event.details
            );
        }

        Ok(())
    }

    fn get_current_pids(&self, report: &AuditReport) -> HashSet<u32> {
        let mut pids = HashSet::new();

        if let Some(ref telemetry) = report.telemetry {
            for finding in &telemetry.findings {
                pids.insert(finding.pid);
            }
        }

        if let Some(ref bloat) = report.bloat {
            for finding in &bloat.findings {
                pids.insert(finding.pid);
            }
        }

        if let Some(ref permissions) = report.permissions {
            for finding in &permissions.findings {
                pids.insert(finding.pid);
            }
        }

        pids
    }

    fn get_process_name(&self, report: &AuditReport, pid: u32) -> Option<String> {
        if let Some(ref telemetry) = report.telemetry {
            if let Some(finding) = telemetry.findings.iter().find(|f| f.pid == pid) {
                return Some(finding.process_name.clone());
            }
        }

        if let Some(ref bloat) = report.bloat {
            if let Some(finding) = bloat.findings.iter().find(|f| f.pid == pid) {
                return Some(finding.process_name.clone());
            }
        }

        if let Some(ref permissions) = report.permissions {
            if let Some(finding) = permissions.findings.iter().find(|f| f.pid == pid) {
                return Some(finding.process_name.clone());
            }
        }

        None
    }
}

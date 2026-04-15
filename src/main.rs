use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use log::{error, info, warn};
use std::path::PathBuf;
use std::process;

mod alternatives;
mod audit;
mod baseline;
mod blocker;
mod comparison;
mod config;
mod export;
mod fix;
mod gui;
mod history;
mod manifest;
mod monitor;
mod scanner;
mod scheduler;
mod scorer;
mod startup;
mod traffic;
mod tree;
mod visualization;
#[cfg(windows)]
mod windows;

use alternatives::AlternativesDb;
use audit::AuditReport;
use baseline::BaselineManager;
use comparison::DiffEngine;
use config::Config;
use export::export_report;
use history::HistoryManager;
use manifest::FixManifest;
use monitor::{Monitor, MonitorConfig};
use scanner::Scanner;
use scheduler::Scheduler;
use scorer::{PrivacyScorer, ThreatModel};
use traffic::TrafficAnalyzer;
use visualization::TrafficVisualizer;

#[derive(Parser, Debug)]
#[command(
    name = "CorpAudit",
    author = "CorpAudit Contributors",
    version = "0.1.0",
    about = "Audit corporate bloat, telemetry, and privacy violations on your system",
    long_about = "CorpAudit - See what's spying, bloating, or enslaving your system. Then fix it.

Built with privacy and transparency in mind. No telemetry, no cloud dependencies, no vendor lock-in.

Why we built this:
- Corporate software increasingly ships with hidden telemetry and data collection
- Modern applications are bloated with unnecessary features and dependencies
- Users deserve transparency about what's running on their systems
- Privacy should be the default, not an afterthought

This tool gives you the power to audit, understand, and reclaim control over your digital environment."
)]
struct Args {
    /// Scan for telemetry and data collection
    #[arg(short, long)]
    telemetry: bool,

    /// Detect resource-heavy and bloated applications
    #[arg(short, long)]
    bloat: bool,

    /// Audit application permissions and access
    #[arg(short, long)]
    permissions: bool,

    /// Run all audits (default)
    #[arg(short, long)]
    all: bool,

    /// Generate fix scripts (non-destructive by default)
    #[arg(short, long)]
    fix: bool,

    /// Apply fixes automatically (use with caution)
    #[arg(long)]
    apply: bool,

    /// Safe mode - no destructive operations
    #[arg(short, long)]
    safe: bool,

    /// Output format (text, json, markdown)
    #[arg(short, long, default_value = "text")]
    format: String,

    /// Output file path
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Quiet mode - only show results
    #[arg(short, long)]
    quiet: bool,

    /// Include system processes in audit
    #[arg(long)]
    include_system: bool,

    /// Minimum severity level to report (low, medium, high, critical)
    #[arg(long, default_value = "medium")]
    severity: String,

    // === New feature: History ===
    /// Show scan history (last 10 scans)
    #[arg(long)]
    history: bool,

    /// Show history for last N days
    #[arg(long, default_value = "30")]
    history_days: u32,

    /// Analyze trends over last N days
    #[arg(long)]
    trend_days: Option<u32>,

    // === New feature: Privacy Score ===
    /// Calculate and display privacy score
    #[arg(long)]
    score: bool,

    /// Set threat model (balanced, paranoid, casual, enterprise, gaming)
    #[arg(long, default_value = "balanced")]
    threat_model: String,

    // === New feature: Traffic Visualization ===
    /// Show network traffic visualization
    #[arg(long)]
    traffic: bool,

    // === New feature: Comparison ===
    /// Compare two report files
    #[arg(long, num_args = 2)]
    compare: Option<Vec<String>>,

    // === New feature: Monitor ===
    /// Start real-time monitoring
    #[arg(long)]
    monitor: bool,

    /// Set monitor interval in seconds
    #[arg(long, default_value = "300")]
    monitor_interval: u64,

    // === Whitelist Management ===
    /// Add process to whitelist
    #[arg(long)]
    whitelist_add_process: Option<String>,

    /// Add domain to whitelist
    #[arg(long)]
    whitelist_add_domain: Option<String>,

    /// Remove process from whitelist
    #[arg(long)]
    whitelist_remove_process: Option<String>,

    /// Remove domain from whitelist
    #[arg(long)]
    whitelist_remove_domain: Option<String>,

    /// Show current whitelist
    #[arg(long)]
    whitelist_show: bool,

    // === Startup Audit ===
    /// Audit startup services and programs
    #[arg(long)]
    startup: bool,

    // === Process Tree ===
    /// Show process tree for telemetry processes
    #[arg(long)]
    tree: bool,

    // === Baseline ===
    /// Save current scan as baseline
    #[arg(long)]
    baseline_save: bool,

    /// Compare current scan against saved baseline
    #[arg(long)]
    baseline_compare: bool,

    // === Network Blocking ===
    /// Generate firewall rules to block telemetry
    #[arg(long)]
    block: bool,

    // === Scheduler ===
    /// Schedule automated scans (daily, weekly, monthly)
    #[arg(long)]
    schedule: Option<String>,

    /// List scheduled scans
    #[arg(long)]
    schedule_list: bool,

    /// Remove scheduled scan by name
    #[arg(long)]
    schedule_remove: Option<String>,

    // === Timeline ===
    /// Show resource usage timeline
    #[arg(long)]
    timeline: bool,

    // === Alternatives ===
    /// Browse privacy-focused software alternatives
    #[arg(long)]
    alternatives: Option<String>,

    // === Dashboard ===
    /// Launch interactive TUI dashboard
    #[arg(long)]
    dashboard: bool,

    /// Launch GUI
    #[arg(long)]
    gui: bool,

    // === Export ===
    /// Export report to file (json or html)
    #[arg(long)]
    export_report: Option<String>,

    /// Export format (json/html)
    #[arg(long, default_value = "json")]
    export_format: String,

    // === System Restore ===
    /// Create system restore point before applying fixes
    #[arg(long)]
    restore_point: bool,

    // === Fix Manifest ===
    /// Generate fix manifest (safe/unsafe classification)
    #[arg(long)]
    fix_manifest: bool,

    // === Version Detection ===
    /// Show Windows version and telemetry profile
    #[arg(long)]
    version_info: bool,
}

fn main() {
    let args = Args::parse();

    // Setup logging
    let log_level = if args.verbose {
        log::LevelFilter::Debug
    } else if args.quiet {
        log::LevelFilter::Error
    } else {
        log::LevelFilter::Info
    };

    env_logger::Builder::from_default_env()
        .filter_level(log_level)
        .init();

    // Handle new features that don't require running a scan first

    // Whitelist management
    if args.whitelist_show {
        match show_whitelist() {
            Ok(_) => process::exit(0),
            Err(e) => {
                error!("Failed to show whitelist: {}", e);
                process::exit(1);
            }
        }
    }

    if let Some(ref process) = args.whitelist_add_process {
        match manage_whitelist("add_process", process) {
            Ok(_) => process::exit(0),
            Err(e) => {
                error!("Failed to add to whitelist: {}", e);
                process::exit(1);
            }
        }
    }

    if let Some(ref domain) = args.whitelist_add_domain {
        match manage_whitelist("add_domain", domain) {
            Ok(_) => process::exit(0),
            Err(e) => {
                error!("Failed to add to whitelist: {}", e);
                process::exit(1);
            }
        }
    }

    if let Some(ref process) = args.whitelist_remove_process {
        match manage_whitelist("remove_process", process) {
            Ok(_) => process::exit(0),
            Err(e) => {
                error!("Failed to remove from whitelist: {}", e);
                process::exit(1);
            }
        }
    }

    if let Some(ref domain) = args.whitelist_remove_domain {
        match manage_whitelist("remove_domain", domain) {
            Ok(_) => process::exit(0),
            Err(e) => {
                error!("Failed to remove from whitelist: {}", e);
                process::exit(1);
            }
        }
    }

    // Baseline save
    if args.baseline_save {
        match save_baseline() {
            Ok(_) => process::exit(0),
            Err(e) => {
                error!("Failed to save baseline: {}", e);
                process::exit(1);
            }
        }
    }

    // Baseline compare
    if args.baseline_compare {
        match compare_baseline() {
            Ok(_) => process::exit(0),
            Err(e) => {
                error!("Failed to compare baseline: {}", e);
                process::exit(1);
            }
        }
    }

    // Scheduler management
    if args.schedule_list {
        match list_schedules() {
            Ok(_) => process::exit(0),
            Err(e) => {
                error!("Failed to list schedules: {}", e);
                process::exit(1);
            }
        }
    }

    if let Some(ref name) = args.schedule_remove {
        match remove_schedule(name) {
            Ok(_) => process::exit(0),
            Err(e) => {
                error!("Failed to remove schedule: {}", e);
                process::exit(1);
            }
        }
    }

    if let Some(ref frequency) = args.schedule {
        match create_schedule(frequency) {
            Ok(_) => process::exit(0),
            Err(e) => {
                error!("Failed to create schedule: {}", e);
                process::exit(1);
            }
        }
    }

    // Alternatives browser
    if let Some(ref search) = args.alternatives {
        match browse_alternatives(search) {
            Ok(_) => process::exit(0),
            Err(e) => {
                error!("Failed to browse alternatives: {}", e);
                process::exit(1);
            }
        }
    }

    // History display
    if args.history {
        match display_history(args.history_days) {
            Ok(_) => process::exit(0),
            Err(e) => {
                error!("Failed to display history: {}", e);
                process::exit(1);
            }
        }
    }

    // Trend analysis
    if let Some(days) = args.trend_days {
        match display_trends(days) {
            Ok(_) => process::exit(0),
            Err(e) => {
                error!("Failed to analyze trends: {}", e);
                process::exit(1);
            }
        }
    }

    // Comparison
    if let Some(ref files) = args.compare {
        if files.len() == 2 {
            match compare_files(&files[0], &files[1]) {
                Ok(_) => process::exit(0),
                Err(e) => {
                    error!("Failed to compare files: {}", e);
                    process::exit(1);
                }
            }
        }
    }

    // Print banner
    if !args.quiet && !args.monitor {
        print_banner();
    }

    // GUI mode
    if args.gui {
        if let Err(e) = gui::run_gui() {
            error!("GUI failed: {}", e);
            process::exit(1);
        }
        process::exit(0);
    }

    // Version info
    if args.version_info {
        match show_version_info() {
            Ok(_) => process::exit(0),
            Err(e) => {
                error!("Failed to get version info: {}", e);
                process::exit(1);
            }
        }
    }

    // Monitoring mode
    if args.monitor {
        match run_monitor(&args) {
            Ok(_) => process::exit(0),
            Err(e) => {
                error!("Monitoring failed: {}", e);
                process::exit(1);
            }
        }
    }

    // Run audit
    match run_audit(&args) {
        Ok(report) => {
            if !args.quiet {
                println!("\n{}", "✓ Audit completed successfully".green().bold());
            }

            // Output report
            if let Err(e) = output_report(&report, &args) {
                error!("Failed to output report: {}", e);
                process::exit(1);
            }

            // Exit with appropriate code
            if report.has_critical_issues() {
                process::exit(2);
            } else if report.has_issues() {
                process::exit(1);
            } else {
                process::exit(0);
            }
        }
        Err(e) => {
            error!("{}", format!("✗ Audit failed: {}", e).red().bold());
            process::exit(1);
        }
    }
}

fn print_banner() {
    let banner = r"
  /$$$$$$                                 /$$$$$$                  /$$ /$$   /$$
 /$$__  $$                               /$$__  $$                | $$|__/  | $$
| $$  \__/  /$$$$$$   /$$$$$$   /$$$$$$ | $$  \ $$ /$$   /$$  /$$$$$$$ /$$ /$$$$$$
| $$       /$$__  $$ /$$__  $$ /$$__  $$| $$$$$$$$| $$  | $$ /$$__  $$| $$|_  $$_/
| $$      | $$  \ $$| $$  \__/| $$  \ $$| $$__  $$| $$  | $$| $$  | $$| $$  | $$
| $$    $$| $$  | $$| $$      | $$  | $$| $$  | $$| $$  | $$| $$  | $$| $$  | $$ /$$
|  $$$$$$/|  $$$$$$/| $$      | $$$$$$$/| $$  | $$|  $$$$$$/|  $$$$$$$| $$  |  $$$$/
 \______/  \______/ |__/      | $$____/ |__/  |__/ \______/  \_______/|__/   \___/
                              | $$
                              | $$
                              |__/

                   A U D I T   T O O L

  See what's spying, bloating, or enslaving your system.
  Then fix it.
"
    .to_string()
    .cyan();
    println!("{}", banner);
}

fn validate_args(args: &Args) -> Result<()> {
    let valid_formats = ["text", "json", "markdown", "html"];
    if !valid_formats.contains(&args.format.as_str()) {
        anyhow::bail!(
            "Invalid format '{}'. Valid formats: text, json, markdown, html",
            args.format
        );
    }

    if args.apply && !args.fix {
        anyhow::bail!("--apply requires --fix to generate fixes first. Use: --fix --apply");
    }

    if args.apply && args.safe {
        anyhow::bail!("--apply cannot be used with --safe. --safe prevents applying fixes.");
    }

    Ok(())
}

fn run_audit(args: &Args) -> Result<AuditReport> {
    validate_args(args)?;

    let config = Config::load_or_default()?;

    // Determine what to scan
    let scan_telemetry = args.telemetry || args.all;
    let scan_bloat = args.bloat || args.all;
    let scan_permissions = args.permissions || args.all;

    // Default to all scans if nothing specified
    let scan_all = !scan_telemetry && !scan_bloat && !scan_permissions;

    let mut scanner = Scanner::new(config, args.include_system, args.severity.clone());

    let mut report = AuditReport::new();

    if scan_all || scan_telemetry {
        info!("Scanning for telemetry and data collection...");
        if let Some(telemetry_report) = scanner.scan_telemetry()? {
            report.telemetry = Some(telemetry_report);
        }
    }

    if scan_all || scan_bloat {
        info!("Detecting bloated applications...");
        if let Some(bloat_report) = scanner.scan_bloat()? {
            report.bloat = Some(bloat_report);
        }
    }

    if scan_all || scan_permissions {
        info!("Auditing application permissions...");
        if let Some(permissions_report) = scanner.scan_permissions()? {
            report.permissions = Some(permissions_report);
        }
    }

    if args.startup {
        info!("Auditing startup services...");
        if let Some(startup_report) = scanner.scan_startup()? {
            report.startup = Some(startup_report);
        }
    }

    // Generate fixes if requested
    if args.fix {
        info!("Generating fix scripts...");
        report.fixes = Some(fix::generate_fixes(&report, args.safe)?);
    }

    // Apply fixes if requested
    if args.apply && !args.safe {
        if let Some(ref fixes) = report.fixes {
            // Create restore point if requested
            if args.restore_point {
                info!("Creating system restore point...");
                #[cfg(windows)]
                {
                    match windows::version::create_system_restore_point("Pre-CorpAudit Fix Application") {
                        Ok(true) => info!("✓ System restore point created successfully"),
                        Ok(false) => warn!("⚠ Failed to create restore point - continuing anyway"),
                        Err(e) => warn!("⚠ Restore point error: {} - continuing anyway", e),
                    }
                }
                #[cfg(not(windows))]
                {
                    warn!("System restore points only supported on Windows");
                }
            }

            info!("Applying fixes...");
            fix::apply_fixes(fixes)?;
        }
    }

    // Save to history
    if let Err(e) = save_to_history(&report) {
        warn!("Failed to save scan to history: {}", e);
    }

    // Export report if requested
    if let Some(ref export_path) = args.export_report {
        match export_report(&report, &args.export_format, export_path) {
            Ok(_) => info!("Report exported to {}", export_path),
            Err(e) => warn!("Failed to export report: {}", e),
        }
    }

    // Generate fix manifest if requested
    if args.fix_manifest {
        if let Some(ref fixes) = report.fixes {
            let manifest = FixManifest::generate(fixes);
            let manifest_summary = manifest.to_summary();
            println!("\n{}", manifest_summary);

            // Also save to file
            let manifest_path = "fix-manifest.json";
            if let Ok(json) = serde_json::to_string_pretty(&manifest) {
                if let Err(e) = std::fs::write(manifest_path, json) {
                    warn!("Failed to write manifest file: {}", e);
                } else {
                    info!("Fix manifest saved to {}", manifest_path);
                }
            }
        }
    }

    // Display privacy score if requested
    if args.score {
        let threat_model = parse_threat_model(&args.threat_model);
        let score = PrivacyScorer::calculate_score(&report, threat_model);
        let score_display = TrafficVisualizer::render_score_display(&score);
        println!("\n{}", score_display);

        // Also show recommendations
        let recommendations = PrivacyScorer::generate_recommendations(&score);
        if !recommendations.is_empty() {
            println!("\nRecommendations:");
            for rec in &recommendations {
                println!("  • {}", rec);
            }
        }
    }

    // Display traffic visualization if requested
    if args.traffic {
        let traffic_report = TrafficAnalyzer::analyze_traffic(&report.telemetry, &report.bloat);
        let traffic_display = TrafficVisualizer::render_traffic_report(&traffic_report);
        println!("\n{}", traffic_display);
    }

    // Display process tree if requested
    if args.tree {
        let tree_display = tree::render_process_tree(&report);
        println!("\n{}", tree_display);
    }

    // Generate firewall block rules if requested
    if args.block {
        let rules = blocker::generate_block_rules(&report)?;
        println!("\n{}", rules);
    }

    // Display timeline if requested
    if args.timeline {
        match display_timeline() {
            Ok(_) => {}
            Err(e) => warn!("Failed to display timeline: {}", e),
        }
    }

    Ok(report)
}

fn save_to_history(report: &AuditReport) -> Result<()> {
    let history_manager = HistoryManager::new()?;
    history_manager.save_scan_report(report)?;
    Ok(())
}

fn parse_threat_model(model: &str) -> ThreatModel {
    match model.to_lowercase().as_str() {
        "paranoid" => ThreatModel::Paranoid,
        "casual" => ThreatModel::Casual,
        "enterprise" => ThreatModel::Enterprise,
        "gaming" => ThreatModel::Gaming,
        _ => ThreatModel::Balanced,
    }
}

fn output_report(report: &AuditReport, args: &Args) -> Result<()> {
    let output = match args.format.as_str() {
        "json" => serde_json::to_string_pretty(report)?,
        "markdown" => report.to_markdown(),
        "html" => report.to_html(),
        "text" | _ => report.to_text(),
    };

    if let Some(ref path) = args.output {
        std::fs::write(path, &output)
            .context(format!("Failed to write report to {}", path.display()))?;
        info!("Report written to {}", path.display());
    } else {
        println!("\n{}", output);
    }

    Ok(())
}

// === New feature functions ===

fn display_history(days: u32) -> Result<()> {
    let history_manager = HistoryManager::new()?;
    let histories = history_manager.load_history(days)?;

    if histories.is_empty() {
        println!("No scan history available for the last {} days", days);
        return Ok(());
    }

    let output = TrafficVisualizer::render_history_table(&histories);
    println!("\n{}", output);

    Ok(())
}

fn display_trends(days: u32) -> Result<()> {
    let history_manager = HistoryManager::new()?;
    let analysis = history_manager.analyze_trends(days)?;

    let output = TrafficVisualizer::render_trend_analysis(&analysis);
    println!("\n{}", output);

    Ok(())
}

fn compare_files(file1: &str, file2: &str) -> Result<()> {
    // Load both reports
    let baseline_content =
        std::fs::read_to_string(file1).context(format!("Failed to read {}", file1))?;
    let current_content =
        std::fs::read_to_string(file2).context(format!("Failed to read {}", file2))?;

    let baseline: AuditReport =
        serde_json::from_str(&baseline_content).context(format!("Failed to parse {}", file1))?;
    let current: AuditReport =
        serde_json::from_str(&current_content).context(format!("Failed to parse {}", file2))?;

    // Compare
    let comparison = DiffEngine::compare_reports(&baseline, &current)?;

    // Output
    let output = TrafficVisualizer::render_comparison_summary(&comparison);
    println!("\n{}", output);

    Ok(())
}

fn run_monitor(args: &Args) -> Result<()> {
    let config = Config::load_or_default()?;

    let monitor_config = MonitorConfig {
        scan_interval_seconds: args.monitor_interval,
        enable_notifications: config.enable_notifications,
        ..Default::default()
    };

    let mut monitor = Monitor::new(monitor_config, config)?;

    println!("{}", "Starting CorpAudit Monitor...".cyan().bold());
    println!("Press Ctrl+C to stop monitoring\n");

    monitor.run()
}

fn show_whitelist() -> Result<()> {
    let config = Config::load_or_default()?;

    println!("\nWhitelisted Processes:");
    if config.whitelisted_processes.is_empty() {
        println!("  (none)");
    } else {
        for p in &config.whitelisted_processes {
            println!("  - {}", p);
        }
    }

    println!("\nWhitelisted Domains:");
    if config.whitelisted_domains.is_empty() {
        println!("  (none)");
    } else {
        for d in &config.whitelisted_domains {
            println!("  - {}", d);
        }
    }

    Ok(())
}

fn manage_whitelist(action: &str, value: &str) -> Result<()> {
    let mut config = Config::load_or_default()?;

    match action {
        "add_process" => {
            if config.add_process_to_whitelist(value.to_string()) {
                println!("Added '{}' to process whitelist", value);
            } else {
                println!("'{}' is already in the process whitelist", value);
            }
        }
        "add_domain" => {
            if config.add_domain_to_whitelist(value.to_string()) {
                println!("Added '{}' to domain whitelist", value);
            } else {
                println!("'{}' is already in the domain whitelist", value);
            }
        }
        "remove_process" => {
            if config.remove_process_from_whitelist(value) {
                println!("Removed '{}' from process whitelist", value);
            } else {
                println!("'{}' not found in process whitelist", value);
            }
        }
        "remove_domain" => {
            if config.remove_domain_from_whitelist(value) {
                println!("Removed '{}' from domain whitelist", value);
            } else {
                println!("'{}' not found in domain whitelist", value);
            }
        }
        _ => anyhow::bail!("Unknown whitelist action: {}", action),
    }

    config.save()?;
    Ok(())
}

fn save_baseline() -> Result<()> {
    let config = Config::load_or_default()?;
    let mut scanner = Scanner::new(config, false, "medium".to_string());
    let mut report = AuditReport::new();

    if let Some(telemetry_report) = scanner.scan_telemetry()? {
        report.telemetry = Some(telemetry_report);
    }
    if let Some(bloat_report) = scanner.scan_bloat()? {
        report.bloat = Some(bloat_report);
    }
    if let Some(permissions_report) = scanner.scan_permissions()? {
        report.permissions = Some(permissions_report);
    }

    let manager = BaselineManager::new()?;
    manager.save_baseline(&report)?;

    println!("{}", "Baseline saved successfully".green().bold());
    Ok(())
}

fn compare_baseline() -> Result<()> {
    let config = Config::load_or_default()?;
    let mut scanner = Scanner::new(config, false, "medium".to_string());
    let mut report = AuditReport::new();

    if let Some(telemetry_report) = scanner.scan_telemetry()? {
        report.telemetry = Some(telemetry_report);
    }
    if let Some(bloat_report) = scanner.scan_bloat()? {
        report.bloat = Some(bloat_report);
    }
    if let Some(permissions_report) = scanner.scan_permissions()? {
        report.permissions = Some(permissions_report);
    }

    let manager = BaselineManager::new()?;
    let baseline = manager.load_baseline()?;

    if let Some(baseline_report) = baseline {
        let comparison = DiffEngine::compare_reports(&baseline_report, &report)?;
        let output = TrafficVisualizer::render_comparison_summary(&comparison);
        println!("\n{}", output);
    } else {
        println!("No baseline found. Run --baseline-save first.");
    }

    Ok(())
}

fn create_schedule(frequency: &str) -> Result<()> {
    let scheduler = Scheduler::new()?;
    scheduler.create_schedule(frequency)?;
    println!("Schedule '{}' created successfully", frequency);
    Ok(())
}

fn list_schedules() -> Result<()> {
    let scheduler = Scheduler::new()?;
    let schedules = scheduler.list_schedules()?;

    if schedules.is_empty() {
        println!("No scheduled scans configured.");
    } else {
        println!("\nScheduled Scans:");
        for (name, desc) in schedules {
            println!("  - {}: {}", name, desc);
        }
    }

    Ok(())
}

fn remove_schedule(name: &str) -> Result<()> {
    let scheduler = Scheduler::new()?;
    if scheduler.remove_schedule(name)? {
        println!("Schedule '{}' removed.", name);
    } else {
        println!("Schedule '{}' not found.", name);
    }
    Ok(())
}

fn display_timeline() -> Result<()> {
    let history_manager = HistoryManager::new()?;
    let timeline_data = history_manager.load_timeline(30)?;

    if timeline_data.is_empty() {
        println!("No timeline data available. Run multiple scans to generate timeline data.");
        return Ok(());
    }

    let output = TrafficVisualizer::render_timeline(&timeline_data);
    println!("\n{}", output);

    Ok(())
}

fn browse_alternatives(search: &str) -> Result<()> {
    let db = AlternativesDb::load()?;
    let results = db.search(search);

    if results.is_empty() {
        println!("No alternatives found for '{}'", search);
    } else {
        println!("\nPrivacy-Focused Alternatives for '{}':\n", search);
        for alt in results {
            println!("  {} -> {}", alt.original.bold(), alt.alternatives.green());
            if !alt.notes.is_empty() {
                println!("    Note: {}", alt.notes);
            }
            println!();
        }
    }

    Ok(())
}

fn show_version_info() -> Result<()> {
    #[cfg(windows)]
    {
        let win_version = windows::version::WindowsVersion::detect()?;

        println!("\n{}", "Windows Version Information".cyan().bold());
        println!("{}", "=".repeat(50));
        println!("Edition: {}", win_version.edition);
        println!("Build: {} ({}.{}.{})", win_version.build, win_version.major, win_version.minor, win_version.build);
        println!("Display Version: {}", win_version.display_version);
        println!("Windows 11: {}", if win_version.is_windows_11 { "Yes ✓" } else { "No ✗" });
        println!();

        if win_version.is_windows_11 {
            println!("{}", "Telemetry Profile:".yellow().bold());
            println!("{}", win_version.get_telemetry_profile());
            println!();
            println!("{}", "Recommended Actions:".yellow().bold());
            for action in win_version.get_recommended_actions() {
                println!("  • {}", action);
            }
        } else {
            println!("{}", "Warning: CorpAudit is optimized for Windows 11".yellow().bold());
            println!("Some fixes may not apply to Windows 10");
        }
        println!();

        // Readiness verdict
        println!("{}", "Readiness Verdict:".green().bold());
        if win_version.build >= 22000 {
            println!("  ✅ System ready for CorpAudit Windows 11 features");
        } else {
            println!("  ⚠️ Windows 10 detected - limited feature support");
        }
        println!();
    }

    #[cfg(not(windows))]
    {
        println!("{}", "Version detection only available on Windows".yellow());
    }

    Ok(())
}

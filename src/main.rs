use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use log::{error, info, warn};
use std::path::PathBuf;
use std::process;

mod audit;
mod config;
mod fix;
mod scanner;
mod history;
mod scorer;
mod comparison;
mod traffic;
mod visualization;
mod monitor;
#[cfg(windows)]
mod windows;

use audit::AuditReport;
use config::Config;
use scanner::Scanner;
use history::HistoryManager;
use scorer::{PrivacyScorer, ThreatModel};
use comparison::DiffEngine;
use traffic::TrafficAnalyzer;
use visualization::TrafficVisualizer;
use monitor::{Monitor, MonitorConfig};

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
    let valid_formats = ["text", "json", "markdown"];
    if !valid_formats.contains(&args.format.as_str()) {
        anyhow::bail!(
            "Invalid format '{}'. Valid formats: text, json, markdown",
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

    // Generate fixes if requested
    if args.fix {
        info!("Generating fix scripts...");
        report.fixes = Some(fix::generate_fixes(&report, args.safe)?);
    }

    // Apply fixes if requested
    if args.apply && !args.safe {
        if let Some(ref fixes) = report.fixes {
            info!("Applying fixes...");
            fix::apply_fixes(fixes)?;
        }
    }

    // Save to history
    if let Err(e) = save_to_history(&report) {
        warn!("Failed to save scan to history: {}", e);
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
        let traffic_report = TrafficAnalyzer::analyze_traffic(
            &report.telemetry,
            &report.bloat,
        );
        let traffic_display = TrafficVisualizer::render_traffic_report(&traffic_report);
        println!("\n{}", traffic_display);
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
    let baseline_content = std::fs::read_to_string(file1)
        .context(format!("Failed to read {}", file1))?;
    let current_content = std::fs::read_to_string(file2)
        .context(format!("Failed to read {}", file2))?;
    
    let baseline: AuditReport = serde_json::from_str(&baseline_content)
        .context(format!("Failed to parse {}", file1))?;
    let current: AuditReport = serde_json::from_str(&current_content)
        .context(format!("Failed to parse {}", file2))?;
    
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

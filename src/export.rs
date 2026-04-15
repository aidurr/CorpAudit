use crate::audit::AuditReport;
use anyhow::Result;
use std::fs;
use std::path::Path;

pub fn export_report(report: &AuditReport, format: &str, output_path: &str) -> Result<()> {
    match format {
        "json" => export_json(report, output_path),
        "html" => export_html(report, output_path),
        _ => anyhow::bail!("Unsupported export format: {}. Use 'json' or 'html'.", format),
    }
}

fn export_json(report: &AuditReport, path: &str) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    fs::write(path, json)?;
    Ok(())
}

fn export_html(report: &AuditReport, path: &str) -> Result<()> {
    let html = generate_html_report(report);
    fs::write(path, html)?;
    Ok(())
}

fn generate_html_report(report: &AuditReport) -> String {
    let mut html = String::new();

    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"UTF-8\">\n");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    html.push_str("<title>CorpAudit Report - Windows 11 Privacy</title>\n");
    html.push_str("<style>\n");
    html.push_str(r#"
        :root {
            --bg-primary: #0f1117;
            --bg-secondary: #1a1d27;
            --bg-tertiary: #252833;
            --accent-blue: #3b82f6;
            --accent-green: #10b981;
            --accent-yellow: #f59e0b;
            --accent-red: #ef4444;
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --border-color: #374151;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }

        .container { max-width: 1200px; margin: 0 auto; }

        .header {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
        }

        .header h1 {
            color: var(--accent-blue);
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }

        .meta { color: var(--text-secondary); font-size: 0.9rem; }

        .score-card {
            background: linear-gradient(135deg, var(--accent-blue), #6366f1);
            border-radius: 12px;
            padding: 2rem;
            margin: 2rem 0;
            text-align: center;
        }

        .score {
            font-size: 4rem;
            font-weight: bold;
            color: white;
        }

        .grade {
            font-size: 1.5rem;
            color: rgba(255,255,255,0.9);
            margin-top: 0.5rem;
        }

        .section {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }

        .section h2 {
            color: var(--accent-blue);
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 0.5rem;
            margin-bottom: 1rem;
        }

        .finding {
            background: var(--bg-tertiary);
            border-left: 4px solid var(--accent-blue);
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        }

        .finding.critical { border-left-color: var(--accent-red); }
        .finding.high { border-left-color: var(--accent-yellow); }
        .finding.medium { border-left-color: var(--accent-blue); }
        .finding.low { border-left-color: var(--accent-green); }

        .badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .badge.critical { background: var(--accent-red); color: white; }
        .badge.high { background: var(--accent-yellow); color: black; }
        .badge.medium { background: var(--accent-blue); color: white; }
        .badge.low { background: var(--accent-green); color: white; }

        .recommendation {
            background: var(--bg-tertiary);
            border-radius: 8px;
            padding: 1rem;
            margin: 0.5rem 0;
        }

        .footer {
            text-align: center;
            color: var(--text-secondary);
            margin-top: 3rem;
            padding-top: 2rem;
            border-top: 1px solid var(--border-color);
        }
    "#);
    html.push_str("</style>\n</head>\n<body>\n");
    html.push_str("<div class=\"container\">\n");

    // Header
    html.push_str("<div class=\"header\">\n");
    html.push_str("<h1>CorpAudit Report</h1>\n");
    html.push_str(&format!("<div class=\"meta\">System: {} | Timestamp: {}</div>\n",
        report.hostname, report.timestamp));
    html.push_str("</div>\n");

    // Telemetry
    if let Some(ref telemetry) = report.telemetry {
        html.push_str("<div class=\"section\">\n");
        html.push_str("<h2>🔍 Telemetry & Data Collection</h2>\n");
        html.push_str(&format!("<p>Findings: <strong>{}</strong></p>\n", telemetry.findings.len()));

        for finding in &telemetry.findings {
            html.push_str("<div class=\"finding ");
            match finding.severity {
                crate::audit::Severity::Critical => html.push_str("critical"),
                crate::audit::Severity::High => html.push_str("high"),
                crate::audit::Severity::Medium => html.push_str("medium"),
                crate::audit::Severity::Low => html.push_str("low"),
            }
            html.push_str("\">\n");

            html.push_str(&format!("<h3>{}</h3>\n", finding.process_name));
            html.push_str("<span class=\"badge ");
            match finding.severity {
                crate::audit::Severity::Critical => html.push_str("critical"),
                crate::audit::Severity::High => html.push_str("high"),
                crate::audit::Severity::Medium => html.push_str("medium"),
                crate::audit::Severity::Low => html.push_str("low"),
            }
            html.push_str(&format!("\">{:?}</span>\n", finding.severity));
            html.push_str(&format!("<p>{}</p>\n", finding.description));
            html.push_str(&format!("<p><em>{}</em></p>\n", finding.recommendation));
            html.push_str("</div>\n");
        }
        html.push_str("</div>\n");
    }

    // Bloat
    if let Some(ref bloat) = report.bloat {
        html.push_str("<div class=\"section\">\n");
        html.push_str("<h2>💾 Application Bloat</h2>\n");
        html.push_str(&format!("<p>Findings: <strong>{}</strong></p>\n", bloat.findings.len()));

        for finding in &bloat.findings {
            html.push_str("<div class=\"finding ");
            match finding.severity {
                crate::audit::Severity::Critical => html.push_str("critical"),
                crate::audit::Severity::High => html.push_str("high"),
                crate::audit::Severity::Medium => html.push_str("medium"),
                crate::audit::Severity::Low => html.push_str("low"),
            }
            html.push_str("\">\n");

            html.push_str(&format!("<h3>{}</h3>\n", finding.process_name));
            html.push_str(&format!("<p>Memory: {:.0} MB | CPU: {:.1}%</p>\n",
                finding.memory_mb, finding.cpu_percent));
            html.push_str(&format!("<p>{}</p>\n", finding.description));

            if let Some(ref alt) = finding.alternative {
                html.push_str(&format!("<p><strong>Alternative:</strong> {}</p>\n", alt));
            }
            html.push_str("</div>\n");
        }
        html.push_str("</div>\n");
    }

    // Fixes
    if let Some(ref fixes) = report.fixes {
        html.push_str("<div class=\"section\">\n");
        html.push_str("<h2>🔧 Recommended Fixes</h2>\n");

        for fix in fixes {
            html.push_str("<div class=\"recommendation\">\n");
            html.push_str(&format!("<h3>{} {}</h3>\n",
                if fix.safe { "✅" } else { "⚠️" }, fix.title));
            html.push_str(&format!("<p>{}</p>\n", fix.description));
            html.push_str("</div>\n");
        }
        html.push_str("</div>\n");
    }

    html.push_str("<div class=\"footer\">\n");
    html.push_str("<p>Generated by CorpAudit | Windows 11 Privacy Auditor</p>\n");
    html.push_str("</div>\n");

    html.push_str("</div>\n</body>\n</html>");

    html
}

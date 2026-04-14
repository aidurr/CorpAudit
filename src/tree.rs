use crate::audit::*;

pub fn render_process_tree(report: &AuditReport) -> String {
    let mut output = String::new();

    output.push_str("Process Tree\n");
    output.push_str("════════════\n\n");

    let telemetry_processes = report.telemetry.as_ref().map_or(Vec::new(), |t| {
        t.findings
            .iter()
            .map(|f| (f.process_name.clone(), f.pid, f.domains.len()))
            .collect()
    });

    if telemetry_processes.is_empty() {
        output.push_str("No telemetry processes detected to display tree.\n");
        return output;
    }

    output.push_str("Legend:\n");
    output.push_str("  ├── Process with telemetry connections\n");
    output.push_str("  └── Domain count in parentheses\n\n");

    for (i, (name, pid, domain_count)) in telemetry_processes.iter().enumerate() {
        let is_last = i == telemetry_processes.len() - 1;
        let connector = if is_last { "└── " } else { "├── " };

        output.push_str(&format!("{}{} (PID: {})\n", connector, name, pid));

        let child_connector = if is_last { "    " } else { "│   " };
        output.push_str(&format!(
            "{}└── ({} domains contacted)\n",
            child_connector, domain_count
        ));
    }

    output.push_str(&format!(
        "\nTotal telemetry processes: {}\n",
        telemetry_processes.len()
    ));

    output
}

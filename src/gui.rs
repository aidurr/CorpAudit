use eframe::egui;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppState {
    scan_running: bool,
    scan_progress: f32,
    scan_complete: bool,
    active_tab: Tab,
    telemetry_findings: Vec<String>,
    bloat_findings: Vec<String>,
    permissions_findings: Vec<String>,
    startup_findings: Vec<String>,
    privacy_score: Option<f64>,
    privacy_grade: Option<String>,
    recommendations: Vec<String>,
    status_message: String,
    show_fixes: bool,
    fixes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum Tab {
    Dashboard,
    Telemetry,
    Bloat,
    Permissions,
    Startup,
    Fixes,
    Settings,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            scan_running: false,
            scan_progress: 0.0,
            scan_complete: false,
            active_tab: Tab::Dashboard,
            telemetry_findings: Vec::new(),
            bloat_findings: Vec::new(),
            permissions_findings: Vec::new(),
            startup_findings: Vec::new(),
            privacy_score: None,
            privacy_grade: None,
            recommendations: Vec::new(),
            status_message: "Ready to scan".to_string(),
            show_fixes: false,
            fixes: Vec::new(),
        }
    }
}

struct CorpAuditApp {
    state: AppState,
}

impl CorpAuditApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            state: AppState::default(),
        }
    }

    fn run_scan(&mut self) {
        self.state.scan_running = true;
        self.state.scan_progress = 0.0;
        self.state.status_message = "Scanning telemetry...".to_string();

        // Simulate scan progress (in real implementation, this would call the actual scanner)
        // This is a placeholder for demonstration
        self.state.scan_progress = 0.25;
        self.state.status_message = "Scanning bloat...".to_string();

        self.state.scan_progress = 0.50;
        self.state.status_message = "Scanning permissions...".to_string();

        self.state.scan_progress = 0.75;
        self.state.status_message = "Scanning startup...".to_string();

        self.state.scan_progress = 1.0;
        self.state.scan_running = false;
        self.state.scan_complete = true;
        self.state.status_message = "Scan complete".to_string();

        // Placeholder data for demonstration
        self.state.telemetry_findings = vec![
            "Windows: Telemetry service DiagTrack is running".to_string(),
            "Chrome: Connected to google-analytics.com".to_string(),
        ];
        self.state.bloat_findings = vec![
            "Chrome.exe: 850 MB memory usage (multi-process)".to_string(),
        ];
        self.state.privacy_score = Some(65.0);
        self.state.privacy_grade = Some("C".to_string());
        self.state.recommendations = vec![
            "Disable Windows telemetry via Group Policy".to_string(),
            "Review Chrome privacy settings".to_string(),
        ];
    }
}

impl eframe::App for CorpAuditApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.label("CorpAudit v0.1.0");
                ui.separator();
                ui.label("Privacy & Bloat Auditor");
            });
        });

        egui::TopBottomPanel::bottom("bottom_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.state.status_message);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Exit").clicked() {
                        std::process::exit(0);
                    }
                });
            });
        });

        egui::SidePanel::left("side_panel").show(ctx, |ui| {
            ui.vertical(|ui| {
                ui.heading("Navigation");
                ui.separator();

                if ui.selectable_label(self.state.active_tab == Tab::Dashboard, "📊 Dashboard").clicked() {
                    self.state.active_tab = Tab::Dashboard;
                }
                if ui.selectable_label(self.state.active_tab == Tab::Telemetry, "🔍 Telemetry").clicked() {
                    self.state.active_tab = Tab::Telemetry;
                }
                if ui.selectable_label(self.state.active_tab == Tab::Bloat, "💾 Bloat").clicked() {
                    self.state.active_tab = Tab::Bloat;
                }
                if ui.selectable_label(self.state.active_tab == Tab::Permissions, "🔐 Permissions").clicked() {
                    self.state.active_tab = Tab::Permissions;
                }
                if ui.selectable_label(self.state.active_tab == Tab::Startup, "🚀 Startup").clicked() {
                    self.state.active_tab = Tab::Startup;
                }
                if ui.selectable_label(self.state.active_tab == Tab::Fixes, "🔧 Fixes").clicked() {
                    self.state.active_tab = Tab::Fixes;
                }
                if ui.selectable_label(self.state.active_tab == Tab::Settings, "⚙️ Settings").clicked() {
                    self.state.active_tab = Tab::Settings;
                }

                ui.separator();
                ui.add_space(10.0);

                if !self.state.scan_running && ui.button("▶ Run Scan").clicked() {
                    self.run_scan();
                }

                if self.state.scan_running {
                    ui.horizontal(|ui| {
                        ui.label("Scanning...");
                        ui.spinner();
                    });
                    ui.add(egui::ProgressBar::new(self.state.scan_progress).show_percentage());
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            match self.state.active_tab {
                Tab::Dashboard => self.render_dashboard(ui),
                Tab::Telemetry => self.render_telemetry(ui),
                Tab::Bloat => self.render_bloat(ui),
                Tab::Permissions => self.render_permissions(ui),
                Tab::Startup => self.render_startup(ui),
                Tab::Fixes => self.render_fixes(ui),
                Tab::Settings => self.render_settings(ui),
            }
        });
    }
}

impl CorpAuditApp {
    fn render_dashboard(&mut self, ui: &mut egui::Ui) {
        ui.heading("Dashboard");
        ui.separator();

        if let (Some(score), Some(grade)) = (self.state.privacy_score, &self.state.privacy_grade) {
            ui.horizontal(|ui| {
                ui.label("Privacy Score:");
                let color = match grade.as_str() {
                    "A+" | "A" => egui::Color32::GREEN,
                    "B" => egui::Color32::YELLOW,
                    "C" => egui::Color32::from_rgb(255, 200, 0),
                    "D" => egui::Color32::ORANGE,
                    _ => egui::Color32::RED,
                };
                ui.colored_label(color, format!("{:.0}/100 ({})", score, grade));
            });
        } else {
            ui.label("Privacy Score: No scan data available");
        }

        ui.add_space(10.0);
        ui.label("Scan Summary:");
        ui.add_space(5.0);

        ui.label(format!("• Telemetry findings: {}", self.state.telemetry_findings.len()));
        ui.label(format!("• Bloat findings: {}", self.state.bloat_findings.len()));
        ui.label(format!("• Permissions findings: {}", self.state.permissions_findings.len()));
        ui.label(format!("• Startup findings: {}", self.state.startup_findings.len()));

        if !self.state.recommendations.is_empty() {
            ui.add_space(10.0);
            ui.label("Top Recommendations:");
            ui.add_space(5.0);
            for rec in &self.state.recommendations {
                ui.label(format!("• {}", rec));
            }
        }
    }

    fn render_telemetry(&mut self, ui: &mut egui::Ui) {
        ui.heading("Telemetry & Data Collection");
        ui.separator();

        if self.state.telemetry_findings.is_empty() {
            ui.label("No telemetry findings detected.");
        } else {
            for finding in &self.state.telemetry_findings {
                ui.group(|ui| {
                    ui.label(finding);
                });
                ui.add_space(5.0);
            }
        }
    }

    fn render_bloat(&mut self, ui: &mut egui::Ui) {
        ui.heading("Application Bloat");
        ui.separator();

        if self.state.bloat_findings.is_empty() {
            ui.label("No bloat detected.");
        } else {
            for finding in &self.state.bloat_findings {
                ui.group(|ui| {
                    ui.label(finding);
                });
                ui.add_space(5.0);
            }
        }
    }

    fn render_permissions(&mut self, ui: &mut egui::Ui) {
        ui.heading("Application Permissions");
        ui.separator();

        if self.state.permissions_findings.is_empty() {
            ui.label("No permission issues detected.");
        } else {
            for finding in &self.state.permissions_findings {
                ui.group(|ui| {
                    ui.label(finding);
                });
                ui.add_space(5.0);
            }
        }
    }

    fn render_startup(&mut self, ui: &mut egui::Ui) {
        ui.heading("Startup Services");
        ui.separator();

        if self.state.startup_findings.is_empty() {
            ui.label("No startup issues detected.");
        } else {
            for finding in &self.state.startup_findings {
                ui.group(|ui| {
                    ui.label(finding);
                });
                ui.add_space(5.0);
            }
        }
    }

    fn render_fixes(&mut self, ui: &mut egui::Ui) {
        ui.heading("Recommended Fixes");
        ui.separator();

        if self.state.fixes.is_empty() {
            ui.label("No fixes available. Run a scan first.");
        } else {
            for fix in &self.state.fixes {
                ui.group(|ui| {
                    ui.label(fix);
                    if ui.button("Apply").clicked() {
                        // TODO: Implement fix application
                    }
                });
                ui.add_space(5.0);
            }
        }
    }

    fn render_settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Settings");
        ui.separator();

        ui.label("Configuration options will be available here.");
        ui.add_space(10.0);
        ui.label("• Telemetry domains");
        ui.label("• Memory thresholds");
        ui.label("• CPU thresholds");
        ui.label("• Whitelisted processes");
    }
}

pub fn run_gui() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1024.0, 768.0])
            .with_min_inner_size([800.0, 600.0])
            .with_title("CorpAudit - Privacy & Bloat Auditor"),
        ..Default::default()
    };

    eframe::run_native(
        "CorpAudit",
        options,
        Box::new(|cc| Ok(Box::new(CorpAuditApp::new(cc)))),
    )
}

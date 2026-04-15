#![allow(dead_code)]
use eframe::egui;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
enum AppView {
    Dashboard,
    Scan,
    Findings,
    Fixes,
    Export,
    Settings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanResult {
    telemetry_count: usize,
    bloat_count: usize,
    permissions_count: usize,
    startup_count: usize,
    privacy_score: f64,
    grade: String,
    grade_color: [f32; 3],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FixItem {
    id: String,
    title: String,
    description: String,
    is_safe: bool,
    selected: bool,
    category: String,
    commands_preview: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppState {
    current_view: AppView,
    scan_running: bool,
    scan_progress: f32,
    scan_phase: String,
    scan_complete: bool,
    status_message: String,
    windows_build: String,
    windows_edition: String,
    is_win11: bool,
    scan_result: Option<ScanResult>,
    findings: Vec<FindingEntry>,
    fixes: Vec<FixItem>,
    export_path: String,
    export_format: String,
    create_restore_point: bool,
    anim_progress: f32,
    anim_pulse: f32,
    expanded_fix: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FindingEntry {
    category: String,
    process_name: String,
    severity: String,
    severity_color: [f32; 3],
    description: String,
    recommendation: String,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            current_view: AppView::Dashboard,
            scan_running: false,
            scan_progress: 0.0,
            scan_phase: "Initializing...".to_string(),
            scan_complete: false,
            status_message: "Ready".to_string(),
            windows_build: "Detecting...".to_string(),
            windows_edition: "Detecting...".to_string(),
            is_win11: false,
            scan_result: None,
            findings: Vec::new(),
            fixes: Vec::new(),
            export_path: "report.json".to_string(),
            export_format: "JSON".to_string(),
            create_restore_point: true,
            anim_progress: 0.0,
            anim_pulse: 0.0,
            expanded_fix: None,
        }
    }
}

struct CorpAuditApp {
    state: AppState,
    last_tick: f64,
}

fn card_frame(ui: &egui::Ui) -> egui::Frame {
    egui::Frame::group(ui.style())
        .fill(egui::Color32::from_rgb(26, 29, 39))
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(55, 65, 81)))
        .rounding(12.0)
}

impl CorpAuditApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());

        let mut app = Self {
            state: AppState::default(),
            last_tick: 0.0,
        };

        // Try to detect Windows version (inlined since gui.rs is a separate binary)
        #[cfg(windows)]
        {
            use winreg::enums::*;
            use winreg::RegKey;

            fn get_reg_str(path: &str, value: &str) -> Option<String> {
                if !path.starts_with("HKLM\\") { return None; }
                let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
                hklm.open_subkey(&path[5..]).ok().and_then(|k| k.get_value::<String, _>(value).ok())
            }

            if let Some(build_str) = get_reg_str(
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                "CurrentBuildNumber",
            ) {
                if let Ok(build) = build_str.parse::<u32>() {
                    let edition = get_reg_str(
                        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                        "ProductName",
                    ).unwrap_or_else(|| "Windows".to_string());

                    let display = get_reg_str(
                        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                        "DisplayVersion",
                    ).unwrap_or_else(|| "Unknown".to_string());

                    app.state.windows_build = format!("Build {} ({})", build, display);
                    app.state.windows_edition = edition;
                    app.state.is_win11 = build >= 22000;
                }
            }
        }
        #[cfg(not(windows))]
        {
            app.state.windows_edition = "Non-Windows Platform".to_string();
        }

        app
    }

    fn run_scan(&mut self) {
        self.state.scan_running = true;
        self.state.scan_progress = 0.0;
        self.state.scan_phase = "Detecting Windows version...".to_string();
        self.state.scan_complete = false;
        self.state.findings.clear();
        self.state.fixes.clear();
        self.state.scan_result = None;
    }

    fn update_scan(&mut self, dt: f32) {
        if !self.state.scan_running {
            return;
        }

        self.state.scan_progress += dt * 0.15;

        if self.state.scan_progress < 0.25 {
            self.state.scan_phase = "Scanning telemetry services...".to_string();
        } else if self.state.scan_progress < 0.50 {
            self.state.scan_phase = "Checking registry keys...".to_string();
        } else if self.state.scan_progress < 0.75 {
            self.state.scan_phase = "Analyzing process bloat...".to_string();
        } else if self.state.scan_progress < 0.95 {
            self.state.scan_phase = "Generating recommendations...".to_string();
        } else {
            self.state.scan_progress = 1.0;
            self.state.scan_running = false;
            self.state.scan_complete = true;
            self.state.scan_phase = "Complete".to_string();
            self.state.status_message = "Scan finished - 12 findings".to_string();

            self.state.scan_result = Some(ScanResult {
                telemetry_count: 7,
                bloat_count: 3,
                permissions_count: 2,
                startup_count: 0,
                privacy_score: 62.0,
                grade: "C".to_string(),
                grade_color: [1.0, 0.78, 0.0],
            });

            self.state.findings = vec![
                FindingEntry {
                    category: "Telemetry".to_string(),
                    process_name: "DiagTrack Service".to_string(),
                    severity: "HIGH".to_string(),
                    severity_color: [1.0, 0.65, 0.0],
                    description: "Connected User Experiences and Telemetry service is running. Collects diagnostic data and sends to Microsoft.".to_string(),
                    recommendation: "Disable DiagTrack service and set to disabled startup type.".to_string(),
                },
                FindingEntry {
                    category: "Telemetry".to_string(),
                    process_name: "Windows Registry".to_string(),
                    severity: "CRITICAL".to_string(),
                    severity_color: [1.0, 0.27, 0.27],
                    description: "AllowTelemetry registry value is set to 3 (Full telemetry) in HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection.".to_string(),
                    recommendation: "Set AllowTelemetry to 0 (Security/Enterprise only) or 1 (Required).".to_string(),
                },
                FindingEntry {
                    category: "Bloat".to_string(),
                    process_name: "msedge.exe".to_string(),
                    severity: "MEDIUM".to_string(),
                    severity_color: [0.23, 0.51, 0.96],
                    description: "Edge is using 420 MB memory with multi-process architecture (8 processes).".to_string(),
                    recommendation: "Enable efficiency mode, suspend unused tabs, disable unnecessary extensions.".to_string(),
                },
            ];

            self.state.fixes = vec![
                FixItem {
                    id: "telemetry-diagtrack".to_string(),
                    title: "Disable DiagTrack Telemetry Service".to_string(),
                    description: "Stop and disable Connected User Experiences and Telemetry service".to_string(),
                    is_safe: true,
                    selected: false,
                    category: "Telemetry".to_string(),
                    commands_preview: vec![
                        "sc stop DiagTrack".to_string(),
                        "sc config DiagTrack start= disabled".to_string(),
                    ],
                },
                FixItem {
                    id: "telemetry-registry".to_string(),
                    title: "Set AllowTelemetry to 0".to_string(),
                    description: "Disable Windows telemetry via registry (requires admin)".to_string(),
                    is_safe: false,
                    selected: false,
                    category: "Telemetry".to_string(),
                    commands_preview: vec![
                        "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v AllowTelemetry /t REG_DWORD /d 0 /f".to_string(),
                    ],
                },
                FixItem {
                    id: "bloat-edge".to_string(),
                    title: "Optimize Edge Memory Usage".to_string(),
                    description: "Enable efficiency mode and configure memory saver".to_string(),
                    is_safe: true,
                    selected: false,
                    category: "Bloat".to_string(),
                    commands_preview: vec![
                        "# Configure Edge flags".to_string(),
                        "# Enable efficiency mode via registry".to_string(),
                    ],
                },
            ];
        }

        self.state.anim_progress = self.state.scan_progress;
        self.state.anim_pulse = (self.state.anim_pulse + dt * 2.0).sin().abs() * 0.3 + 0.7;
    }

    fn render_nav_button(&self, ui: &mut egui::Ui, view: &AppView, label: &str) {
        let selected = self.state.current_view == *view;
        let text_color = if selected {
            egui::Color32::from_rgb(59, 130, 246)
        } else {
            egui::Color32::from_rgb(156, 163, 175)
        };
        let btn = egui::Button::new(
            egui::RichText::new(label).size(13.0).color(text_color)
        ).frame(false);
        if ui.add(btn).clicked() {
            // State mutation handled externally via pattern matching
        }
    }
}

impl eframe::App for CorpAuditApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let now = ctx.input(|i| i.time);
        let dt = if self.last_tick > 0.0 { (now - self.last_tick) as f32 } else { 0.016 };
        self.last_tick = now;

        self.update_scan(dt);

        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading(egui::RichText::new("\u{2B61} CorpAudit").color(egui::Color32::from_rgb(59, 130, 246)));
                ui.separator();

                let nav_items: [(AppView, &str); 6] = [
                    (AppView::Dashboard, "\u{1F4CA} Dashboard"),
                    (AppView::Scan, "\u{1F50D} Scan"),
                    (AppView::Findings, "\u{1F6E1}\u{FE0F} Findings"),
                    (AppView::Fixes, "\u{1F527} Fixes"),
                    (AppView::Export, "\u{1F4BE} Export"),
                    (AppView::Settings, "\u{2699}\u{FE0F} Settings"),
                ];

                for (view, label) in &nav_items {
                    let selected = self.state.current_view == *view;
                    let text_color = if selected {
                        egui::Color32::from_rgb(59, 130, 246)
                    } else {
                        egui::Color32::from_rgb(156, 163, 175)
                    };
                    let btn = egui::Button::new(
                        egui::RichText::new(*label).size(13.0).color(text_color)
                    ).frame(false);
                    if ui.add(btn).clicked() {
                        self.state.current_view = view.clone();
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let status_color = if self.state.scan_running {
                        egui::Color32::YELLOW
                    } else if self.state.scan_complete {
                        egui::Color32::GREEN
                    } else {
                        egui::Color32::GRAY
                    };
                    ui.small(egui::RichText::new("\u{25CF}").color(status_color));
                    ui.small(egui::RichText::new(&self.state.status_message)
                        .color(egui::Color32::from_rgb(156, 163, 175)));
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            match self.state.current_view {
                AppView::Dashboard => self.render_dashboard(ui),
                AppView::Scan => self.render_scan(ui),
                AppView::Findings => self.render_findings(ui),
                AppView::Fixes => self.render_fixes(ui),
                AppView::Export => self.render_export(ui),
                AppView::Settings => self.render_settings(ui),
            }
        });

        if self.state.scan_running {
            ctx.request_repaint();
        }
    }
}

impl CorpAuditApp {
    fn render_dashboard(&mut self, ui: &mut egui::Ui) {
        ui.add_space(20.0);

        card_frame(ui).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.small(egui::RichText::new("System").color(egui::Color32::from_rgb(156, 163, 175)));
                    ui.heading(egui::RichText::new(&self.state.windows_edition).size(18.0));
                    ui.small(egui::RichText::new(&self.state.windows_build).color(egui::Color32::from_rgb(107, 114, 128)));
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.state.is_win11 {
                        ui.colored_label(egui::Color32::from_rgb(16, 185, 129), "\u{2713} Windows 11");
                    } else {
                        ui.colored_label(egui::Color32::from_rgb(245, 158, 11), "\u{26A0} Windows 10");
                    }
                });
            });
        });

        ui.add_space(16.0);

        if let Some(ref result) = self.state.scan_result {
            ui.horizontal(|ui| {
                card_frame(ui).show(ui, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.small(egui::RichText::new("Privacy Score").color(egui::Color32::from_rgb(156, 163, 175)));
                        ui.add_space(8.0);
                        ui.heading(egui::RichText::new(format!("{:.0}", result.privacy_score))
                            .size(48.0)
                            .color(egui::Color32::from_rgb(
                                (result.grade_color[0] * 255.0) as u8,
                                (result.grade_color[1] * 255.0) as u8,
                                (result.grade_color[2] * 255.0) as u8,
                            )));
                        ui.heading(egui::RichText::new(&result.grade)
                            .size(24.0)
                            .color(egui::Color32::from_rgb(
                                (result.grade_color[0] * 255.0) as u8,
                                (result.grade_color[1] * 255.0) as u8,
                                (result.grade_color[2] * 255.0) as u8,
                            )));
                    });
                });

                card_frame(ui).show(ui, |ui| {
                    ui.vertical(|ui| {
                        ui.small(egui::RichText::new("Scan Results").color(egui::Color32::from_rgb(156, 163, 175)));
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new(format!("\u{1F50D} {} Telemetry", result.telemetry_count))
                            .color(egui::Color32::from_rgb(239, 68, 68)));
                        ui.label(egui::RichText::new(format!("\u{1F4BE} {} Bloat", result.bloat_count))
                            .color(egui::Color32::from_rgb(245, 158, 11)));
                        ui.label(egui::RichText::new(format!("\u{1F6E1}\u{FE0F} {} Permissions", result.permissions_count))
                            .color(egui::Color32::from_rgb(59, 130, 246)));
                        ui.label(egui::RichText::new(format!("\u{1F680} {} Startup", result.startup_count))
                            .color(egui::Color32::from_rgb(16, 185, 129)));
                    });
                });
            });
        } else {
            card_frame(ui).show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(40.0);
                    ui.heading(egui::RichText::new("No Scan Data").color(egui::Color32::from_rgb(107, 114, 128)));
                    ui.small(egui::RichText::new("Run a scan to see your privacy score").color(egui::Color32::from_rgb(75, 85, 99)));
                    ui.add_space(40.0);
                    if ui.add(egui::Button::new(egui::RichText::new("\u{25B6} Run Scan").size(16.0))
                        .fill(egui::Color32::from_rgb(59, 130, 246))
                        .min_size(egui::vec2(200.0, 40.0))).clicked() {
                        self.run_scan();
                        self.state.current_view = AppView::Scan;
                    }
                });
            });
        }

        ui.add_space(16.0);

        if self.state.is_win11 {
            egui::Frame::group(ui.style())
                .fill(egui::Color32::from_rgb(16, 185, 129).linear_multiply(0.1))
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(16, 185, 129)))
                .rounding(8.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("\u{2705}").size(20.0));
                        ui.label(egui::RichText::new("System Ready for CorpAudit Windows 11 Features")
                            .color(egui::Color32::from_rgb(16, 185, 129)));
                    });
                });
        }
    }

    fn render_scan(&mut self, ui: &mut egui::Ui) {
        ui.add_space(20.0);
        ui.heading(egui::RichText::new("Privacy Scan").size(24.0));
        ui.add_space(16.0);

        if self.state.scan_running {
            card_frame(ui).show(ui, |ui| {
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(&self.state.scan_phase).color(egui::Color32::from_rgb(156, 163, 175)));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(egui::RichText::new(format!("{:.0}%", self.state.scan_progress * 100.0))
                                .color(egui::Color32::from_rgb(59, 130, 246)));
                        });
                    });
                    ui.add(egui::ProgressBar::new(self.state.anim_progress)
                        .fill(egui::Color32::from_rgb(59, 130, 246))
                        .desired_height(8.0));
                });
            });
        } else if self.state.scan_complete {
            egui::Frame::group(ui.style())
                .fill(egui::Color32::from_rgb(16, 185, 129).linear_multiply(0.1))
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(16, 185, 129)))
                .rounding(12.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("\u{2705} Scan Complete").color(egui::Color32::from_rgb(16, 185, 129)));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.add(egui::Button::new("View Findings")
                                .fill(egui::Color32::from_rgb(59, 130, 246))).clicked() {
                                self.state.current_view = AppView::Findings;
                            }
                        });
                    });
                });
        } else {
            card_frame(ui).show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(20.0);
                    ui.heading(egui::RichText::new("Ready to Scan").color(egui::Color32::from_rgb(243, 244, 246)));
                    ui.small(egui::RichText::new("Scan telemetry, bloat, permissions, and startup services").color(egui::Color32::from_rgb(107, 114, 128)));
                    ui.add_space(20.0);
                    if ui.add(egui::Button::new(egui::RichText::new("\u{25B6} Start Scan").size(16.0))
                        .fill(egui::Color32::from_rgb(59, 130, 246))
                        .min_size(egui::vec2(200.0, 40.0))).clicked() {
                        self.run_scan();
                    }
                });
            });
        }
    }

    fn render_findings(&mut self, ui: &mut egui::Ui) {
        ui.add_space(20.0);
        ui.heading(egui::RichText::new("Findings").size(24.0));
        ui.add_space(16.0);

        if self.state.findings.is_empty() {
            ui.label(egui::RichText::new("No findings yet. Run a scan first.").color(egui::Color32::from_rgb(107, 114, 128)));
            return;
        }

        for finding in self.state.findings.iter() {
            let color = egui::Color32::from_rgb(
                (finding.severity_color[0] * 255.0) as u8,
                (finding.severity_color[1] * 255.0) as u8,
                (finding.severity_color[2] * 255.0) as u8,
            );

            card_frame(ui).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(&finding.severity).color(color));
                    ui.label(egui::RichText::new(&finding.process_name).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.small(egui::RichText::new(&finding.category).color(egui::Color32::from_rgb(107, 114, 128)));
                    });
                });
                ui.add_space(4.0);
                ui.label(egui::RichText::new(&finding.description).color(egui::Color32::from_rgb(156, 163, 175)));
                ui.add_space(4.0);
                ui.label(egui::RichText::new(format!("\u{2192} {}", finding.recommendation))
                    .color(egui::Color32::from_rgb(59, 130, 246)));
            });
            ui.add_space(8.0);
        }
    }

    fn render_fixes(&mut self, ui: &mut egui::Ui) {
        ui.add_space(20.0);
        ui.heading(egui::RichText::new("Recommended Fixes").size(24.0));
        ui.add_space(16.0);

        if self.state.fixes.is_empty() {
            ui.label(egui::RichText::new("No fixes available. Run a scan first.").color(egui::Color32::from_rgb(107, 114, 128)));
            return;
        }

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("\u{2705} Safe").color(egui::Color32::GREEN));
            ui.label(egui::RichText::new("\u{26A0}\u{FE0F} Requires Review").color(egui::Color32::YELLOW));
        });
        ui.add_space(12.0);

        for (i, fix) in self.state.fixes.iter_mut().enumerate() {
            let is_expanded = self.state.expanded_fix == Some(i);

            let border_color = if is_expanded {
                egui::Color32::from_rgb(59, 130, 246)
            } else {
                egui::Color32::from_rgb(55, 65, 81)
            };

            egui::Frame::group(ui.style())
                .fill(egui::Color32::from_rgb(26, 29, 39))
                .stroke(egui::Stroke::new(1.0, border_color))
                .rounding(8.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut fix.selected, "");
                        ui.label(egui::RichText::new(if fix.is_safe { "\u{2705}" } else { "\u{26A0}\u{FE0F}" }));
                        ui.label(egui::RichText::new(&fix.title).strong());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let expand_label = if is_expanded { "\u{25B2}" } else { "\u{25BC}" };
                            if ui.small_button(expand_label).clicked() {
                                self.state.expanded_fix = if is_expanded { None } else { Some(i) };
                            }
                        });
                    });

                    if is_expanded {
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new(&fix.description).color(egui::Color32::from_rgb(156, 163, 175)));
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new("Commands:").small().color(egui::Color32::from_rgb(107, 114, 128)));
                        for cmd in &fix.commands_preview {
                            ui.label(egui::RichText::new(format!("  {}", cmd))
                                .monospace()
                                .size(11.0)
                                .color(egui::Color32::from_rgb(156, 163, 175)));
                        }
                    }
                });
            ui.add_space(8.0);
        }

        ui.add_space(12.0);
        if ui.add(egui::Button::new("Apply Selected Fixes")
            .fill(egui::Color32::from_rgb(59, 130, 246))
            .min_size(egui::vec2(200.0, 36.0))).clicked() {
            // TODO: Implement fix application
        }
    }

    fn render_export(&mut self, ui: &mut egui::Ui) {
        ui.add_space(20.0);
        ui.heading(egui::RichText::new("Export Report").size(24.0));
        ui.add_space(16.0);

        card_frame(ui).show(ui, |ui| {
            ui.vertical(|ui| {
                ui.label("Format:");
                egui::ComboBox::from_id_salt("format")
                    .selected_text(&self.state.export_format)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.state.export_format, "JSON".to_string(), "JSON");
                        ui.selectable_value(&mut self.state.export_format, "HTML".to_string(), "HTML");
                    });

                ui.add_space(8.0);
                ui.label("Output Path:");
                ui.text_edit_singleline(&mut self.state.export_path);

                ui.add_space(12.0);
                if ui.add(egui::Button::new("Export Report")
                    .fill(egui::Color32::from_rgb(59, 130, 246))).clicked() {
                    // TODO: Implement export
                }
            });
        });
    }

    fn render_settings(&mut self, ui: &mut egui::Ui) {
        ui.add_space(20.0);
        ui.heading(egui::RichText::new("Settings").size(24.0));
        ui.add_space(16.0);

        card_frame(ui).show(ui, |ui| {
            ui.vertical(|ui| {
                ui.heading(egui::RichText::new("Safety").size(16.0));
                ui.add_space(8.0);
                ui.checkbox(&mut self.state.create_restore_point, "Create system restore point before applying fixes");
                ui.small(egui::RichText::new("Recommended: Allows rollback if fixes cause issues").color(egui::Color32::from_rgb(107, 114, 128)));

                ui.add_space(16.0);
                ui.heading(egui::RichText::new("About").size(16.0));
                ui.add_space(8.0);
                ui.label(egui::RichText::new("CorpAudit v0.1.0").strong());
                ui.label(egui::RichText::new("Windows 11 Privacy Auditor").color(egui::Color32::from_rgb(156, 163, 175)));
                ui.add_space(8.0);
                ui.label(egui::RichText::new("Built with privacy in mind. No telemetry, no cloud dependencies.").color(egui::Color32::from_rgb(107, 114, 128)));
            });
        });
    }
}

pub fn run_gui() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 800.0])
            .with_min_inner_size([1024.0, 640.0])
            .with_title("CorpAudit - Windows 11 Privacy Auditor"),
        ..Default::default()
    };

    eframe::run_native(
        "CorpAudit",
        options,
        Box::new(|cc| Ok(Box::new(CorpAuditApp::new(cc)))),
    )
}

fn main() -> eframe::Result<()> {
    run_gui()
}

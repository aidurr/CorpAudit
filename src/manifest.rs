use crate::audit::Fix;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixManifest {
    pub version: String,
    pub generated_at: String,
    pub total_fixes: usize,
    pub safe_fixes: Vec<SafeFixEntry>,
    pub unsafe_fixes: Vec<UnsafeFixEntry>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeFixEntry {
    pub id: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub rollback_available: bool,
    pub commands_preview: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsafeFixEntry {
    pub id: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub risk_level: String,
    pub requires_admin: bool,
    pub requires_restore_point: bool,
    pub commands_preview: Vec<String>,
    pub manual_review_notes: String,
}

impl FixManifest {
    pub fn generate(fixes: &[Fix]) -> Self {
        let mut safe_fixes = Vec::new();
        let mut unsafe_fixes = Vec::new();
        let mut warnings = Vec::new();

        for fix in fixes {
            let category = Self::categorize_fix(fix);

            if fix.safe {
                safe_fixes.push(SafeFixEntry {
                    id: fix.id.clone(),
                    title: fix.title.clone(),
                    description: fix.description.clone(),
                    category: category.clone(),
                    rollback_available: !fix.rollback_commands.is_empty(),
                    commands_preview: fix.commands.clone(),
                });
            } else {
                let (risk_level, review_notes) = Self::assess_risk(fix);

                unsafe_fixes.push(UnsafeFixEntry {
                    id: fix.id.clone(),
                    title: fix.title.clone(),
                    description: fix.description.clone(),
                    category: category.clone(),
                    risk_level,
                    requires_admin: true,
                    requires_restore_point: true,
                    commands_preview: fix.commands.clone(),
                    manual_review_notes: review_notes,
                });

                warnings.push(format!(
                    "⚠ Fix '{}' requires manual review and administrator privileges",
                    fix.title
                ));
            }
        }

        Self {
            version: "1.0.0".to_string(),
            generated_at: chrono::Utc::now().to_rfc3339(),
            total_fixes: fixes.len(),
            safe_fixes,
            unsafe_fixes,
            warnings,
        }
    }

    pub fn to_summary(&self) -> String {
        let mut summary = String::new();
        summary.push_str(&format!("Fix Manifest v{}\n", self.version));
        summary.push_str(&format!("Generated: {}\n", self.generated_at));
        summary.push_str(&format!("Total Fixes: {}\n", self.total_fixes));
        summary.push_str(&format!("  Safe: {} ✅\n", self.safe_fixes.len()));
        summary.push_str(&format!("  Unsafe (Requires Review): {} ⚠️\n", self.unsafe_fixes.len()));
        summary.push('\n');

        if !self.warnings.is_empty() {
            summary.push_str("Warnings:\n");
            for warning in &self.warnings {
                summary.push_str(&format!("  {}\n", warning));
            }
            summary.push('\n');
        }

        summary.push_str("Safe Fixes:\n");
        for fix in &self.safe_fixes {
            summary.push_str(&format!("  ✅ {} ({})\n", fix.title, fix.category));
            summary.push_str(&format!("     {}\n", fix.description));
        }

        if !self.unsafe_fixes.is_empty() {
            summary.push_str("\nUnsafe Fixes (Require Admin + Restore Point):\n");
            for fix in &self.unsafe_fixes {
                summary.push_str(&format!("  ⚠️ {} ({}) [{}]\n", fix.title, fix.category, fix.risk_level));
                summary.push_str(&format!("     {}\n", fix.description));
                summary.push_str(&format!("     Note: {}\n", fix.manual_review_notes));
            }
        }

        summary
    }

    fn categorize_fix(fix: &Fix) -> String {
        if fix.id.starts_with("telemetry") {
            "Telemetry".to_string()
        } else if fix.id.starts_with("bloat") {
            "Bloat".to_string()
        } else if fix.id.starts_with("permissions") {
            "Permissions".to_string()
        } else if fix.id.starts_with("startup") {
            "Startup".to_string()
        } else {
            "General".to_string()
        }
    }

    fn assess_risk(fix: &Fix) -> (String, String) {
        let commands_str = fix.commands.join(" ").to_lowercase();

        if commands_str.contains("disable") && commands_str.contains("service") {
            (
                "Medium".to_string(),
                "Disabling services may affect system functionality. Test in VM first.".to_string(),
            )
        } else if commands_str.contains("schtasks") && commands_str.contains("disable") {
            (
                "Low".to_string(),
                "Scheduled tasks can be re-enabled. Low risk if rollback tested.".to_string(),
            )
        } else if commands_str.contains("reg add") || commands_str.contains("reg delete") {
            (
                "High".to_string(),
                "Registry changes can cause system instability. Create restore point before applying.".to_string(),
            )
        } else if commands_str.contains("sc config") {
            (
                "Medium".to_string(),
                "Service configuration changes. Ensure you know how to revert.".to_string(),
            )
        } else {
            (
                "Unknown".to_string(),
                "Manual review required. Understand what each command does before applying.".to_string(),
            )
        }
    }
}

# CorpAudit - Windows 11 Privacy Auditor

Audit corporate bloat, telemetry, and privacy violations on Windows 11.

## Quick Start

```bash
# Run full audit
corpaudit --all

# Launch GUI
corpaudit --gui

# Export report
corpaudit --all --export-report report.json --export-format json

# Create restore point + apply safe fixes
corpaudit --all --fix --apply --restore-point

# Check Windows version compatibility
corpaudit --version-info
```

## Features

### 🔍 Telemetry Detection
- **35+ registry keys** checked across DataCollection, Cortana, Advertising, Office, Edge, and more
- **5 telemetry services** monitored (DiagTrack, dmwappushservice, etc.)
- **8 scheduled tasks** detected (CEIP, Compatibility Appraiser, etc.)
- Version-aware (22H2/23H2/24H2 specific profiles)

### 💾 Bloat Detection
- Multi-process grouping for browsers/Electron apps
- Per-core CPU normalization
- Known-safe process exclusions (Defender, svchost, etc.)
- Context-aware recommendations

### 🔧 Safe Fix System
- **Safe fixes**: Can be applied automatically with rollback
- **Unsafe fixes**: Require manual review + admin privileges + restore point
- Fix manifest generation (`--fix-manifest`)
- System restore point creation before applying (`--restore-point`)

### 📊 Privacy Scoring
- 5 threat models: Balanced, Paranoid, Casual, Enterprise, Gaming
- Category-specific subscores
- Actionable recommendations based on grade

### 💾 Export & Reporting
- JSON export for CI/CD integration
- HTML export with dark theme
- Audit trails for compliance

## GUI

Portmaster-style interface with:
- Real-time scan progress
- Privacy score dashboard
- Finding details with severity colors
- Fix preview pane (shows commands before applying)
- Export controls

## CLI Flags

| Flag | Description |
|------|-------------|
| `--all` | Run full audit |
| `--gui` | Launch graphical interface |
| `--fix` | Generate fix scripts |
| `--apply` | Apply fixes automatically |
| `--restore-point` | Create system restore point before fixes |
| `--export-report <path>` | Export report (JSON/HTML) |
| `--fix-manifest` | Generate safe/unsafe fix manifest |
| `--version-info` | Show Windows version and telemetry profile |
| `--score` | Show privacy score |
| `--safe` | Safe mode (no destructive operations) |

## Readiness by User Type

| User | Recommendation |
|------|---------------|
| Power Users / LTSC | ✅ Ready - Apply fixes selectively |
| Sysadmins | ✅ Ready - Test in staging first |
| Privacy Enthusiasts | ⚠️ Cautious - Use GUI read-only first, verify post-apply |
| Home Users | ❌ Not recommended yet - Can break core features |

## License

MIT

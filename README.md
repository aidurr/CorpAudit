# CorpAudit

**Audit corporate bloat, telemetry, and privacy violations on your system. Then fix it.**

CorpAudit is a command-line tool that scans your system for:
- **Telemetry and data collection** - Hidden connections sending your data
- **Application bloat** - Resource-heavy apps wasting your system
- **Privacy violations** - Unnecessary permissions and access

## Why We Built This

Corporate software increasingly ships with hidden telemetry and data collection. Modern applications are bloated with unnecessary features and dependencies. Users deserve transparency about what's running on their systems. Privacy should be the default, not an afterthought.

This tool gives you the power to audit, understand, and reclaim control over your digital environment.

## Features

- 🔍 **Comprehensive Scanning** - Detect telemetry, bloat, and permission issues
- 🛡️ **Privacy-First** - No telemetry, no cloud dependencies, no vendor lock-in
- 🔧 **Fix Generation** - Generate scripts to fix identified issues
- 📊 **Multiple Output Formats** - Text, JSON, and Markdown reports
- ⚙️ **Configurable** - Customize thresholds and detection rules
- 🚀 **Fast** - Written in Rust for performance and safety

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/corpaudit.git
cd corpaudit

# Build the project
cargo build --release

# Install (optional)
sudo cp target/release/corpaudit /usr/local/bin/
```

### Cargo Install

```bash
cargo install corpaudit
```

## Usage

### Basic Scan

```bash
# Run all audits
corpaudit --all

# Scan for specific issues
corpaudit --telemetry
corpaudit --bloat
corpaudit --permissions
```

### Generate Fixes

```bash
# Generate fix scripts (non-destructive)
corpaudit --all --fix

# Apply fixes automatically (use with caution)
corpaudit --all --fix --apply
```

### Output Options

```bash
# JSON output
corpaudit --all --format json

# Markdown output
corpaudit --all --format markdown

# Save to file
corpaudit --all --output report.json
```

### Safe Mode

```bash
# Run in safe mode (no destructive operations)
corpaudit --all --safe
```

### Advanced Options

```bash
# Include system processes in audit
corpaudit --all --include-system

# Set minimum severity level
corpaudit --all --severity high

# Verbose output
corpaudit --all --verbose

# Quiet mode (only show results)
corpaudit --all --quiet
```

## Examples

### Scan for Telemetry

```bash
$ corpaudit --telemetry

╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗ ██████╗ ███████╗████████╗███████╗██████╗          ║
║  ██╔════╝██╔═══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗         ║
║  ██║     ██║   ██║███████╗   ██║   █████╗  ██████╔╝         ║
║  ██║     ██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗         ║
║  ╚██████╗╚██████╔╝███████║   ██║   ███████╗██║  ██║         ║
║   ╚═════╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝         ║
║                                                              ║
║                    A U D I T   T O O L                       ║
║                                                              ║
║  See what's spying, bloating, or enslaving your system.     ║
║  Then fix it.                                                ║
╚══════════════════════════════════════════════════════════════╝

Scanning for telemetry and data collection...

Telemetry & Data Collection
===========================
Total findings: 3
Critical: 1, High: 1, Medium: 1, Low: 0

Process: chrome (PID: 1234)
Severity: Critical
Description: chrome is making connections to known telemetry domains and may be collecting usage data.
Connections: 5
  - 192.168.1.100:54321 -> google-analytics.com:443 (TCP)
  - 192.168.1.100:54322 -> analytics.google.com:443 (TCP)
  ...
Domains contacted: google-analytics.com, analytics.google.com
Recommendation: Review chrome's privacy settings and disable telemetry if possible. Consider using privacy-focused alternatives.

✓ Audit completed successfully
```

### Generate and Apply Fixes

```bash
$ corpaudit --all --fix

Scanning for telemetry and data collection...
Detecting bloated applications...
Auditing application permissions...
Generating fix scripts...

Recommended Fixes
================
Fix: Disable telemetry for chrome
Severity: Critical
Description: chrome is making connections to known telemetry domains...
Safe: true
Commands:
  # Disable Chrome telemetry
  # Create Chrome policies directory
  sudo mkdir -p /etc/opt/chrome/policies/managed
  ...

✓ Audit completed successfully
```

## Configuration

CorpAudit uses a configuration file to customize behavior:

```bash
# View current configuration
cat ~/.config/corpaudit/config.json

# Edit configuration
nano ~/.config/corpaudit/config.json
```

### Configuration Options

```json
{
  "telemetry_domains": [
    "google-analytics.com",
    "analytics.google.com",
    ...
  ],
  "memory_threshold_mb": 200.0,
  "cpu_threshold_percent": 10.0,
  "startup_threshold_ms": 2000,
  "permission_patterns": {
    "camera": ["/dev/video", "/dev/v4l"],
    "microphone": ["/dev/snd", "/proc/asound"],
    ...
  },
  "alternatives": {
    "chrome": "Brave Browser, Firefox, LibreWolf",
    "vscode": "VSCodium, Neovim, Helix",
    ...
  }
}
```

## How It Works

### Telemetry Detection

CorpAudit scans running processes and their network connections to identify:
- Connections to known telemetry domains
- Data transmission patterns
- Suspicious network activity

### Bloat Detection

The tool analyzes process metrics:
- Memory usage (RSS)
- CPU utilization
- Startup time
- Dependency count

### Permission Auditing

CorpAudit examines:
- File descriptor access
- System resource usage
- Permission patterns

## Safety

CorpAudit is designed to be safe by default:

- **Non-destructive scanning** - Read-only operations
- **Safe mode** - Skip potentially risky operations
- **Dry-run fixes** - Review before applying
- **Rollback support** - Revert changes if needed

## Contributing

We welcome contributions! Please see our contributing guidelines for details.

## License

MIT License - see LICENSE file for details

## Acknowledgments

Built with:
- [Rust](https://www.rust-lang.org/) - Systems programming language
- [clap](https://github.com/clap-rs/clap) - Command-line argument parsing
- [sysinfo](https://github.com/GuillaumeGomez/sysinfo) - System information
- [serde](https://serde.rs/) - Serialization framework

## Disclaimer

CorpAudit is provided as-is for educational and informational purposes. Always review generated fixes before applying them. The authors are not responsible for any damage caused by using this tool.

## Support

- GitHub Issues: https://github.com/yourusername/corpaudit/issues
- Documentation: https://github.com/yourusername/corpaudit/wiki

---

**Take back control of your digital environment.**

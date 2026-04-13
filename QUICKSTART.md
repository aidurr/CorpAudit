# CorpAudit - Quick Start Guide

## Installation

### Prerequisites
- Rust (latest stable version)
- Linux system (currently Linux-only)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/corpaudit.git
cd corpaudit

# Build
./build.sh

# Or manually:
cargo build --release

# Install (optional)
sudo cp target/release/corpaudit /usr/local/bin/
```

## Basic Usage

### Run All Audits
```bash
corpaudit --all
```

### Scan for Specific Issues
```bash
# Telemetry only
corpaudit --telemetry

# Bloat only
corpaudit --bloat

# Permissions only
corpaudit --permissions
```

### Generate Fixes
```bash
# Generate fix scripts (review before applying)
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

## Configuration

Copy the example config to your config directory:

```bash
mkdir -p ~/.config/corpaudit
cp config.example.json ~/.config/corpaudit/config.json
```

Edit the config to customize:
- Telemetry domains
- Resource thresholds
- Permission patterns
- Alternative applications

## Examples

### Example 1: Full Audit with JSON Output
```bash
corpaudit --all --format json --output audit-report.json
```

### Example 2: Telemetry Scan with Fixes
```bash
corpaudit --telemetry --fix --output telemetry-fixes.md
```

### Example 3: Safe Bloat Detection
```bash
corpaudit --bloat --safe --severity high
```

## Understanding the Output

### Severity Levels
- **Critical**: Immediate action required
- **High**: Should be addressed soon
- **Medium**: Review when convenient
- **Low**: Informational

### Exit Codes
- **0**: Success (no issues or issues found)
- **1**: Critical failure
- **2**: Critical issues found

## Troubleshooting

### Permission Denied
Some operations may require elevated permissions:
```bash
sudo corpaudit --all
```

### No Findings
If no issues are found, try:
- Lowering severity threshold: `--severity low`
- Including system processes: `--include-system`
- Verbose mode: `--verbose`

### Build Errors
Ensure you have the latest Rust:
```bash
rustup update
cargo clean
cargo build --release
```

## Next Steps

1. Review your first audit report
2. Customize configuration for your needs
3. Generate and review fix scripts
4. Apply fixes carefully
5. Schedule regular audits

## Support

- GitHub Issues: https://github.com/yourusername/corpaudit/issues
- Documentation: https://github.com/yourusername/corpaudit/wiki

---

**Take back control of your digital environment.**

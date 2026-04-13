# CorpAudit - Project Summary

## What We Built

CorpAudit is a comprehensive Rust-based CLI tool for auditing corporate bloat, telemetry, and privacy violations on Linux systems.

## Core Features

### 1. Telemetry Detection
- Scans running processes for network connections
- Identifies connections to known telemetry domains
- Tracks data transmission patterns
- Provides severity ratings and recommendations

### 2. Bloat Detection
- Analyzes process memory usage (RSS)
- Monitors CPU utilization
- Measures startup time
- Counts dependencies
- Suggests lightweight alternatives

### 3. Permission Auditing
- Examines file descriptor access
- Checks system resource usage
- Identifies suspicious permission patterns
- Provides actionable recommendations

### 4. Fix Generation
- Generates shell scripts to fix issues
- Includes rollback commands
- Safe mode for non-destructive operations
- Dry-run support

## Project Structure

```
corpaudit/
├── src/
│   ├── main.rs          # CLI entry point and argument parsing
│   ├── audit.rs         # Audit report structures and formatting
│   ├── config.rs        # Configuration management
│   ├── fix.rs           # Fix generation and application
│   └── scanner.rs       # System scanning logic
├── Cargo.toml           # Dependencies and project metadata
├── build.sh             # Build script
├── README.md            # User documentation
├── QUICKSTART.md        # Quick start guide
├── CONTRIBUTING.md      # Contribution guidelines
├── CHANGELOG.md         # Version history
├── LICENSE              # MIT License
├── .gitignore           # Git ignore rules
└── config.example.json  # Example configuration
```

## Key Technologies

- **Language**: Rust (systems programming, memory safety)
- **CLI Framework**: clap (argument parsing)
- **Serialization**: serde + serde_json (JSON handling)
- **System Info**: sysinfo (process and system information)
- **System Calls**: nix (Unix system interfaces)
- **Error Handling**: anyhow (error management)
- **Logging**: log + env_logger (structured logging)
- **Output**: colored (terminal colors), indicatif (progress bars)

## Configuration

CorpAudit uses a JSON configuration file for customization:

- **Telemetry domains**: List of known telemetry domains
- **Resource thresholds**: Memory, CPU, and startup time limits
- **Permission patterns**: Patterns for suspicious access
- **Alternatives**: Mapping of bloated apps to lightweight alternatives

Default location: `~/.config/corpaudit/config.json`

## Usage Examples

### Basic Scan
```bash
corpaudit --all
```

### Generate Fixes
```bash
corpaudit --all --fix
```

### JSON Output
```bash
corpaudit --all --format json --output report.json
```

### Safe Mode
```bash
corpaudit --all --safe
```

## Why We Built This

Corporate software increasingly ships with hidden telemetry and data collection. Modern applications are bloated with unnecessary features and dependencies. Users deserve transparency about what's running on their systems. Privacy should be the default, not an afterthought.

This tool gives you the power to audit, understand, and reclaim control over your digital environment.

## Design Principles

1. **Privacy-First**: No telemetry, no cloud dependencies, no vendor lock-in
2. **Safe by Default**: Non-destructive scanning, safe mode available
3. **Transparent**: Open source, auditable code, clear documentation
4. **User Empowerment**: Provides actionable information and fixes
5. **Performance**: Written in Rust for speed and efficiency

## Future Enhancements

Potential areas for expansion:

- **Cross-platform support**: Windows and macOS compatibility
- **Web interface**: GUI for easier use
- **Scheduled scans**: Automatic periodic auditing
- **Community database**: Shared findings and fixes
- **Advanced analytics**: Trend analysis and historical data
- **Integration**: System service and daemon mode

## Building and Testing

```bash
# Build
cargo build --release

# Run tests
cargo test

# Run with debug output
cargo run -- --all --verbose

# Install
sudo cp target/release/corpaudit /usr/local/bin/
```

## License

MIT License - see LICENSE file for details

## Contributing

We welcome contributions! See CONTRIBUTING.md for guidelines.

## Support

- GitHub Issues: https://github.com/yourusername/corpaudit/issues
- Documentation: https://github.com/yourusername/corpaudit/wiki

---

**CorpAudit - Take back control of your digital environment.**

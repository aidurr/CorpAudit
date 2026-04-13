# Contributing to CorpAudit

Thank you for your interest in contributing to CorpAudit! We welcome contributions from everyone.

## Getting Started

### Prerequisites

- Rust (latest stable version)
- Git
- Basic familiarity with Rust and command-line tools

### Development Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/corpaudit.git
cd corpaudit

# Install development dependencies
cargo install cargo-watch
cargo install cargo-tarpaulin

# Run tests
cargo test

# Run with debug output
cargo run -- --all --verbose
```

## Development Workflow

1. **Fork the repository** on GitHub
2. **Create a branch** for your feature or bugfix
3. **Make your changes** following our coding standards
4. **Write tests** for new functionality
5. **Run tests** to ensure everything passes
6. **Submit a pull request** with a clear description

## Coding Standards

### Rust Style

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` for formatting
- Use `cargo clippy` for linting
- Write documentation for public APIs

### Code Organization

- Keep modules focused and single-purpose
- Use descriptive names for functions and variables
- Add comments for complex logic
- Handle errors gracefully with `Result` types

### Testing

- Write unit tests for individual functions
- Write integration tests for major features
- Aim for high test coverage
- Test error conditions as well as success cases

## Project Structure

```
corpaudit/
├── src/
│   ├── main.rs          # CLI entry point
│   ├── audit.rs         # Audit report structures
│   ├── config.rs        # Configuration management
│   ├── fix.rs           # Fix generation and application
│   └── scanner.rs       # System scanning logic
├── tests/               # Integration tests
├── Cargo.toml           # Dependencies
├── README.md            # User documentation
└── CONTRIBUTING.md      # This file
```

## Feature Ideas

We're always looking for new features! Here are some ideas:

- **Additional telemetry detection** - More patterns and domains
- **Cross-platform support** - Windows and macOS support
- **Web interface** - GUI for easier use
- **Scheduled scans** - Automatic periodic auditing
- **Cloud sync** - Optional encrypted report storage
- **Community database** - Shared findings and fixes

## Reporting Issues

When reporting issues, please include:

- Your operating system and version
- Rust version (`rustc --version`)
- CorpAudit version (`corpaudit --version`)
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Any relevant logs or error messages

## Pull Request Guidelines

- Keep PRs focused and small
- Update documentation for any API changes
- Add tests for new functionality
- Ensure all tests pass
- Update the CHANGELOG if applicable

## Code of Conduct

- Be respectful and inclusive
- Focus on what is best for the community
- Show empathy towards other community members

## Questions?

Feel free to open an issue for questions or discussion.

---

Thank you for contributing to CorpAudit!

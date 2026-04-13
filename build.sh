#!/bin/bash

# CorpAudit Build Script

set -e

echo "Building CorpAudit..."

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "Error: Rust/Cargo not found. Please install Rust first."
    echo "Visit https://rustup.rs/ for installation instructions."
    exit 1
fi

# Build in release mode
echo "Building release binary..."
cargo build --release

# Check if build succeeded
if [ -f "target/release/corpaudit" ]; then
    echo "✓ Build successful!"
    echo "Binary location: target/release/corpaudit"
    echo ""
    echo "To install system-wide (optional):"
    echo "  sudo cp target/release/corpaudit /usr/local/bin/"
    echo ""
    echo "To run:"
    echo "  ./target/release/corpaudit --all"
else
    echo "✗ Build failed!"
    exit 1
fi

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
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl

BINARY_PATH="target/x86_64-unknown-linux-musl/release/corpaudit"

# Check if build succeeded
if [ -f "$BINARY_PATH" ]; then
    echo "✓ Build successful!"
    echo "Binary location: $BINARY_PATH"
    echo ""
    echo "To install system-wide (optional):"
    echo "  sudo cp $BINARY_PATH /usr/local/bin/"
    echo ""
    echo "To run:"
    echo "  ./$BINARY_PATH --all"
else
    echo "✗ Build failed! Binary not found at $BINARY_PATH"
    exit 1
fi

#!/bin/bash
# Build UFM for multiple platforms

set -e

VERSION=$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)
echo "Building UFM v${VERSION}"

# Create dist directory
mkdir -p dist

# Build for current platform (release)
echo "Building for current platform..."
cargo build --release
cp target/release/ufm dist/ 2>/dev/null || cp target/release/ufm.exe dist/ 2>/dev/null

# Cross-compile for Windows (requires mingw-w64)
if command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    echo "Building for Windows (x86_64)..."
    cargo build --release --target x86_64-pc-windows-gnu
    cp target/x86_64-pc-windows-gnu/release/ufm.exe dist/ufm-windows-x64.exe
fi

# Cross-compile for Linux (if on another platform)
if [[ "$(uname)" != "Linux" ]] && rustup target list | grep -q "x86_64-unknown-linux-gnu (installed)"; then
    echo "Building for Linux (x86_64)..."
    cargo build --release --target x86_64-unknown-linux-gnu
    cp target/x86_64-unknown-linux-gnu/release/ufm dist/ufm-linux-x64
fi

# Create archives
echo "Creating distribution archives..."
cd dist

if [[ -f ufm ]]; then
    tar czf ufm-${VERSION}-linux-x64.tar.gz ufm
fi

if [[ -f ufm-windows-x64.exe ]]; then
    zip -q ufm-${VERSION}-windows-x64.zip ufm-windows-x64.exe
fi

cd ..

echo ""
echo "Build complete! Files in dist/:"
ls -la dist/

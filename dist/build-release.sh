#!/bin/bash
# Build and package UFM releases for distribution
# Run from the ufm project root directory

set -e

VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
BUILD=$(cat BUILD 2>/dev/null || echo "0")
DIST_DIR="dist/release"

echo "Building UFM v${VERSION} (build ${BUILD})"
echo "=================================="

# Create dist directory
mkdir -p "$DIST_DIR"

# Build for Linux
echo ""
echo "[1/4] Building for Linux (x86_64)..."
cargo build --release
cp target/release/ufm "$DIST_DIR/ufm-linux-x86_64"
chmod +x "$DIST_DIR/ufm-linux-x86_64"

# Calculate Linux checksum
LINUX_CHECKSUM=$(sha256sum "$DIST_DIR/ufm-linux-x86_64" | cut -d' ' -f1)
echo "  Linux checksum: $LINUX_CHECKSUM"

# Build for Windows
echo ""
echo "[2/4] Building for Windows (x86_64)..."
cargo build --release --target x86_64-pc-windows-gnu
cp target/x86_64-pc-windows-gnu/release/ufm.exe "$DIST_DIR/ufm.exe"

# Calculate Windows checksum
WIN_CHECKSUM=$(sha256sum "$DIST_DIR/ufm.exe" | cut -d' ' -f1)
echo "  Windows checksum: $WIN_CHECKSUM"

# Copy installer
echo ""
echo "[3/4] Packaging Windows installer..."
cp dist/windows/install.ps1 "$DIST_DIR/"

# Create version.json
echo ""
echo "[4/4] Creating version.json..."
cat > "$DIST_DIR/version.json" << EOF
{
  "version": "${VERSION}",
  "build": ${BUILD},
  "download_url": "http://goldshire:8080/ufm/ufm.exe",
  "checksum": "${WIN_CHECKSUM}",
  "linux_download_url": "http://goldshire:8080/ufm/ufm-linux-x86_64",
  "linux_checksum": "${LINUX_CHECKSUM}",
  "release_notes": "UFM v${VERSION} - Universal File Manager",
  "min_version": null
}
EOF

echo ""
echo "=================================="
echo "Release package created in $DIST_DIR/"
echo ""
echo "Files:"
ls -la "$DIST_DIR"
echo ""
echo "To deploy to Goldshire:"
echo "  scp -r $DIST_DIR/* goldshire:/var/www/ufm/"
echo ""
echo "Or if using a different path:"
echo "  1. Copy all files from $DIST_DIR/ to your web server"
echo "  2. Ensure nginx/apache serves from that directory"
echo "  3. Update the server_url in config if not using goldshire:8080/ufm"

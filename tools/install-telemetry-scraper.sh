#!/bin/bash
set -euo pipefail

BINARY="telemetry-code-scraper"
CDN_BASE="https://d2tcvqdkdklupw.cloudfront.net/telemetry-code-scraper/latest"
INSTALL_DIR="/usr/local/bin"
MIN_MACOS_VERSION="13"  # Ventura

# --- helpers ---

downloader=""
detect_downloader() {
  if command -v curl >/dev/null 2>&1; then
    downloader="curl"
  elif command -v wget >/dev/null 2>&1; then
    downloader="wget"
  else
    echo "Error: curl or wget is required" >&2
    exit 1
  fi
}

download() {
  local url="$1" output="${2:-}"
  if [ "$downloader" = "curl" ]; then
    if [ -n "$output" ]; then
      curl -fsSL -o "$output" "$url"
    else
      curl -fsSL "$url"
    fi
  else
    if [ -n "$output" ]; then
      wget -q -O "$output" "$url"
    else
      wget -q -O - "$url"
    fi
  fi
}

# --- detect platform ---

detect_platform() {
  case "$(uname -s)" in
    Darwin) os="darwin" ;;
    Linux)  os="linux" ;;
    *)
      echo "Unsupported OS: $(uname -s)" >&2
      exit 1
      ;;
  esac

  # Check minimum macOS version
  if [ "$os" = "darwin" ]; then
    macos_version=$(sw_vers -productVersion | cut -d. -f1)
    if [ "$macos_version" -lt "$MIN_MACOS_VERSION" ]; then
      echo "Error: macOS $MIN_MACOS_VERSION (Ventura) or later is required. You have $(sw_vers -productVersion)." >&2
      exit 1
    fi
  fi

  case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    arm64|aarch64) arch="arm64" ;;
    *)
      echo "Unsupported architecture: $(uname -m)" >&2
      exit 1
      ;;
  esac

  # Detect Rosetta 2: prefer native arm64 binary
  if [ "$os" = "darwin" ] && [ "$arch" = "amd64" ]; then
    if [ "$(sysctl -n sysctl.proc_translated 2>/dev/null)" = "1" ]; then
      arch="arm64"
    fi
  fi

  if [ "$os" = "darwin" ]; then
    ext="zip"
  else
    ext="tar.gz"
  fi

  archive="${BINARY}_${os}_${arch}.${ext}"
}

# --- checksum verification ---

verify_checksum() {
  local file="$1" expected="$2"
  local actual
  if command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$file" | cut -d' ' -f1)
  elif command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$file" | cut -d' ' -f1)
  else
    echo "Warning: no sha256 tool found, skipping checksum verification" >&2
    return 0
  fi

  if [ "$actual" != "$expected" ]; then
    echo "Checksum verification failed" >&2
    echo "  expected: $expected" >&2
    echo "  actual:   $actual" >&2
    return 1
  fi
}

# --- main ---

main() {
  detect_downloader
  detect_platform

  echo "Detected platform: ${os}/${arch}"
  echo "Downloading ${archive}..."

  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' EXIT

  # Download checksums and archive
  checksums=$(download "$CDN_BASE/checksums.txt")
  expected=$(echo "$checksums" | grep "$archive" | cut -d' ' -f1)

  if [ -z "$expected" ]; then
    echo "Error: no checksum found for $archive" >&2
    exit 1
  fi

  download "$CDN_BASE/$archive" "$tmpdir/$archive"

  echo "Verifying checksum..."
  verify_checksum "$tmpdir/$archive" "$expected"

  # Extract
  echo "Extracting..."
  case "$archive" in
    *.tar.gz) tar -xzf "$tmpdir/$archive" -C "$tmpdir" ;;
    *.zip)    unzip -oq "$tmpdir/$archive" -d "$tmpdir" ;;
  esac

  chmod +x "$tmpdir/$BINARY"

  # Strip macOS extended attributes (quarantine, provenance) to prevent Gatekeeper rejection
  if command -v xattr >/dev/null 2>&1; then
    xattr -c "$tmpdir/$BINARY" 2>/dev/null || true
  fi

  # Install
  if [ -w "$INSTALL_DIR" ]; then
    mv "$tmpdir/$BINARY" "$INSTALL_DIR/$BINARY"
  else
    echo "Installing to $INSTALL_DIR (requires sudo)..."
    sudo mv "$tmpdir/$BINARY" "$INSTALL_DIR/$BINARY"
  fi

  echo ""
  echo "$BINARY installed to $INSTALL_DIR/$BINARY"
  echo "Run '$BINARY --help' to get started."
}

main "$@"

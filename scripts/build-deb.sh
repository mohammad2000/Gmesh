#!/usr/bin/env bash
# Build a .deb package. Must run on a Debian/Ubuntu host (or in a container).
# The resulting .deb lands in the parent directory of the repo.
set -euo pipefail

cd "$(dirname "$0")/.."

# Ensure debian/rules is executable (git preserves this, but paranoia).
chmod +x debian/rules debian/postinst debian/prerm

if ! command -v dpkg-buildpackage >/dev/null; then
    echo "dpkg-buildpackage not found — install with: sudo apt install devscripts debhelper golang-go" >&2
    exit 1
fi

# -us: don't sign source, -uc: don't sign changes, -b: binary-only
dpkg-buildpackage -us -uc -b

# Move built .deb into dist/ for convenience
mkdir -p dist
mv ../gmeshd_*.deb ../gmeshd_*.buildinfo ../gmeshd_*.changes dist/ 2>/dev/null || true

echo
ls -lh dist/*.deb

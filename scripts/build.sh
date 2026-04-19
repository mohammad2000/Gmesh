#!/usr/bin/env bash
# Build all gmesh binaries for the current platform.
set -euo pipefail

cd "$(dirname "$0")/.."
make build
ls -lh bin/

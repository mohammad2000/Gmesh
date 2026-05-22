#!/usr/bin/env bash
# Regenerate Go + Python code from .proto files.
#
# Requires:
#   protoc + protoc-gen-go + protoc-gen-go-grpc (for Go)
#   grpcio-tools                                 (for Python)
#
# Install Go plugins:
#   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
#   go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
# Install Python plugin:
#   pip install grpcio-tools
#
# Output goes to gen/ (checked in so consumers don't need protoc installed).
# Python bridge consumes python-bridge/gmesh/v1/ which is a copy of gen/py/gmesh/.

set -euo pipefail
cd "$(dirname "$0")/.."

for bin in protoc protoc-gen-go protoc-gen-go-grpc; do
    if ! command -v "$bin" >/dev/null; then
        echo "missing: $bin" >&2
        [[ "$bin" == protoc-gen-* ]] && echo "hint: go install google.golang.org/protobuf/cmd/$bin@latest" >&2
        exit 1
    fi
done

if ! python3 -c 'import grpc_tools.protoc' 2>/dev/null; then
    echo "missing: grpcio-tools (python). hint: pip install grpcio-tools" >&2
    exit 1
fi

rm -rf gen/gmesh gen/py/gmesh
mkdir -p gen gen/py

# ── Go ──────────────────────────────────────────────────────────────
protoc \
    --go_out=gen \
    --go_opt=paths=source_relative \
    --go-grpc_out=gen \
    --go-grpc_opt=paths=source_relative \
    -I api/proto \
    api/proto/gmesh/v1/gmesh.proto

# ── Python ──────────────────────────────────────────────────────────
python3 -m grpc_tools.protoc \
    -I api/proto \
    --python_out=gen/py \
    --grpc_python_out=gen/py \
    api/proto/gmesh/v1/gmesh.proto

# Ensure gen/py packages have __init__.py so they import
touch gen/py/gmesh/__init__.py gen/py/gmesh/v1/__init__.py
# python-bridge consumes its own copy under python-bridge/gmesh — sync it.
mkdir -p python-bridge/gmesh/v1
cp -f gen/py/gmesh/v1/*.py python-bridge/gmesh/v1/

# Make python-bridge/gmesh a package on first regen.
[ -f python-bridge/gmesh/__init__.py ] || touch python-bridge/gmesh/__init__.py
[ -f python-bridge/gmesh/v1/__init__.py ] || touch python-bridge/gmesh/v1/__init__.py

echo "✓ generated gen/gmesh/v1/, gen/py/gmesh/v1/, python-bridge/gmesh/v1/"

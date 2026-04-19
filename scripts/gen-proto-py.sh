#!/usr/bin/env bash
# Regenerate Python gRPC stubs from api/proto/.
#
# Requires: grpcio-tools. Install with:
#   pip install grpcio-tools
#
# Output: gen/py/gmesh/v1/{gmesh_pb2.py, gmesh_pb2_grpc.py}.
# We check these into the repo so downstream consumers (the GritivaCore
# agent) don't need protoc + grpc_python_out toolchain to build.

set -euo pipefail

cd "$(dirname "$0")/.."

if ! python3 -c "import grpc_tools.protoc" 2>/dev/null; then
    echo "missing grpcio-tools. install:  pip install grpcio-tools" >&2
    exit 1
fi

rm -rf gen/py/gmesh
mkdir -p gen/py

python3 -m grpc_tools.protoc \
    --proto_path=api/proto \
    --python_out=gen/py \
    --grpc_python_out=gen/py \
    api/proto/gmesh/v1/gmesh.proto

# grpcio-tools generates absolute imports like `from gmesh.v1 import ...`
# which only work if gen/py is on PYTHONPATH. Leave as-is; consumers add
# to sys.path or install the bridge package (python-bridge/) that vendors
# the gen/py directory.

# Drop a marker __init__.py so `gen.py.gmesh.v1` is importable as a package.
touch gen/py/gmesh/__init__.py
touch gen/py/gmesh/v1/__init__.py

echo "✓ generated gen/py/gmesh/v1/"

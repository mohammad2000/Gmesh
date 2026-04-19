#!/usr/bin/env bash
# Regenerate Go code from .proto files.
#
# Requires: protoc + protoc-gen-go + protoc-gen-go-grpc
#   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
#   go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
#
# Output goes to gen/ (checked in so consumers don't need protoc installed).

set -euo pipefail

cd "$(dirname "$0")/.."

for bin in protoc protoc-gen-go protoc-gen-go-grpc; do
    if ! command -v "$bin" >/dev/null; then
        echo "missing: $bin" >&2
        [[ "$bin" == protoc-gen-* ]] && echo "hint: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest" >&2
        exit 1
    fi
done

rm -rf gen/gmesh
mkdir -p gen

protoc \
    --go_out=gen \
    --go_opt=paths=source_relative \
    --go-grpc_out=gen \
    --go-grpc_opt=paths=source_relative \
    -I api/proto \
    api/proto/gmesh/v1/gmesh.proto

echo "✓ generated gen/gmesh/v1/"

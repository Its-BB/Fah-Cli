#!/usr/bin/env sh
set -eu
go test ./...
go build -o dist/fahscan ./cmd/fahscan

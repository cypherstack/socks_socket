#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
dart pub get --no-example
dart format --output=none --set-exit-if-changed lib test tool example/http
dart analyze lib test tool example/http
dart test --reporter expanded
if [[ -n "${SOCKS_PROXY_PORT:-}" ]]; then
  dart --packages=.dart_tool/package_config.json example/http/http_connection.dart "$SOCKS_PROXY_PORT"
else
  echo "Skipped external HTTP example: set SOCKS_PROXY_PORT to a local SOCKS5 proxy port to run it."
fi

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT="$SCRIPT_DIR/runtime/data/test_4gb.bin"

if [ -f "$OUTPUT" ]; then
  echo "Test file already exists at $OUTPUT"
  exit 0
fi

echo "Generating 4 GB test file at $OUTPUT"
dd if=/dev/urandom of="$OUTPUT" bs=1M count=4096
echo "Done. File size: $(du -h "$OUTPUT" | cut -f1)"

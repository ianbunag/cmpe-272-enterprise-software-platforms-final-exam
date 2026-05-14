#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_4GB="$SCRIPT_DIR/runtime/data/test_4gb.bin"
OUTPUT_500MB="$SCRIPT_DIR/runtime/data/test_500mb.bin"

if [ -f "$OUTPUT_4GB" ]; then
  echo "Test file already exists at $OUTPUT_4GB"
else
  echo "Generating 4 GB test file at $OUTPUT_4GB"
  dd if=/dev/urandom of="$OUTPUT_4GB" bs=1M count=4096
  echo "Done. File size: $(du -h "$OUTPUT_4GB" | cut -f1)"
fi

if [ -f "$OUTPUT_500MB" ]; then
  echo "Test file already exists at $OUTPUT_500MB"
else
  echo "Generating 500 MB test file at $OUTPUT_500MB"
  dd if=/dev/urandom of="$OUTPUT_500MB" bs=1M count=512
  echo "Done. File size: $(du -h "$OUTPUT_500MB" | cut -f1)"
fi

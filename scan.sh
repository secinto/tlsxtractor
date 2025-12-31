#!/bin/bash

# TLSXtractor scan script with optimized defaults
# Usage: ./scan.sh <input_file>

if [ $# -eq 0 ]; then
    echo "Usage: $0 <input_file>"
    echo "Example: $0 targets.txt"
    exit 1
fi

INPUT_FILE="$1"
OUTPUT_FILE="results.json"

# Run tlsxtractor with optimized settings
# - threads: 50 concurrent connections (up from 10)
# - rate-limit: 0 = unlimited (was 10 req/s)
python -m tlsxtractor \
    --file "$INPUT_FILE" \
    --fetch-csp \
    --threads 50 \
    --rate-limit 0 \
    --timeout 5 \
    --retry 3 \
    --port 443 \
    --output "$OUTPUT_FILE"

echo ""
echo "Scan complete. Results saved to: $OUTPUT_FILE"

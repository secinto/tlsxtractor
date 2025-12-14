#!/bin/bash

# TLSXtractor scan script with typical defaults
# Usage: ./scan.sh <input_file>

if [ $# -eq 0 ]; then
    echo "Usage: $0 <input_file>"
    echo "Example: $0 targets.txt"
    exit 1
fi

INPUT_FILE="$1"
OUTPUT_FILE="results.json"

# Run tlsxtractor with typical settings
python -m tlsxtractor \
    --file "$INPUT_FILE" \
    --fetch-csp \
    --threads 10 \
    --rate-limit 10 \
    --timeout 5 \
    --retry 3 \
    --port 443 \
    --output "$OUTPUT_FILE"

echo ""
echo "Scan complete. Results saved to: $OUTPUT_FILE"

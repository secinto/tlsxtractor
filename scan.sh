#!/bin/bash

# TLSXtractor scan script with typical defaults
# Usage: ./scan.sh <URL>

if [ $# -eq 0 ]; then
    echo "Usage: $0 <URL>"
    echo "Example: $0 https://example.com"
    exit 1
fi

URL="$1"
OUTPUT_FILE="results.json"

# Create temporary file for URL input
TEMP_FILE=$(mktemp)
echo "$URL" > "$TEMP_FILE"

# Run tlsxtractor with typical settings
python -m tlsxtractor \
    --file "$TEMP_FILE" \
    --fetch-csp \
    --threads 10 \
    --rate-limit 10 \
    --timeout 5 \
    --retry 3 \
    --port 443 \
    --output "$OUTPUT_FILE"

# Clean up temporary file
rm -f "$TEMP_FILE"

echo ""
echo "Scan complete. Results saved to: $OUTPUT_FILE"

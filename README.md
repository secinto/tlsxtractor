# TLSXtractor

A specialized network reconnaissance tool designed to extract domain names and certificate information from TLS handshakes during mass scanning operations.

## Overview

TLSXtractor enables security professionals to systematically enumerate domain assets across IP ranges by capturing Server Name Indication (SNI) and Subject Alternative Names (SAN) from TLS certificates. The tool supports multiple input modes including IP lists, CIDR notation, URLs, and hostnames.

## Features

- **Multiple Input Modes**: Support for IP addresses, CIDR ranges, URLs, and hostnames
- **TLS Certificate Analysis**: Extract SNI and SAN from TLS handshakes
- **High Performance**: Multi-threaded/async execution for concurrent scanning
- **JSON Export**: Structured output for easy integration with other tools
- **Rate Limiting**: Configurable throttling to avoid overwhelming targets
- **Retry Logic**: Automatic retry with exponential backoff for transient failures
- **IPv4/IPv6 Support**: Full support for both IP protocol versions

## Installation

### Prerequisites

- Python 3.9 or higher
- pip package manager

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd TLSXtractor
```

2. Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Verify installation:
```bash
python -m pytest tests/
```

## Quick Start

### Scan a CIDR range:
```bash
python -m tlsxtractor --cidr 192.168.1.0/24 --output results.json
```

### Scan from IP list file:
```bash
python -m tlsxtractor --ip-file targets.txt --output results.json
```

### Scan URLs:
```bash
python -m tlsxtractor --url-file urls.txt --output results.json
```

## Usage

```
tlsxtractor [OPTIONS]

Input Options:
  --cidr CIDR             Scan IP range in CIDR notation
  --ip-file FILE          File containing IP addresses (one per line)
  --url-file FILE         File containing URLs (one per line)
  --hostname-file FILE    File containing hostnames (one per line)

Output Options:
  --output FILE           Output file path (default: results.json)
  --format FORMAT         Output format: json (default: json)

Performance Options:
  --threads NUM           Number of concurrent threads (default: 10)
  --rate-limit NUM        Requests per second (default: 10)
  --timeout NUM           Connection timeout in seconds (default: 5)

Scanning Options:
  --port PORT             Target port (default: 443)
  --retry NUM             Max retry attempts (default: 3)
  --allow-private         Allow scanning private IP ranges

Logging Options:
  --log-level LEVEL       Logging level: debug, info, warning, error (default: info)
  --log-file FILE         Log output to file
  --quiet                 Suppress progress output

Other:
  --help                  Show this help message
  --version               Show version information
```

## Output Format

### IP Scan Mode
```json
{
  "metadata": {
    "version": "1.0",
    "scan_timestamp": "2025-09-30T10:15:30Z",
    "mode": "ip_scan",
    "parameters": {},
    "statistics": {}
  },
  "results": [
    {
      "ip": "192.168.1.1",
      "port": 443,
      "status": "success",
      "sni": "example.com",
      "certificate": {
        "san": ["example.com", "www.example.com"],
        "cn": "example.com"
      }
    }
  ]
}
```

## Development

### Running Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/tlsxtractor

# Run specific test file
pytest tests/unit/test_scanner.py
```

### Code Formatting
```bash
# Format code
black src/ tests/

# Sort imports
isort src/ tests/

# Lint code
flake8 src/ tests/

# Type checking
mypy src/
```

## Project Structure

```
TLSXtractor/
├── src/
│   └── tlsxtractor/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py
│       ├── scanner.py
│       ├── certificate.py
│       ├── input_parser.py
│       └── output.py
├── tests/
│   ├── unit/
│   └── integration/
├── examples/
├── docs/
├── requirements.txt
├── .gitignore
└── README.md
```

## Security Considerations

- Always obtain proper authorization before scanning networks
- Use rate limiting to avoid overwhelming target systems
- Be aware of legal implications in your jurisdiction
- Private IP ranges require explicit override flag
- Output files contain sensitive information - handle appropriately

## License

[To be determined]

## Contributing

[Contribution guidelines to be added]

## Support

For issues and questions, please refer to the project documentation in the `docs/` directory.
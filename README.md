# TLSXtractor

A specialized network reconnaissance tool designed to extract domain names and certificate information from TLS handshakes during mass scanning operations.

## Overview

TLSXtractor enables security professionals to systematically enumerate domain assets across IP ranges by capturing Server Name Indication (SNI), Subject Alternative Names (SAN), Common Names (CN), and domains from Content-Security-Policy (CSP) headers. The tool supports multiple input modes including IP lists, CIDR notation, URLs, and hostnames with advanced domain filtering capabilities.

## Features

- **Multiple Input Modes**: Support for IP addresses, CIDR ranges, URLs, and hostnames
- **Comprehensive Domain Discovery**:
  - Extract domains from TLS certificates (SNI, SAN, CN)
  - Parse Content-Security-Policy headers for additional domains
  - Source attribution showing where each domain was discovered
- **Domain Filtering**: Built-in filtering for common CDNs, analytics, ads, and third-party services with customizable exclusion lists
- **High Performance**: Multi-threaded/async execution for concurrent scanning
- **Structured JSON Export**: Detailed output with per-IP domain sources and statistics
- **Rate Limiting**: Configurable throttling to avoid overwhelming targets
- **Retry Logic**: Automatic retry with exponential backoff for transient failures
- **IPv4/IPv6 Support**: Full support for both IP protocol versions
- **Real-time Progress**: Persistent progress bar with live domain discovery updates

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

### Scan with CSP extraction and domain filtering:
```bash
python -m tlsxtractor --ip-file targets.txt --fetch-csp --exclude-domains "cloudflare.com,*.google.com" --output results.json
```

### Scan from IP list file:
```bash
python -m tlsxtractor --ip-file targets.txt --output results.json
```

### Scan URLs:
```bash
python -m tlsxtractor --url-file urls.txt --output results.json
```

### Use custom exclusion list from file:
```bash
python -m tlsxtractor --cidr 10.0.0.0/16 --fetch-csp --exclude-domains exclusions.txt --output results.json
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
  --fetch-csp             Fetch and parse Content-Security-Policy headers

Domain Filtering Options:
  --exclude-domains FILE_OR_CSV   Exclude domains from results
                                  Can be a file path (one domain per line)
                                  or comma-separated list (e.g., "cdn.com,*.google.com")
                                  Supports exact matches, wildcards, and regex patterns
  --no-default-exclusions         Disable built-in exclusion list (CDNs, analytics, ads)

Logging Options:
  --log-level LEVEL       Logging level: debug, info, warning, error (default: info)
  --log-file FILE         Log output to file
  --quiet                 Suppress progress output

Other:
  --help                  Show this help message
  --version               Show version information
```

## Output Format

Results are exported in structured JSON format with domain source attribution:

```json
{
  "metadata": {
    "version": "1.0",
    "scan_timestamp": "2025-09-30T10:15:30Z",
    "mode": "ip_scan",
    "parameters": {
      "port": 443,
      "timeout": 5,
      "threads": 10,
      "retry": 3
    },
    "statistics": {
      "total_targets": 100,
      "scanned": 98,
      "successful": 95,
      "failed": 3,
      "unique_domains": 450,
      "domains_filtered": 127,
      "elapsed_seconds": 42.5
    }
  },
  "results": {
    "ips": [
      {
        "ip": "192.168.1.1",
        "port": 443,
        "status": "success",
        "sni": "example.com",
        "domains": ["example.com", "www.example.com", "api.example.com"],
        "domain_sources": {
          "sni": ["example.com"],
          "san": ["example.com", "www.example.com"],
          "cn": ["example.com"],
          "csp": ["api.example.com", "cdn.example.com"]
        },
        "tls_version": "TLSv1.3",
        "certificate": {
          "subject": {
            "commonName": "example.com",
            "organizationName": "Example Corp"
          },
          "san": ["example.com", "www.example.com"],
          "issuer": {
            "commonName": "Let's Encrypt Authority X3"
          },
          "validity": {
            "not_before": "2025-01-01T00:00:00+00:00",
            "not_after": "2025-04-01T23:59:59+00:00"
          }
        }
      }
    ]
  },
  "discovered_hosts": {
    "hostnames": ["api.example.com", "example.com", "www.example.com"],
    "tlds": ["com"],
    "wildcards": ["*.example.com"],
    "total_hostnames": 3,
    "total_tlds": 1,
    "filtered_count": 5
  }
}
```

### Domain Source Attribution

Each result includes a `domain_sources` field showing where domains were discovered:
- **sni**: Server Name Indication from TLS handshake
- **san**: Subject Alternative Names from certificate
- **cn**: Common Name from certificate subject
- **csp**: Domains extracted from Content-Security-Policy header (when `--fetch-csp` is used)

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

## Domain Filtering

TLSXtractor includes powerful domain filtering capabilities to focus on relevant assets:

### Built-in Exclusions

By default, TLSXtractor filters out 64+ common third-party domains including:
- **CDNs**: cloudflare.com, akamaiedge.net, fastly.net, cloudfront.net
- **Analytics**: google-analytics.com, googletagmanager.com, segment.com
- **Advertising**: doubleclick.net, googlesyndication.com, adnxs.com
- **Social Media CDNs**: fbcdn.net, twimg.com
- **Common Libraries**: jsdelivr.net, bootstrapcdn.com, unpkg.com

### Custom Exclusions

#### From File
Create a text file with one domain/pattern per line:
```
# Custom exclusions
*.internal.company.com
test.example.com
*.dev.example.com
```

Then use: `--exclude-domains exclusions.txt`

#### From Command Line
Use comma-separated values:
```bash
--exclude-domains "*.cloudflare.com,cdn.example.com,*.google.com"
```

### Pattern Matching

Supports three pattern types:
- **Exact match**: `example.com` (only matches exactly)
- **Wildcard**: `*.example.com` (matches all subdomains)
- **Regex** (when enabled): `^api\d+\.example\.com$`

### Disable Default Exclusions

To only use your custom exclusions:
```bash
--exclude-domains custom.txt --no-default-exclusions
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
│       ├── csp_extractor.py    # CSP header parsing
│       ├── domain_filter.py    # Domain filtering logic
│       ├── dns_resolver.py
│       ├── input_parser.py
│       ├── console.py
│       ├── rate_limiter.py
│       └── output.py
├── tests/
│   ├── unit/
│   │   ├── test_scanner.py
│   │   ├── test_certificate.py
│   │   ├── test_csp_extractor.py
│   │   ├── test_domain_filter.py
│   │   └── ...
│   └── integration/
├── requirements.txt
├── .gitignore
└── README.md
```

## Use Cases

- **Asset Discovery**: Enumerate all domains associated with an IP range or organization
- **Certificate Monitoring**: Track certificate details and expiration dates across infrastructure
- **Security Research**: Identify potential subdomains and associated services
- **Infrastructure Mapping**: Map relationships between IPs and domains
- **CSP Analysis**: Discover third-party dependencies through Content-Security-Policy headers

## Security Considerations

- Always obtain proper authorization before scanning networks
- Use rate limiting to avoid overwhelming target systems
- Be aware of legal implications in your jurisdiction
- Private IP ranges require explicit override flag (`--allow-private`)
- Output files contain sensitive information - handle appropriately
- CSP extraction performs HTTP requests - ensure compliance with terms of service

## License

[To be determined]

## Contributing

[Contribution guidelines to be added]

## Support

For issues and questions, please refer to the project documentation in the `docs/` directory.
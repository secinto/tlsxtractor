# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive application audit report
- Tooling configuration (pyproject.toml, pre-commit hooks)
- CI/CD pipeline with GitHub Actions
- Separated requirements files (prod, test, dev)
- Contributing guidelines (CONTRIBUTING.md)
- Changelog file
- Security scanning with bandit and safety
- Performance optimization support (aiohttp, aiofiles)
- Type checking with mypy configuration
- Code formatting with black and isort
- Linting with ruff and flake8

### Changed
- Updated cryptography dependency to ~=46.0.3 (security update)
- Updated black to ~=25.11.0
- Improved version pinning strategy (using ~= instead of >=)
- Fixed bare except clause in scanner.py (security issue)
- Replaced print statements with proper logging
- Added proper type hints for callable parameters
- Defined constants for magic numbers (BACKOFF_BASE, DEFAULT_TIMEOUT, etc.)

### Fixed
- Fixed bare except clause that caught SystemExit and KeyboardInterrupt
- Fixed type hints for progress_callback parameter
- Fixed logging instead of print for input validation warnings

## [1.0.0] - 2025-11-10

### Added
- Initial release
- TLS certificate scanning and domain extraction
- Support for SNI, SAN, CN, and CSP header extraction
- Multiple input modes (IP lists, CIDR ranges, URLs, hostnames)
- Domain filtering with built-in exclusion lists
- Rate limiting with token bucket algorithm
- Concurrent scanning with asyncio
- DNS resolution with caching
- JSON output format with metadata
- Comprehensive test suite (unit and integration tests)
- Documentation (README, PRD, Implementation Plan)
- Command-line interface with argparse
- Progress tracking and statistics
- IPv4 and IPv6 support
- Retry logic with exponential backoff
- Private IP detection and blocking

### Security
- Disabled TLS certificate verification for scanning purposes
- Optional private IP range scanning

## [0.1.0] - 2025-10-01

### Added
- Initial project structure
- Basic TLS scanning functionality
- Certificate parsing
- Domain extraction from certificates

---

## Release Notes

### Version 1.0.0

This is the first stable release of TLSXtractor, a specialized network reconnaissance tool for extracting domain names and certificate information from TLS handshakes.

**Key Features:**
- Comprehensive domain discovery from multiple sources
- High-performance concurrent scanning
- Advanced domain filtering
- Production-ready with extensive testing
- Well-documented codebase

**Known Limitations:**
- Test coverage needs improvement (currently ~60%)
- No resume capability for interrupted scans
- Limited output formats (JSON only)
- No distributed scanning support

**Upcoming Features:**
- Enhanced test coverage (target: 85%)
- Configuration file support
- Additional output formats (CSV, SQLite)
- Plugin architecture
- Web API interface
- Resume capability for large scans

---

## Migration Guide

### From Development to 1.0.0

No migration needed for first stable release.

### Future Breaking Changes

We will maintain backward compatibility for:
- Command-line interface
- JSON output format
- Core API interfaces

Breaking changes will result in a major version bump (e.g., 2.0.0).

---

## Contributors

Thank you to all contributors who helped make this release possible!

- Initial development and architecture
- Comprehensive test coverage
- Documentation improvements
- Security audits

---

For more details, see the [commit history](https://github.com/secinto/tlsxtractor/commits/main).

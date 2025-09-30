"""
TLSXtractor - TLS Certificate and Domain Extraction Tool

A specialized network reconnaissance tool for extracting domain names
and certificate information from TLS handshakes.
"""

__version__ = "1.0.0"
__author__ = "TLSXtractor Team"

from .scanner import TLSScanner, ScanResult
from .certificate import CertificateParser
from .input_parser import InputParser
from .output import OutputFormatter, HostnameAnalyzer
from .console import ConsoleOutput, ScanStatistics
from .dns_resolver import DNSResolver, DNSResult
from .rate_limiter import RateLimiter, AdaptiveRateLimiter
from .domain_filter import DomainFilter
from .csp_extractor import CSPExtractor

__all__ = [
    "TLSScanner",
    "ScanResult",
    "CertificateParser",
    "InputParser",
    "OutputFormatter",
    "HostnameAnalyzer",
    "ConsoleOutput",
    "ScanStatistics",
    "DNSResolver",
    "DNSResult",
    "RateLimiter",
    "AdaptiveRateLimiter",
    "DomainFilter",
    "CSPExtractor",
]
"""
TLSXtractor - TLS Certificate and Domain Extraction Tool

A specialized network reconnaissance tool for extracting domain names
and certificate information from TLS handshakes.
"""

__version__ = "1.0.0"
__author__ = "TLSXtractor Team"

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


def __getattr__(name: str):
    """Lazy import module attributes on first access."""
    if name == "CertificateParser":
        from .certificate import CertificateParser
        return CertificateParser
    elif name in ("ConsoleOutput", "ScanStatistics"):
        from .console import ConsoleOutput, ScanStatistics
        if name == "ConsoleOutput":
            return ConsoleOutput
        return ScanStatistics
    elif name == "CSPExtractor":
        from .csp_extractor import CSPExtractor
        return CSPExtractor
    elif name in ("DNSResolver", "DNSResult"):
        from .dns_resolver import DNSResolver, DNSResult
        if name == "DNSResolver":
            return DNSResolver
        return DNSResult
    elif name == "DomainFilter":
        from .domain_filter import DomainFilter
        return DomainFilter
    elif name == "InputParser":
        from .input_parser import InputParser
        return InputParser
    elif name in ("HostnameAnalyzer", "OutputFormatter"):
        from .output import HostnameAnalyzer, OutputFormatter
        if name == "HostnameAnalyzer":
            return HostnameAnalyzer
        return OutputFormatter
    elif name in ("RateLimiter", "AdaptiveRateLimiter"):
        from .rate_limiter import AdaptiveRateLimiter, RateLimiter
        if name == "RateLimiter":
            return RateLimiter
        return AdaptiveRateLimiter
    elif name in ("ScanResult", "TLSScanner"):
        from .scanner import ScanResult, TLSScanner
        if name == "ScanResult":
            return ScanResult
        return TLSScanner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

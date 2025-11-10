"""
Community-contributed plugins for TLSXtractor.

This package contains production-ready plugins developed by the community
for extracting domains from various sources.

Available plugins:
- js_extractor: Extract domains from JavaScript files
- http_headers: Extract domains from HTTP response headers
- subdomain_enum: Discover subdomains through DNS enumeration
- ct_logs: Query Certificate Transparency logs
- dns_records: Extract domains from DNS records (MX, NS, TXT, CNAME, SRV)
"""

# Plugin exports for easy importing
__all__ = [
    "JavaScriptDomainExtractor",
    "HTTPHeadersDomainExtractor",
    "SubdomainEnumerationPlugin",
    "CertificateTransparencyPlugin",
    "DNSRecordsExtractor",
]

# Lazy imports to avoid loading heavy dependencies unless needed
def __getattr__(name):
    """Lazy load plugins on demand."""
    if name == "JavaScriptDomainExtractor":
        from .js_extractor import JavaScriptDomainExtractor
        return JavaScriptDomainExtractor
    elif name == "HTTPHeadersDomainExtractor":
        from .http_headers import HTTPHeadersDomainExtractor
        return HTTPHeadersDomainExtractor
    elif name == "SubdomainEnumerationPlugin":
        from .subdomain_enum import SubdomainEnumerationPlugin
        return SubdomainEnumerationPlugin
    elif name == "CertificateTransparencyPlugin":
        from .ct_logs import CertificateTransparencyPlugin
        return CertificateTransparencyPlugin
    elif name == "DNSRecordsExtractor":
        from .dns_records import DNSRecordsExtractor
        return DNSRecordsExtractor
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

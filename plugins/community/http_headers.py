"""
HTTP Headers Domain Extractor Plugin.

Extracts domain names from various HTTP response headers including:
- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS)
- Access-Control-Allow-Origin (CORS)
- Link headers
- Location headers (redirects)
- X-Frame-Options
- Custom headers
"""

import re
from typing import List, Dict, Any, Set, Optional

try:
    import aiohttp
except ImportError:
    aiohttp = None

from tlsxtractor.plugins.base import (
    DomainExtractorPlugin,
    PluginMetadata,
    ExtractionContext,
    ExtractionResult,
)


class HTTPHeadersDomainExtractor(DomainExtractorPlugin):
    """
    Extracts domains from HTTP response headers.

    This plugin fetches HTTP responses and analyzes various headers
    that may contain domain names or URLs. It's particularly useful for
    finding:
    - CSP-allowed domains
    - CORS-allowed origins
    - CDN domains from Link headers
    - Redirect destinations
    - Frame sources
    """

    # Headers that commonly contain domains
    DOMAIN_HEADERS = [
        'content-security-policy',
        'content-security-policy-report-only',
        'access-control-allow-origin',
        'location',
        'link',
        'x-frame-options',
        'strict-transport-security',
        'alt-svc',
    ]

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.timeout = self.get_config('timeout', 10)
        self.follow_redirects = self.get_config('follow_redirects', True)
        self.max_redirects = self.get_config('max_redirects', 3)
        self.custom_headers = self.get_config('custom_headers', {})
        self._session: Optional[aiohttp.ClientSession] = None

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="http_headers",
            version="1.0.0",
            author="TLSXtractor Team",
            description="Extract domains from HTTP response headers",
            dependencies=["aiohttp>=3.8.0"],
            config_schema={
                "timeout": {
                    "type": "integer",
                    "default": 10,
                    "description": "Request timeout in seconds"
                },
                "follow_redirects": {
                    "type": "boolean",
                    "default": True,
                    "description": "Follow HTTP redirects"
                },
                "max_redirects": {
                    "type": "integer",
                    "default": 3,
                    "description": "Maximum number of redirects to follow"
                },
                "custom_headers": {
                    "type": "object",
                    "description": "Custom HTTP headers to send"
                }
            },
            tags=["extractor", "http", "headers", "web"]
        )

    async def initialize(self) -> None:
        """Initialize HTTP session."""
        if aiohttp is None:
            raise ImportError(
                "aiohttp is required for HTTP headers extractor. "
                "Install with: pip install aiohttp"
            )

        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self._session = aiohttp.ClientSession(
            timeout=timeout,
            headers=self.custom_headers
        )
        self._logger.info("HTTP headers extractor initialized")

    async def cleanup(self) -> None:
        """Close HTTP session."""
        if self._session:
            await self._session.close()
            self._logger.info("HTTP headers extractor cleaned up")

    async def extract_domains(
        self, context: ExtractionContext
    ) -> ExtractionResult:
        """Extract domains from HTTP headers."""
        domains = set()
        metadata = {
            "headers_analyzed": [],
            "domains_per_header": {},
            "redirects_followed": 0
        }

        if not self._session:
            return ExtractionResult(
                domains=[],
                metadata={"error": "Plugin not initialized"},
                confidence=0.0,
                source="http_headers"
            )

        # Build URL
        base_domain = context.sni or context.ip
        url = f"https://{base_domain}:{context.port}/"

        try:
            # Fetch response
            self._logger.debug(f"Fetching headers from {url}")
            async with self._session.get(
                url,
                ssl=False,
                allow_redirects=self.follow_redirects,
                max_redirects=self.max_redirects
            ) as response:
                headers = response.headers

                # Extract from each header
                for header_name in self.DOMAIN_HEADERS:
                    if header_name in headers:
                        header_value = headers[header_name]
                        header_domains = self._extract_from_header(
                            header_name,
                            header_value
                        )

                        if header_domains:
                            domains.update(header_domains)
                            metadata["headers_analyzed"].append(header_name)
                            metadata["domains_per_header"][header_name] = len(header_domains)
                            self._logger.debug(
                                f"Found {len(header_domains)} domains in {header_name}"
                            )

                # Track redirects
                metadata["redirects_followed"] = len(response.history)

            # Remove target domain
            domains.discard(base_domain)
            if context.sni:
                domains.discard(context.sni)

            return ExtractionResult(
                domains=list(domains),
                metadata=metadata,
                confidence=0.9,  # Headers are highly reliable
                source="http_headers"
            )

        except Exception as e:
            self._logger.error(f"HTTP headers extraction failed: {e}")
            return ExtractionResult(
                domains=list(domains),
                metadata=metadata,
                confidence=0.3 if domains else 0.0,
                source="http_headers",
                errors=[str(e)]
            )

    def _extract_from_header(
        self,
        header_name: str,
        header_value: str
    ) -> Set[str]:
        """
        Extract domains from a specific header.

        Args:
            header_name: Name of the HTTP header
            header_value: Value of the header

        Returns:
            Set of extracted domains
        """
        domains = set()

        if header_name in ['content-security-policy', 'content-security-policy-report-only']:
            domains.update(self._extract_from_csp(header_value))

        elif header_name == 'access-control-allow-origin':
            domains.update(self._extract_from_cors(header_value))

        elif header_name == 'location':
            domains.update(self._extract_from_url(header_value))

        elif header_name == 'link':
            domains.update(self._extract_from_link(header_value))

        elif header_name == 'alt-svc':
            domains.update(self._extract_from_alt_svc(header_value))

        else:
            # Generic URL extraction
            domains.update(self._extract_urls_generic(header_value))

        return domains

    def _extract_from_csp(self, csp_value: str) -> Set[str]:
        """Extract domains from Content-Security-Policy header."""
        domains = set()

        # CSP directives that may contain domains
        directives = [
            'default-src', 'script-src', 'style-src', 'img-src',
            'connect-src', 'font-src', 'frame-src', 'media-src',
            'object-src', 'worker-src', 'manifest-src', 'form-action'
        ]

        for directive in directives:
            pattern = f"{directive}\\s+([^;]+)"
            matches = re.findall(pattern, csp_value, re.IGNORECASE)

            for match in matches:
                # Extract domains from the directive value
                url_pattern = r'https?://([a-z0-9.-]+\.[a-z]{2,})'
                domain_matches = re.findall(url_pattern, match, re.IGNORECASE)
                domains.update(d.lower() for d in domain_matches)

        return domains

    def _extract_from_cors(self, cors_value: str) -> Set[str]:
        """Extract domain from Access-Control-Allow-Origin header."""
        domains = set()

        # Skip wildcard
        if cors_value == '*':
            return domains

        # Extract domain from URL
        domain = self._extract_domain_from_url(cors_value)
        if domain:
            domains.add(domain)

        return domains

    def _extract_from_link(self, link_value: str) -> Set[str]:
        """Extract domains from Link header."""
        domains = set()

        # Link header format: <url>; rel="relation"
        url_pattern = r'<(https?://[^>]+)>'
        urls = re.findall(url_pattern, link_value)

        for url in urls:
            domain = self._extract_domain_from_url(url)
            if domain:
                domains.add(domain)

        return domains

    def _extract_from_alt_svc(self, alt_svc_value: str) -> Set[str]:
        """Extract domains from Alt-Svc header."""
        domains = set()

        # Alt-Svc format: h2="hostname:port"
        pattern = r'h[23]="([^:"]+):\d+"'
        matches = re.findall(pattern, alt_svc_value)

        for match in matches:
            if '.' in match and self._is_valid_domain(match):
                domains.add(match.lower())

        return domains

    def _extract_from_url(self, url: str) -> Set[str]:
        """Extract domain from a URL."""
        domain = self._extract_domain_from_url(url)
        return {domain} if domain else set()

    def _extract_urls_generic(self, value: str) -> Set[str]:
        """Generic URL extraction from header value."""
        domains = set()

        # Find all URLs
        url_pattern = r'https?://([a-z0-9.-]+\.[a-z]{2,})'
        matches = re.findall(url_pattern, value, re.IGNORECASE)

        for match in matches:
            if self._is_valid_domain(match):
                domains.add(match.lower())

        return domains

    def _extract_domain_from_url(self, url: str) -> Optional[str]:
        """
        Extract domain name from URL.

        Args:
            url: URL string

        Returns:
            Domain name or None if invalid
        """
        # Simple regex-based extraction
        pattern = r'https?://([a-z0-9.-]+\.[a-z]{2,})'
        match = re.search(pattern, url, re.IGNORECASE)

        if match:
            domain = match.group(1).lower()
            if self._is_valid_domain(domain):
                return domain

        return None

    def _is_valid_domain(self, domain: str) -> bool:
        """Validate that a string is a valid domain name."""
        if not domain or len(domain) > 253:
            return False

        if '.' not in domain:
            return False

        if not re.match(r'^[a-z0-9.-]+$', domain, re.IGNORECASE):
            return False

        if domain.startswith(('.', '-')) or domain.endswith(('.', '-')):
            return False

        labels = domain.split('.')
        for label in labels:
            if not label or len(label) > 63:
                return False

        if len(labels[-1]) < 2:
            return False

        return True

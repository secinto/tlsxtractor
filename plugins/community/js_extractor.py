"""
JavaScript Domain Extractor Plugin.

Extracts domain names from inline and external JavaScript files by:
- Fetching the main HTML page
- Extracting inline JavaScript
- Following external JavaScript file references
- Parsing domains from various patterns (URLs, API endpoints, config objects)
"""

import re
import asyncio
from typing import List, Dict, Any, Set
from urllib.parse import urljoin, urlparse

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


class JavaScriptDomainExtractor(DomainExtractorPlugin):
    """
    Extracts domains from JavaScript files (inline and external).

    This plugin:
    1. Fetches the HTML page from the target
    2. Extracts and analyzes inline JavaScript
    3. Identifies and fetches external JS files
    4. Parses multiple domain patterns from JavaScript code
    5. Returns discovered domains with metadata

    Useful for finding:
    - API endpoints
    - CDN domains
    - Third-party service integrations
    - Backend service URLs
    - Configuration domains
    """

    # Regex patterns for extracting domains from JavaScript
    DOMAIN_PATTERNS = [
        # Standard URLs
        r'https?://([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
        # API configurations
        r'["\']api["\']:\s*["\']https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']',
        r'api(?:Url|Endpoint|Host):\s*["\']([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']',
        # Endpoint declarations
        r'endpoint:\s*["\']https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']',
        r'baseURL:\s*["\']https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']',
        # Domain configurations
        r'domain:\s*["\']([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']',
        r'host:\s*["\']([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']',
        # Websocket URLs
        r'wss?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
        # CDN patterns
        r'cdn:\s*["\']https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']',
        # Common framework patterns
        r'axios\.(?:get|post|put|delete)\(["\']https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
        r'fetch\(["\']https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
    ]

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.max_file_size = self.get_config('max_file_size', 5 * 1024 * 1024)  # 5MB default
        self.timeout = self.get_config('timeout', 30)
        self.max_js_files = self.get_config('max_js_files', 10)
        self.follow_external = self.get_config('follow_external', True)
        self.user_agent = self.get_config(
            'user_agent',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        )
        self._session: Optional[aiohttp.ClientSession] = None

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="js_extractor",
            version="1.0.0",
            author="TLSXtractor Team",
            description="Extract domains from JavaScript files (inline and external)",
            dependencies=["aiohttp>=3.8.0"],
            config_schema={
                "max_file_size": {
                    "type": "integer",
                    "default": 5242880,
                    "description": "Maximum JS file size to download (bytes)"
                },
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Request timeout in seconds"
                },
                "max_js_files": {
                    "type": "integer",
                    "default": 10,
                    "description": "Maximum number of external JS files to fetch"
                },
                "follow_external": {
                    "type": "boolean",
                    "default": True,
                    "description": "Fetch and analyze external JavaScript files"
                },
                "user_agent": {
                    "type": "string",
                    "description": "User-Agent header for HTTP requests"
                }
            },
            tags=["extractor", "javascript", "web", "http"]
        )

    async def initialize(self) -> None:
        """Initialize HTTP session."""
        if aiohttp is None:
            raise ImportError(
                "aiohttp is required for JavaScript extractor. "
                "Install with: pip install aiohttp"
            )

        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self._session = aiohttp.ClientSession(
            timeout=timeout,
            headers={'User-Agent': self.user_agent}
        )
        self._logger.info("JavaScript extractor initialized")

    async def cleanup(self) -> None:
        """Close HTTP session."""
        if self._session:
            await self._session.close()
            self._logger.info("JavaScript extractor cleaned up")

    def validate_config(self) -> bool:
        """Validate plugin configuration."""
        if self.max_file_size <= 0:
            raise ValueError("max_file_size must be positive")
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
        if self.max_js_files < 0:
            raise ValueError("max_js_files must be non-negative")
        return True

    async def extract_domains(
        self, context: ExtractionContext
    ) -> ExtractionResult:
        """Extract domains from JavaScript files."""
        domains = set()
        metadata = {
            "html_fetched": False,
            "inline_js_analyzed": False,
            "js_files_analyzed": 0,
            "js_files_found": 0,
            "patterns_matched": {},
            "errors": []
        }

        if not self._session:
            return ExtractionResult(
                domains=[],
                metadata={"error": "Plugin not initialized"},
                confidence=0.0,
                source="js_extractor"
            )

        # Determine base URL
        base_domain = context.sni or context.ip
        base_url = f"https://{base_domain}:{context.port}/"

        try:
            # Fetch main HTML page
            self._logger.debug(f"Fetching HTML from {base_url}")
            html_content = await self._fetch_url(base_url)
            metadata["html_fetched"] = True

            # Extract domains from inline JavaScript
            inline_domains = self._extract_from_js(html_content)
            domains.update(inline_domains)
            metadata["inline_js_analyzed"] = True
            metadata["inline_domains_found"] = len(inline_domains)

            # Find external JavaScript files
            if self.follow_external:
                js_urls = self._find_js_files(html_content, base_url)
                metadata["js_files_found"] = len(js_urls)
                self._logger.debug(f"Found {len(js_urls)} external JS files")

                # Fetch and analyze external JS files
                for js_url in js_urls[:self.max_js_files]:
                    try:
                        self._logger.debug(f"Fetching JS file: {js_url}")
                        js_content = await self._fetch_url(js_url)
                        js_domains = self._extract_from_js(js_content)
                        domains.update(js_domains)
                        metadata["js_files_analyzed"] += 1
                    except Exception as e:
                        error_msg = f"Failed to fetch {js_url}: {e}"
                        self._logger.debug(error_msg)
                        metadata["errors"].append(error_msg)

            # Remove the target domain itself
            domains.discard(base_domain)
            if context.sni:
                domains.discard(context.sni)

            # Calculate confidence based on success
            confidence = 0.8
            if not metadata["html_fetched"]:
                confidence = 0.0
            elif metadata["js_files_found"] > 0 and metadata["js_files_analyzed"] == 0:
                confidence = 0.5

            return ExtractionResult(
                domains=list(domains),
                metadata=metadata,
                confidence=confidence,
                source="js_extractor"
            )

        except Exception as e:
            error_msg = f"JavaScript extraction failed: {e}"
            self._logger.error(error_msg)
            metadata["errors"].append(error_msg)
            return ExtractionResult(
                domains=list(domains),
                metadata=metadata,
                confidence=0.3 if domains else 0.0,
                source="js_extractor",
                errors=[error_msg]
            )

    async def _fetch_url(self, url: str) -> str:
        """
        Fetch URL content with size limit.

        Args:
            url: URL to fetch

        Returns:
            Response text content

        Raises:
            ValueError: If content is too large
            aiohttp.ClientError: If request fails
        """
        async with self._session.get(url, ssl=False) as response:
            # Check content length
            content_length = response.headers.get('Content-Length')
            if content_length and int(content_length) > self.max_file_size:
                raise ValueError(
                    f"Content too large: {content_length} bytes "
                    f"(max: {self.max_file_size})"
                )

            # Read with size limit
            content = await response.text()
            if len(content) > self.max_file_size:
                raise ValueError(
                    f"Content too large: {len(content)} bytes "
                    f"(max: {self.max_file_size})"
                )

            return content

    def _find_js_files(self, html: str, base_url: str) -> List[str]:
        """
        Find JavaScript file URLs in HTML.

        Args:
            html: HTML content
            base_url: Base URL for resolving relative paths

        Returns:
            List of absolute JavaScript file URLs
        """
        urls = []

        # Find script tags with src attribute
        script_pattern = r'<script[^>]+src=["\'](.*?)["\']'
        matches = re.findall(script_pattern, html, re.IGNORECASE)

        for match in matches:
            # Convert to absolute URL
            absolute_url = urljoin(base_url, match)

            # Only include JS files (skip data: and other non-http schemes)
            if absolute_url.startswith(('http://', 'https://')):
                # Check if it's actually a JS file
                if absolute_url.endswith('.js') or 'javascript' in absolute_url.lower():
                    urls.append(absolute_url)

        return urls

    def _extract_from_js(self, js_content: str) -> Set[str]:
        """
        Extract domains from JavaScript content.

        Args:
            js_content: JavaScript code content

        Returns:
            Set of extracted domain names
        """
        domains = set()

        for pattern in self.DOMAIN_PATTERNS:
            try:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    # Clean and validate domain
                    domain = match.strip().lower()
                    if self._is_valid_domain(domain):
                        domains.add(domain)
            except re.error as e:
                self._logger.warning(f"Regex error with pattern {pattern}: {e}")

        return domains

    def _is_valid_domain(self, domain: str) -> bool:
        """
        Validate that a string is a valid domain name.

        Args:
            domain: Domain name to validate

        Returns:
            True if domain appears valid
        """
        # Basic validation
        if not domain or len(domain) > 253:
            return False

        # Must contain at least one dot
        if '.' not in domain:
            return False

        # Check for invalid characters
        if not re.match(r'^[a-z0-9.-]+$', domain):
            return False

        # Must not start or end with dot or hyphen
        if domain.startswith(('.', '-')) or domain.endswith(('.', '-')):
            return False

        # Each label must be valid
        labels = domain.split('.')
        for label in labels:
            if not label or len(label) > 63:
                return False
            if label.startswith('-') or label.endswith('-'):
                return False

        # TLD must be at least 2 characters
        if len(labels[-1]) < 2:
            return False

        return True

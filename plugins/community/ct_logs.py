"""
Certificate Transparency Logs Plugin.

Queries Certificate Transparency (CT) log databases to discover domains
associated with certificates issued for the target. CT logs are public
repositories of SSL/TLS certificates mandated by browsers.
"""

import re
import json
from typing import List, Dict, Any, Set, Optional
from urllib.parse import quote

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


class CertificateTransparencyPlugin(DomainExtractorPlugin):
    """
    Discovers domains through Certificate Transparency log queries.

    This plugin:
    1. Queries public CT log databases (crt.sh, censys.io style APIs)
    2. Retrieves all certificates issued for the target domain
    3. Extracts Subject Alternative Names (SANs) from certificates
    4. Returns discovered domains with certificate metadata

    Useful for finding:
    - All subdomains with valid certificates
    - Historical certificates and domains
    - Wildcard certificate coverage
    - Certificate issuance patterns
    - Associated domains from the same organization
    """

    # CT log API endpoints
    CT_LOG_APIS = {
        'crtsh': 'https://crt.sh/?q={domain}&output=json',
        # Add more CT log APIs as needed
        # 'google': 'https://www.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch',
    }

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.timeout = self.get_config('timeout', 30)
        self.max_results = self.get_config('max_results', 1000)
        self.include_expired = self.get_config('include_expired', True)
        self.include_wildcards = self.get_config('include_wildcards', True)
        self.api_endpoint = self.get_config('api_endpoint', 'crtsh')
        self.user_agent = self.get_config(
            'user_agent',
            'TLSXtractor CT Plugin/1.0'
        )
        self._session: Optional[aiohttp.ClientSession] = None

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="ct_logs",
            version="1.0.0",
            author="TLSXtractor Team",
            description="Extract domains from Certificate Transparency logs",
            dependencies=["aiohttp>=3.8.0"],
            config_schema={
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Request timeout in seconds"
                },
                "max_results": {
                    "type": "integer",
                    "default": 1000,
                    "description": "Maximum number of certificates to process"
                },
                "include_expired": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include expired certificates"
                },
                "include_wildcards": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include wildcard domains"
                },
                "api_endpoint": {
                    "type": "string",
                    "default": "crtsh",
                    "description": "CT log API to use (crtsh)"
                },
                "user_agent": {
                    "type": "string",
                    "description": "User-Agent header for HTTP requests"
                }
            },
            tags=["extractor", "certificate", "ct-logs", "ssl", "tls"]
        )

    async def initialize(self) -> None:
        """Initialize HTTP session."""
        if aiohttp is None:
            raise ImportError(
                "aiohttp is required for CT logs plugin. "
                "Install with: pip install aiohttp"
            )

        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self._session = aiohttp.ClientSession(
            timeout=timeout,
            headers={'User-Agent': self.user_agent}
        )
        self._logger.info("Certificate Transparency plugin initialized")

    async def cleanup(self) -> None:
        """Close HTTP session."""
        if self._session:
            await self._session.close()
            self._logger.info("Certificate Transparency plugin cleaned up")

    def validate_config(self) -> bool:
        """Validate plugin configuration."""
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
        if self.max_results <= 0:
            raise ValueError("max_results must be positive")
        if self.api_endpoint not in self.CT_LOG_APIS:
            raise ValueError(f"Unknown API endpoint: {self.api_endpoint}")
        return True

    async def extract_domains(
        self, context: ExtractionContext
    ) -> ExtractionResult:
        """Extract domains from Certificate Transparency logs."""
        domains = set()
        metadata = {
            "api_endpoint": self.api_endpoint,
            "certificates_found": 0,
            "certificates_processed": 0,
            "expired_certificates": 0,
            "wildcard_domains": 0,
            "query_domain": None,
        }

        if not self._session:
            return ExtractionResult(
                domains=[],
                metadata={"error": "Plugin not initialized"},
                confidence=0.0,
                source="ct_logs"
            )

        try:
            # Determine domain to query
            query_domain = self._extract_query_domain(context)
            if not query_domain:
                return ExtractionResult(
                    domains=[],
                    metadata={"error": "Could not determine domain to query"},
                    confidence=0.0,
                    source="ct_logs"
                )

            metadata["query_domain"] = query_domain
            self._logger.debug(f"Querying CT logs for: {query_domain}")

            # Query CT logs
            certificates = await self._query_ct_logs(query_domain)
            metadata["certificates_found"] = len(certificates)

            # Process certificates and extract domains
            for cert_data in certificates[:self.max_results]:
                cert_domains = self._extract_domains_from_cert(cert_data, metadata)
                domains.update(cert_domains)
                metadata["certificates_processed"] += 1

            # Remove the query domain itself
            domains.discard(query_domain)

            # Calculate confidence
            confidence = 0.95  # CT logs are highly reliable
            if metadata["certificates_found"] == 0:
                confidence = 0.5  # No results might mean API issue

            return ExtractionResult(
                domains=list(domains),
                metadata=metadata,
                confidence=confidence,
                source="ct_logs"
            )

        except Exception as e:
            error_msg = f"CT logs query failed: {e}"
            self._logger.error(error_msg)
            return ExtractionResult(
                domains=list(domains),
                metadata=metadata,
                confidence=0.3 if domains else 0.0,
                source="ct_logs",
                errors=[error_msg]
            )

    def _extract_query_domain(self, context: ExtractionContext) -> Optional[str]:
        """
        Extract the domain to query from context.

        Args:
            context: Extraction context

        Returns:
            Domain to query or None
        """
        # Prefer SNI
        if context.sni:
            return context.sni

        # Try existing domains
        if context.existing_domains:
            return context.existing_domains[0]

        return None

    async def _query_ct_logs(self, domain: str) -> List[Dict[str, Any]]:
        """
        Query Certificate Transparency logs for a domain.

        Args:
            domain: Domain to query

        Returns:
            List of certificate data dictionaries

        Raises:
            aiohttp.ClientError: If request fails
            ValueError: If response is invalid
        """
        # Get API URL
        api_url = self.CT_LOG_APIS[self.api_endpoint].format(
            domain=quote(domain)
        )

        self._logger.debug(f"Querying: {api_url}")

        try:
            async with self._session.get(api_url) as response:
                response.raise_for_status()

                # Parse JSON response
                content_type = response.headers.get('Content-Type', '')
                if 'application/json' not in content_type:
                    text = await response.text()
                    self._logger.warning(
                        f"Unexpected content type: {content_type}. "
                        f"Response preview: {text[:200]}"
                    )
                    return []

                data = await response.json()

                # Handle different API response formats
                if self.api_endpoint == 'crtsh':
                    # crt.sh returns an array directly
                    if isinstance(data, list):
                        return data
                    else:
                        self._logger.warning(f"Unexpected crt.sh response format: {type(data)}")
                        return []

                return []

        except aiohttp.ClientError as e:
            self._logger.error(f"HTTP request failed: {e}")
            raise
        except json.JSONDecodeError as e:
            self._logger.error(f"Failed to parse JSON response: {e}")
            return []

    def _extract_domains_from_cert(
        self,
        cert_data: Dict[str, Any],
        metadata: Dict[str, Any]
    ) -> Set[str]:
        """
        Extract domains from certificate data.

        Args:
            cert_data: Certificate data from CT log API
            metadata: Metadata dictionary to update

        Returns:
            Set of extracted domains
        """
        domains = set()

        try:
            # crt.sh format
            if 'name_value' in cert_data:
                # name_value contains SANs, one per line
                san_text = cert_data['name_value']
                san_domains = san_text.split('\n')

                for domain in san_domains:
                    domain = domain.strip().lower()

                    # Handle wildcard domains
                    if domain.startswith('*.'):
                        metadata["wildcard_domains"] += 1
                        if self.include_wildcards:
                            # Include the base domain without wildcard
                            base_domain = domain[2:]  # Remove "*."
                            if self._is_valid_domain(base_domain):
                                domains.add(base_domain)
                    else:
                        if self._is_valid_domain(domain):
                            domains.add(domain)

            # Check if certificate is expired
            if 'not_after' in cert_data:
                # not_after is typically in ISO format: "2024-12-31T23:59:59"
                # For simplicity, we'll include all if include_expired is True
                # A more sophisticated implementation would parse and check dates
                pass

        except Exception as e:
            self._logger.debug(f"Error extracting domains from cert: {e}")

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

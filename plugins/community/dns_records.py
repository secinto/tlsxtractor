"""
DNS Records Extractor Plugin.

Extracts domain names from various DNS record types including:
- MX (Mail Exchange) records
- NS (Name Server) records
- CNAME (Canonical Name) records
- TXT (Text) records
- SRV (Service) records
- PTR (Pointer) records
"""

import re
from typing import List, Dict, Any, Set, Optional

try:
    import aiodns
except ImportError:
    aiodns = None

from tlsxtractor.plugins.base import (
    DomainExtractorPlugin,
    PluginMetadata,
    ExtractionContext,
    ExtractionResult,
)


class DNSRecordsExtractor(DomainExtractorPlugin):
    """
    Extracts domains from DNS records.

    This plugin queries various DNS record types that commonly
    contain domain references:
    - MX records (mail servers)
    - NS records (name servers)
    - CNAME records (aliases)
    - TXT records (verification, SPF, DKIM, DMARC)
    - SRV records (service locations)
    - PTR records (reverse DNS)

    Useful for finding:
    - Mail infrastructure (MX, TXT with SPF)
    - Authoritative name servers (NS)
    - Domain aliases and redirects (CNAME)
    - Service providers (TXT records often contain third-party domains)
    - Service endpoints (SRV)
    """

    # DNS record types to query
    RECORD_TYPES = ['MX', 'NS', 'CNAME', 'TXT', 'SRV']

    # Common SRV service prefixes
    SRV_SERVICES = [
        '_http._tcp',
        '_https._tcp',
        '_ldap._tcp',
        '_xmpp-client._tcp',
        '_xmpp-server._tcp',
        '_jabber._tcp',
        '_sip._tcp',
        '_sip._udp',
        '_caldav._tcp',
        '_carddav._tcp',
    ]

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.timeout = self.get_config('timeout', 5)
        self.query_mx = self.get_config('query_mx', True)
        self.query_ns = self.get_config('query_ns', True)
        self.query_cname = self.get_config('query_cname', True)
        self.query_txt = self.get_config('query_txt', True)
        self.query_srv = self.get_config('query_srv', True)
        self.parse_txt_records = self.get_config('parse_txt_records', True)
        self._resolver: Optional[aiodns.DNSResolver] = None

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="dns_records",
            version="1.0.0",
            author="TLSXtractor Team",
            description="Extract domains from DNS records (MX, NS, TXT, CNAME, SRV)",
            dependencies=["aiodns>=3.0.0", "pycares>=4.0.0"],
            config_schema={
                "timeout": {
                    "type": "integer",
                    "default": 5,
                    "description": "DNS query timeout in seconds"
                },
                "query_mx": {
                    "type": "boolean",
                    "default": True,
                    "description": "Query MX records"
                },
                "query_ns": {
                    "type": "boolean",
                    "default": True,
                    "description": "Query NS records"
                },
                "query_cname": {
                    "type": "boolean",
                    "default": True,
                    "description": "Query CNAME records"
                },
                "query_txt": {
                    "type": "boolean",
                    "default": True,
                    "description": "Query TXT records"
                },
                "query_srv": {
                    "type": "boolean",
                    "default": True,
                    "description": "Query SRV records"
                },
                "parse_txt_records": {
                    "type": "boolean",
                    "default": True,
                    "description": "Extract domains from TXT record content"
                }
            },
            tags=["extractor", "dns", "records", "mx", "ns", "txt"]
        )

    async def initialize(self) -> None:
        """Initialize DNS resolver."""
        if aiodns is None:
            raise ImportError(
                "aiodns is required for DNS records extractor. "
                "Install with: pip install aiodns pycares"
            )

        self._resolver = aiodns.DNSResolver(timeout=self.timeout)
        self._logger.info("DNS records extractor initialized")

    async def cleanup(self) -> None:
        """Cleanup resources."""
        self._logger.info("DNS records extractor cleaned up")

    def validate_config(self) -> bool:
        """Validate plugin configuration."""
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
        return True

    async def extract_domains(
        self, context: ExtractionContext
    ) -> ExtractionResult:
        """Extract domains from DNS records."""
        domains = set()
        metadata = {
            "target_domain": None,
            "records_queried": [],
            "records_found": {},
            "txt_domains_extracted": 0,
        }

        if not self._resolver:
            return ExtractionResult(
                domains=[],
                metadata={"error": "Plugin not initialized"},
                confidence=0.0,
                source="dns_records"
            )

        try:
            # Determine target domain
            target_domain = self._extract_target_domain(context)
            if not target_domain:
                return ExtractionResult(
                    domains=[],
                    metadata={"error": "Could not determine target domain"},
                    confidence=0.0,
                    source="dns_records"
                )

            metadata["target_domain"] = target_domain
            self._logger.debug(f"Querying DNS records for: {target_domain}")

            # Query MX records
            if self.query_mx:
                mx_domains = await self._query_mx(target_domain, metadata)
                domains.update(mx_domains)

            # Query NS records
            if self.query_ns:
                ns_domains = await self._query_ns(target_domain, metadata)
                domains.update(ns_domains)

            # Query CNAME records
            if self.query_cname:
                cname_domains = await self._query_cname(target_domain, metadata)
                domains.update(cname_domains)

            # Query TXT records
            if self.query_txt:
                txt_domains = await self._query_txt(target_domain, metadata)
                domains.update(txt_domains)

            # Query SRV records
            if self.query_srv:
                srv_domains = await self._query_srv(target_domain, metadata)
                domains.update(srv_domains)

            # Remove target domain itself
            domains.discard(target_domain)

            # Calculate confidence based on records found
            confidence = 0.9 if domains else 0.7

            return ExtractionResult(
                domains=list(domains),
                metadata=metadata,
                confidence=confidence,
                source="dns_records"
            )

        except Exception as e:
            error_msg = f"DNS records extraction failed: {e}"
            self._logger.error(error_msg)
            return ExtractionResult(
                domains=list(domains),
                metadata=metadata,
                confidence=0.3 if domains else 0.0,
                source="dns_records",
                errors=[error_msg]
            )

    def _extract_target_domain(self, context: ExtractionContext) -> Optional[str]:
        """
        Extract the target domain from context.

        Args:
            context: Extraction context

        Returns:
            Target domain or None
        """
        # Prefer SNI
        if context.sni:
            return context.sni

        # Try existing domains
        if context.existing_domains:
            return context.existing_domains[0]

        return None

    async def _query_mx(
        self,
        domain: str,
        metadata: Dict[str, Any]
    ) -> Set[str]:
        """
        Query MX records and extract mail server domains.

        Args:
            domain: Domain to query
            metadata: Metadata dictionary to update

        Returns:
            Set of extracted domains
        """
        domains = set()
        metadata["records_queried"].append("MX")

        try:
            records = await self._resolver.query(domain, 'MX')
            metadata["records_found"]["MX"] = len(records)

            for record in records:
                # MX record has 'host' attribute containing mail server domain
                mx_domain = record.host.strip('.').lower()
                if self._is_valid_domain(mx_domain):
                    domains.add(mx_domain)
                    self._logger.debug(f"Found MX: {mx_domain}")

        except aiodns.error.DNSError as e:
            self._logger.debug(f"No MX records for {domain}: {e}")
            metadata["records_found"]["MX"] = 0

        return domains

    async def _query_ns(
        self,
        domain: str,
        metadata: Dict[str, Any]
    ) -> Set[str]:
        """
        Query NS records and extract name server domains.

        Args:
            domain: Domain to query
            metadata: Metadata dictionary to update

        Returns:
            Set of extracted domains
        """
        domains = set()
        metadata["records_queried"].append("NS")

        try:
            records = await self._resolver.query(domain, 'NS')
            metadata["records_found"]["NS"] = len(records)

            for record in records:
                # NS record has 'host' attribute
                ns_domain = record.host.strip('.').lower()
                if self._is_valid_domain(ns_domain):
                    domains.add(ns_domain)
                    self._logger.debug(f"Found NS: {ns_domain}")

        except aiodns.error.DNSError as e:
            self._logger.debug(f"No NS records for {domain}: {e}")
            metadata["records_found"]["NS"] = 0

        return domains

    async def _query_cname(
        self,
        domain: str,
        metadata: Dict[str, Any]
    ) -> Set[str]:
        """
        Query CNAME record and extract canonical name.

        Args:
            domain: Domain to query
            metadata: Metadata dictionary to update

        Returns:
            Set of extracted domains
        """
        domains = set()
        metadata["records_queried"].append("CNAME")

        try:
            records = await self._resolver.query(domain, 'CNAME')
            metadata["records_found"]["CNAME"] = len(records)

            for record in records:
                # CNAME record has 'cname' attribute
                cname_domain = record.cname.strip('.').lower()
                if self._is_valid_domain(cname_domain):
                    domains.add(cname_domain)
                    self._logger.debug(f"Found CNAME: {cname_domain}")

        except aiodns.error.DNSError as e:
            self._logger.debug(f"No CNAME records for {domain}: {e}")
            metadata["records_found"]["CNAME"] = 0

        return domains

    async def _query_txt(
        self,
        domain: str,
        metadata: Dict[str, Any]
    ) -> Set[str]:
        """
        Query TXT records and extract domains from content.

        Args:
            domain: Domain to query
            metadata: Metadata dictionary to update

        Returns:
            Set of extracted domains
        """
        domains = set()
        metadata["records_queried"].append("TXT")

        try:
            records = await self._resolver.query(domain, 'TXT')
            metadata["records_found"]["TXT"] = len(records)

            for record in records:
                # TXT record has 'text' attribute (bytes)
                txt_content = record.text.decode('utf-8', errors='ignore')
                self._logger.debug(f"TXT record: {txt_content[:100]}")

                if self.parse_txt_records:
                    # Extract domains from TXT content
                    extracted = self._extract_domains_from_txt(txt_content)
                    domains.update(extracted)
                    metadata["txt_domains_extracted"] += len(extracted)

        except aiodns.error.DNSError as e:
            self._logger.debug(f"No TXT records for {domain}: {e}")
            metadata["records_found"]["TXT"] = 0

        return domains

    async def _query_srv(
        self,
        domain: str,
        metadata: Dict[str, Any]
    ) -> Set[str]:
        """
        Query SRV records for common services.

        Args:
            domain: Domain to query
            metadata: Metadata dictionary to update

        Returns:
            Set of extracted domains
        """
        domains = set()
        metadata["records_queried"].append("SRV")
        srv_found = 0

        for service in self.SRV_SERVICES:
            srv_domain = f"{service}.{domain}"

            try:
                records = await self._resolver.query(srv_domain, 'SRV')
                srv_found += len(records)

                for record in records:
                    # SRV record has 'host' attribute
                    target_domain = record.host.strip('.').lower()
                    if self._is_valid_domain(target_domain):
                        domains.add(target_domain)
                        self._logger.debug(f"Found SRV target: {target_domain}")

            except aiodns.error.DNSError:
                # SRV record doesn't exist for this service
                pass

        metadata["records_found"]["SRV"] = srv_found
        return domains

    def _extract_domains_from_txt(self, txt_content: str) -> Set[str]:
        """
        Extract domains from TXT record content.

        Looks for domains in:
        - SPF records (v=spf1 include:domain.com)
        - DKIM records
        - DMARC records (rua=mailto:user@domain.com)
        - Verification records
        - General domain references

        Args:
            txt_content: TXT record content

        Returns:
            Set of extracted domains
        """
        domains = set()

        # SPF records: include:domain.com, redirect=domain.com
        spf_pattern = r'(?:include|redirect)[=:]([a-z0-9.-]+\.[a-z]{2,})'
        spf_matches = re.findall(spf_pattern, txt_content, re.IGNORECASE)
        for domain in spf_matches:
            if self._is_valid_domain(domain):
                domains.add(domain.lower())

        # DMARC records: rua=mailto:user@domain.com
        dmarc_pattern = r'mailto:[^@]+@([a-z0-9.-]+\.[a-z]{2,})'
        dmarc_matches = re.findall(dmarc_pattern, txt_content, re.IGNORECASE)
        for domain in dmarc_matches:
            if self._is_valid_domain(domain):
                domains.add(domain.lower())

        # General domain pattern (with protocol)
        url_pattern = r'https?://([a-z0-9.-]+\.[a-z]{2,})'
        url_matches = re.findall(url_pattern, txt_content, re.IGNORECASE)
        for domain in url_matches:
            if self._is_valid_domain(domain):
                domains.add(domain.lower())

        # General domain pattern (without protocol)
        # Be more conservative to avoid false positives
        domain_pattern = r'\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        domain_matches = re.findall(domain_pattern, txt_content, re.IGNORECASE)
        for match in domain_matches:
            domain = match[0] if isinstance(match, tuple) else match
            domain = domain.strip('.').lower()
            if self._is_valid_domain(domain) and len(domain) > 4:
                domains.add(domain)

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

"""
Subdomain Enumeration Plugin.

Discovers subdomains through DNS enumeration using common subdomain wordlists.
This plugin performs DNS lookups for potential subdomains to identify valid hosts.
"""

import asyncio
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


class SubdomainEnumerationPlugin(DomainExtractorPlugin):
    """
    Discovers subdomains through DNS enumeration.

    This plugin:
    1. Extracts the base domain from the target
    2. Tests common subdomain prefixes via DNS lookups
    3. Returns discovered valid subdomains
    4. Supports custom wordlists

    Useful for finding:
    - Development/staging environments (dev., staging., test.)
    - Administrative interfaces (admin., panel., dashboard.)
    - API endpoints (api., api-v2., rest.)
    - Mail servers (mail., smtp., webmail.)
    - Infrastructure (vpn., proxy., cdn.)
    """

    # Common subdomain prefixes to test
    DEFAULT_WORDLIST = [
        # Development & Testing
        'dev', 'development', 'test', 'testing', 'stage', 'staging',
        'uat', 'qa', 'demo', 'sandbox', 'lab',

        # Administrative
        'admin', 'administrator', 'panel', 'dashboard', 'console',
        'portal', 'manage', 'management', 'control',

        # APIs & Services
        'api', 'api-v1', 'api-v2', 'rest', 'graphql', 'ws', 'websocket',
        'oauth', 'auth', 'sso', 'login', 'account',

        # Web Infrastructure
        'www', 'www1', 'www2', 'web', 'web1', 'web2',
        'static', 'assets', 'cdn', 'media', 'images', 'img',

        # Mail Services
        'mail', 'email', 'smtp', 'pop', 'imap', 'webmail',
        'mx', 'mx1', 'mx2', 'mailserver',

        # Networking & Infrastructure
        'vpn', 'proxy', 'gateway', 'firewall', 'router',
        'ns', 'ns1', 'ns2', 'dns', 'dns1', 'dns2',

        # Databases & Storage
        'db', 'database', 'mysql', 'postgres', 'mongo',
        'redis', 'cache', 'memcache', 'storage', 'backup',

        # Monitoring & Logs
        'monitor', 'monitoring', 'metrics', 'grafana', 'kibana',
        'logs', 'logging', 'elk', 'analytics', 'stats',

        # Mobile & Apps
        'mobile', 'app', 'apps', 'android', 'ios',
        'm', 'wap',

        # Documentation & Help
        'docs', 'documentation', 'help', 'support', 'wiki',
        'kb', 'knowledgebase', 'faq',

        # Version Control & CI/CD
        'git', 'gitlab', 'github', 'bitbucket', 'svn',
        'ci', 'jenkins', 'build', 'deploy',

        # Cloud & Hosting
        'cloud', 'aws', 'azure', 'gcp', 's3',
        'bucket', 'storage',

        # Regional/Localization
        'us', 'eu', 'asia', 'uk', 'de', 'fr', 'jp',
        'east', 'west', 'north', 'south',

        # Common Prefixes
        'internal', 'external', 'public', 'private',
        'secure', 'beta', 'alpha', 'prod', 'production',
        'old', 'new', 'legacy', 'v1', 'v2', 'v3',
    ]

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.timeout = self.get_config('timeout', 3)
        self.max_concurrent = self.get_config('max_concurrent', 50)
        self.custom_wordlist = self.get_config('custom_wordlist', None)
        self.use_default_wordlist = self.get_config('use_default_wordlist', True)
        self.recursive = self.get_config('recursive', False)
        self.recursive_depth = self.get_config('recursive_depth', 1)
        self._resolver: Optional[aiodns.DNSResolver] = None

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="subdomain_enum",
            version="1.0.0",
            author="TLSXtractor Team",
            description="Discover subdomains through DNS enumeration",
            dependencies=["aiodns>=3.0.0", "pycares>=4.0.0"],
            config_schema={
                "timeout": {
                    "type": "integer",
                    "default": 3,
                    "description": "DNS query timeout in seconds"
                },
                "max_concurrent": {
                    "type": "integer",
                    "default": 50,
                    "description": "Maximum concurrent DNS queries"
                },
                "custom_wordlist": {
                    "type": "string",
                    "description": "Path to custom subdomain wordlist file"
                },
                "use_default_wordlist": {
                    "type": "boolean",
                    "default": True,
                    "description": "Use built-in wordlist"
                },
                "recursive": {
                    "type": "boolean",
                    "default": False,
                    "description": "Recursively enumerate discovered subdomains"
                },
                "recursive_depth": {
                    "type": "integer",
                    "default": 1,
                    "description": "Maximum recursive enumeration depth"
                }
            },
            tags=["extractor", "dns", "subdomain", "enumeration"]
        )

    async def initialize(self) -> None:
        """Initialize DNS resolver."""
        if aiodns is None:
            raise ImportError(
                "aiodns is required for subdomain enumeration. "
                "Install with: pip install aiodns pycares"
            )

        self._resolver = aiodns.DNSResolver(timeout=self.timeout)
        self._logger.info("Subdomain enumeration plugin initialized")

    async def cleanup(self) -> None:
        """Cleanup resources."""
        self._logger.info("Subdomain enumeration plugin cleaned up")

    def validate_config(self) -> bool:
        """Validate plugin configuration."""
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
        if self.max_concurrent <= 0:
            raise ValueError("max_concurrent must be positive")
        if self.recursive_depth < 0:
            raise ValueError("recursive_depth must be non-negative")

        # Validate custom wordlist file if provided
        if self.custom_wordlist:
            try:
                with open(self.custom_wordlist, 'r') as f:
                    pass
            except FileNotFoundError:
                raise ValueError(f"Custom wordlist file not found: {self.custom_wordlist}")

        return True

    async def extract_domains(
        self, context: ExtractionContext
    ) -> ExtractionResult:
        """Extract domains through subdomain enumeration."""
        domains = set()
        metadata = {
            "base_domain": None,
            "subdomains_tested": 0,
            "subdomains_found": 0,
            "wordlist_size": 0,
            "dns_errors": 0,
            "recursive_depth_used": 0,
        }

        if not self._resolver:
            return ExtractionResult(
                domains=[],
                metadata={"error": "Plugin not initialized"},
                confidence=0.0,
                source="subdomain_enum"
            )

        try:
            # Determine base domain to enumerate
            base_domain = self._extract_base_domain(context)
            if not base_domain:
                return ExtractionResult(
                    domains=[],
                    metadata={"error": "Could not determine base domain"},
                    confidence=0.0,
                    source="subdomain_enum"
                )

            metadata["base_domain"] = base_domain
            self._logger.debug(f"Enumerating subdomains for: {base_domain}")

            # Build wordlist
            wordlist = self._build_wordlist()
            metadata["wordlist_size"] = len(wordlist)

            # Enumerate subdomains
            discovered = await self._enumerate_subdomains(
                base_domain,
                wordlist,
                metadata
            )
            domains.update(discovered)

            # Recursive enumeration if enabled
            if self.recursive and discovered and self.recursive_depth > 0:
                recursive_domains = await self._recursive_enumerate(
                    discovered,
                    wordlist,
                    depth=1,
                    metadata=metadata
                )
                domains.update(recursive_domains)

            metadata["subdomains_found"] = len(domains)

            # Calculate confidence based on results
            confidence = 0.95 if domains else 0.7  # DNS is highly reliable

            return ExtractionResult(
                domains=list(domains),
                metadata=metadata,
                confidence=confidence,
                source="subdomain_enum"
            )

        except Exception as e:
            error_msg = f"Subdomain enumeration failed: {e}"
            self._logger.error(error_msg)
            return ExtractionResult(
                domains=list(domains),
                metadata=metadata,
                confidence=0.3 if domains else 0.0,
                source="subdomain_enum",
                errors=[error_msg]
            )

    def _extract_base_domain(self, context: ExtractionContext) -> Optional[str]:
        """
        Extract the base domain to enumerate from context.

        Args:
            context: Extraction context

        Returns:
            Base domain or None
        """
        # Prefer SNI, fall back to existing domains
        if context.sni:
            return context.sni

        # Try to get domain from existing domains list
        if context.existing_domains:
            return context.existing_domains[0]

        return None

    def _build_wordlist(self) -> List[str]:
        """
        Build the subdomain wordlist from configured sources.

        Returns:
            List of subdomain prefixes to test
        """
        wordlist = set()

        # Add default wordlist if enabled
        if self.use_default_wordlist:
            wordlist.update(self.DEFAULT_WORDLIST)

        # Add custom wordlist if provided
        if self.custom_wordlist:
            try:
                with open(self.custom_wordlist, 'r') as f:
                    for line in f:
                        subdomain = line.strip()
                        if subdomain and not subdomain.startswith('#'):
                            wordlist.add(subdomain)
                self._logger.debug(f"Loaded {len(wordlist)} entries from custom wordlist")
            except Exception as e:
                self._logger.warning(f"Failed to load custom wordlist: {e}")

        return sorted(wordlist)

    async def _enumerate_subdomains(
        self,
        base_domain: str,
        wordlist: List[str],
        metadata: Dict[str, Any]
    ) -> Set[str]:
        """
        Enumerate subdomains for a base domain.

        Args:
            base_domain: Base domain to enumerate
            wordlist: List of subdomain prefixes to test
            metadata: Metadata dictionary to update

        Returns:
            Set of discovered subdomains
        """
        discovered = set()
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def check_subdomain(prefix: str) -> Optional[str]:
            """Check if subdomain exists via DNS lookup."""
            subdomain = f"{prefix}.{base_domain}"

            async with semaphore:
                try:
                    # Try A record lookup
                    await self._resolver.query(subdomain, 'A')
                    self._logger.debug(f"Found subdomain: {subdomain}")
                    return subdomain
                except aiodns.error.DNSError:
                    # Subdomain doesn't exist or lookup failed
                    metadata["dns_errors"] += 1
                    return None
                except Exception as e:
                    self._logger.debug(f"DNS query error for {subdomain}: {e}")
                    metadata["dns_errors"] += 1
                    return None

        # Create tasks for all subdomains
        tasks = [check_subdomain(prefix) for prefix in wordlist]
        metadata["subdomains_tested"] = len(tasks)

        # Execute with progress tracking
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect successful discoveries
        for result in results:
            if isinstance(result, str) and result:
                discovered.add(result)

        return discovered

    async def _recursive_enumerate(
        self,
        domains: Set[str],
        wordlist: List[str],
        depth: int,
        metadata: Dict[str, Any]
    ) -> Set[str]:
        """
        Recursively enumerate subdomains of discovered domains.

        Args:
            domains: Previously discovered domains to enumerate
            wordlist: Subdomain wordlist
            depth: Current recursion depth
            metadata: Metadata dictionary to update

        Returns:
            Set of newly discovered domains
        """
        if depth > self.recursive_depth:
            return set()

        metadata["recursive_depth_used"] = max(
            metadata["recursive_depth_used"],
            depth
        )

        all_discovered = set()

        for domain in domains:
            self._logger.debug(f"Recursive enumeration of {domain} (depth={depth})")
            discovered = await self._enumerate_subdomains(
                domain,
                wordlist,
                metadata
            )

            if discovered:
                all_discovered.update(discovered)

                # Recurse deeper if enabled
                if depth < self.recursive_depth:
                    deeper = await self._recursive_enumerate(
                        discovered,
                        wordlist,
                        depth + 1,
                        metadata
                    )
                    all_discovered.update(deeper)

        return all_discovered

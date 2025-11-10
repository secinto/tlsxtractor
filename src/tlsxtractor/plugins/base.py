"""
Base classes for TLSXtractor plugins.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
import logging


logger = logging.getLogger(__name__)


@dataclass
class PluginMetadata:
    """
    Plugin metadata and configuration information.

    Attributes:
        name: Unique plugin identifier
        version: Plugin version (semver)
        author: Plugin author/maintainer
        description: Brief description of plugin functionality
        dependencies: List of required Python packages
        config_schema: JSON schema for plugin configuration
        tags: Category tags for plugin discovery
    """
    name: str
    version: str
    author: str
    description: str
    dependencies: List[str] = field(default_factory=list)
    config_schema: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)


@dataclass
class ExtractionContext:
    """
    Context provided to domain extractor plugins.

    Contains all information available about the target that can be
    used for domain extraction.

    Attributes:
        ip: Target IP address
        port: Target port number
        sni: Server Name Indication (if available)
        certificate: Parsed certificate information (if available)
        http_response: HTTP response data (if available)
        existing_domains: Domains already discovered from other sources
        scan_config: Scan configuration dictionary
        metadata: Additional metadata
    """
    ip: str
    port: int
    sni: Optional[str] = None
    certificate: Optional[Dict[str, Any]] = None
    http_response: Optional[Dict[str, Any]] = None
    existing_domains: List[str] = field(default_factory=list)
    scan_config: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExtractionResult:
    """
    Result from domain extraction.

    Attributes:
        domains: List of discovered domain names
        metadata: Additional metadata about the extraction
        confidence: Confidence score (0.0 to 1.0)
        source: Name of the extraction source
        errors: List of errors encountered (if any)
    """
    domains: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    source: str = "unknown"
    errors: List[str] = field(default_factory=list)


class DomainExtractorPlugin(ABC):
    """
    Base class for domain extractor plugins.

    Domain extractor plugins analyze targets and extract domain names
    from various sources (certificates, HTTP headers, JavaScript, etc.).

    Plugins should:
    - Inherit from this class
    - Implement get_metadata() and extract_domains()
    - Optionally override initialize() and cleanup() for resource management
    - Be stateless when possible (multiple instances may be created)
    """

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize plugin with configuration.

        Args:
            config: Plugin-specific configuration dictionary
        """
        self.config = config or {}
        self._enabled = True
        self._logger = logging.getLogger(f"plugin.{self.__class__.__name__}")

    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """
        Get plugin metadata.

        Returns:
            Plugin metadata including name, version, description, etc.
        """
        pass

    @abstractmethod
    async def extract_domains(
        self, context: ExtractionContext
    ) -> ExtractionResult:
        """
        Extract domains from the given context.

        This is the main plugin method that performs domain extraction.
        Should be idempotent and handle errors gracefully.

        Args:
            context: Extraction context with target information

        Returns:
            Extraction result with discovered domains and metadata
        """
        pass

    async def initialize(self) -> None:
        """
        Initialize plugin resources.

        Called once when plugin is loaded. Override to set up
        resources like HTTP clients, database connections, caches, etc.

        Example:
            async def initialize(self):
                self._session = aiohttp.ClientSession()
                self._cache = {}
        """
        pass

    async def cleanup(self) -> None:
        """
        Clean up plugin resources.

        Called when plugin is unloaded. Override to clean up
        any resources allocated in initialize().

        Example:
            async def cleanup(self):
                if self._session:
                    await self._session.close()
        """
        pass

    def validate_config(self) -> bool:
        """
        Validate plugin configuration.

        Override to implement custom configuration validation.
        Should raise ValueError if configuration is invalid.

        Returns:
            True if configuration is valid

        Raises:
            ValueError: If configuration is invalid
        """
        return True

    def enable(self) -> None:
        """Enable this plugin."""
        self._enabled = True
        self._logger.info(f"Plugin {self.get_metadata().name} enabled")

    def disable(self) -> None:
        """Disable this plugin."""
        self._enabled = False
        self._logger.info(f"Plugin {self.get_metadata().name} disabled")

    def is_enabled(self) -> bool:
        """
        Check if plugin is enabled.

        Returns:
            True if plugin is enabled and will be executed
        """
        return self._enabled

    def get_config(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value.

        Args:
            key: Configuration key
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        return self.config.get(key, default)


class FilterPlugin(ABC):
    """
    Base class for domain filter plugins.

    Filter plugins process lists of domains and filter them based
    on custom criteria (reputation, blocklists, patterns, etc.).
    """

    def __init__(self, config: Dict[str, Any] = None):
        """Initialize filter plugin with configuration."""
        self.config = config or {}
        self._enabled = True
        self._logger = logging.getLogger(f"plugin.{self.__class__.__name__}")

    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        pass

    @abstractmethod
    async def filter_domains(self, domains: List[str]) -> List[str]:
        """
        Filter domains based on plugin criteria.

        Args:
            domains: List of domains to filter

        Returns:
            Filtered list of domains
        """
        pass

    async def initialize(self) -> None:
        """Initialize plugin resources."""
        pass

    async def cleanup(self) -> None:
        """Clean up plugin resources."""
        pass

    def validate_config(self) -> bool:
        """Validate plugin configuration."""
        return True

    def enable(self) -> None:
        """Enable this plugin."""
        self._enabled = True

    def disable(self) -> None:
        """Disable this plugin."""
        self._enabled = False

    def is_enabled(self) -> bool:
        """Check if plugin is enabled."""
        return self._enabled


class EnrichmentPlugin(ABC):
    """
    Base class for domain enrichment plugins.

    Enrichment plugins add additional metadata to discovered domains
    (WHOIS data, DNS records, reputation scores, etc.).
    """

    def __init__(self, config: Dict[str, Any] = None):
        """Initialize enrichment plugin with configuration."""
        self.config = config or {}
        self._enabled = True
        self._logger = logging.getLogger(f"plugin.{self.__class__.__name__}")

    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        pass

    @abstractmethod
    async def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """
        Enrich domain with additional metadata.

        Args:
            domain: Domain name to enrich

        Returns:
            Dictionary with enrichment data
        """
        pass

    async def enrich_domains(self, domains: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Enrich multiple domains.

        Default implementation calls enrich_domain() for each domain.
        Override for batch processing optimizations.

        Args:
            domains: List of domains to enrich

        Returns:
            Dictionary mapping domain names to enrichment data
        """
        results = {}
        for domain in domains:
            try:
                results[domain] = await self.enrich_domain(domain)
            except Exception as e:
                self._logger.error(f"Failed to enrich {domain}: {e}")
                results[domain] = {"error": str(e)}
        return results

    async def initialize(self) -> None:
        """Initialize plugin resources."""
        pass

    async def cleanup(self) -> None:
        """Clean up plugin resources."""
        pass

    def validate_config(self) -> bool:
        """Validate plugin configuration."""
        return True

    def enable(self) -> None:
        """Enable this plugin."""
        self._enabled = True

    def disable(self) -> None:
        """Disable this plugin."""
        self._enabled = False

    def is_enabled(self) -> bool:
        """Check if plugin is enabled."""
        return self._enabled

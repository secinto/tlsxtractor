# TLSXtractor Plugin System

The TLSXtractor plugin system enables extensible domain extraction through custom plugins. This document covers the plugin architecture, available plugins, configuration, and custom plugin development.

## Table of Contents

- [Overview](#overview)
- [Plugin Types](#plugin-types)
- [Available Plugins](#available-plugins)
- [Using Plugins](#using-plugins)
- [Configuration](#configuration)
- [Creating Custom Plugins](#creating-custom-plugins)
- [Plugin Development Best Practices](#plugin-development-best-practices)

## Overview

The plugin system allows you to:

- **Extend extraction capabilities** - Add new domain discovery methods
- **Filter results** - Apply custom filtering logic
- **Enrich data** - Add metadata and intelligence to discovered domains
- **Customize behavior** - Configure plugins for your specific needs

### Architecture

```
┌─────────────────────────────────────────┐
│         Plugin Manager                  │
├─────────────────────────────────────────┤
│  - Plugin Discovery                     │
│  - Lifecycle Management                 │
│  - Execution Coordination               │
│  - Configuration Validation             │
└─────────────────────────────────────────┘
            ↓           ↓          ↓
  ┌─────────────┐ ┌──────────┐ ┌─────────────┐
  │  Extractor  │ │  Filter  │ │ Enrichment  │
  │   Plugins   │ │  Plugins │ │   Plugins   │
  └─────────────┘ └──────────┘ └─────────────┘
```

## Plugin Types

### 1. Domain Extractor Plugins

Extract domains from various sources:
- Web content (JavaScript, HTML, headers)
- DNS infrastructure (subdomains, records)
- Certificate databases (CT logs)
- Third-party APIs

**Base Class**: `DomainExtractorPlugin`

### 2. Filter Plugins

Filter and validate discovered domains:
- Block private/internal domains
- Remove noise (CDNs, third-party services)
- Apply allowlists/blocklists
- Validate domain quality

**Base Class**: `FilterPlugin`

### 3. Enrichment Plugins

Add intelligence to discovered domains:
- Geolocation data
- Threat intelligence
- Historical data
- Ownership information

**Base Class**: `EnrichmentPlugin`

## Available Plugins

### JavaScript Extractor (`js_extractor`)

**Purpose**: Extracts domains from inline and external JavaScript files.

**What it discovers**:
- API endpoints
- CDN domains
- Backend service URLs
- Third-party integrations

**How it works**:
1. Fetches the target's HTML page
2. Extracts and analyzes inline JavaScript
3. Follows external JavaScript file references
4. Parses domains using multiple regex patterns

**Configuration**:
```python
{
    "max_file_size": 5242880,      # 5MB max per JS file
    "timeout": 30,                  # HTTP request timeout
    "max_js_files": 10,             # Max external JS files to fetch
    "follow_external": True,        # Fetch external JS files
    "user_agent": "Mozilla/5.0..."  # Custom User-Agent
}
```

**Example Usage**:
```python
from tlsxtractor.plugins.manager import PluginManager
from tlsxtractor.plugins.base import ExtractionContext

# Initialize plugin manager
manager = PluginManager()

# Load JavaScript extractor plugin
await manager.load_plugin("js_extractor", {
    "timeout": 30,
    "max_js_files": 15
})

# Create extraction context
context = ExtractionContext(
    ip="93.184.216.34",
    port=443,
    sni="example.com"
)

# Execute plugin
results = await manager.execute_plugins(context)
for result in results:
    if result.source == "js_extractor":
        print(f"Found {len(result.domains)} domains")
        print(f"Analyzed {result.metadata['js_files_analyzed']} JS files")
```

---

### HTTP Headers Extractor (`http_headers`)

**Purpose**: Extracts domains from HTTP response headers.

**What it discovers**:
- CSP-allowed domains
- CORS-allowed origins
- CDN domains from Link headers
- Redirect destinations

**Headers analyzed**:
- Content-Security-Policy (CSP)
- Access-Control-Allow-Origin (CORS)
- Location (redirects)
- Link (preload/prefetch)
- Alt-Svc (alternative services)
- Strict-Transport-Security

**Configuration**:
```python
{
    "timeout": 10,              # HTTP request timeout
    "follow_redirects": True,   # Follow redirect chains
    "max_redirects": 3,         # Max redirects to follow
    "custom_headers": {}        # Custom HTTP headers
}
```

**Example Usage**:
```python
await manager.load_plugin("http_headers", {
    "follow_redirects": True,
    "max_redirects": 5
})

context = ExtractionContext(
    ip="93.184.216.34",
    port=443,
    sni="example.com"
)

results = await manager.execute_plugins(context)
for result in results:
    if result.source == "http_headers":
        print(f"Headers analyzed: {result.metadata['headers_analyzed']}")
        print(f"Domains per header: {result.metadata['domains_per_header']}")
```

---

### Subdomain Enumeration (`subdomain_enum`)

**Purpose**: Discovers subdomains through DNS enumeration using wordlists.

**What it discovers**:
- Development/staging environments (dev., test., staging.)
- Administrative interfaces (admin., panel., dashboard.)
- API endpoints (api., api-v2., rest.)
- Mail servers (mail., smtp., webmail.)
- Infrastructure (vpn., proxy., cdn.)

**How it works**:
1. Uses a built-in wordlist of 100+ common subdomain prefixes
2. Performs DNS lookups for each potential subdomain
3. Optionally supports custom wordlists
4. Can recursively enumerate discovered subdomains

**Configuration**:
```python
{
    "timeout": 3,                   # DNS query timeout
    "max_concurrent": 50,           # Max concurrent DNS queries
    "custom_wordlist": None,        # Path to custom wordlist
    "use_default_wordlist": True,   # Use built-in wordlist
    "recursive": False,             # Recursive enumeration
    "recursive_depth": 1            # Max recursion depth
}
```

**Example Usage**:
```python
await manager.load_plugin("subdomain_enum", {
    "max_concurrent": 100,
    "recursive": True,
    "recursive_depth": 2
})

context = ExtractionContext(
    ip="93.184.216.34",
    port=443,
    sni="example.com"
)

results = await manager.execute_plugins(context)
for result in results:
    if result.source == "subdomain_enum":
        meta = result.metadata
        print(f"Base domain: {meta['base_domain']}")
        print(f"Tested: {meta['subdomains_tested']} subdomains")
        print(f"Found: {meta['subdomains_found']} valid subdomains")
```

**Custom Wordlist Format**:
```text
# subdomains.txt
api
api-v1
api-v2
dev
staging
admin
# ... more subdomains
```

---

### Certificate Transparency Logs (`ct_logs`)

**Purpose**: Queries Certificate Transparency log databases to discover certificates and domains.

**What it discovers**:
- All subdomains with valid certificates
- Historical certificates and domains
- Wildcard certificate coverage
- Certificate issuance patterns

**Data sources**:
- crt.sh (default)
- Additional CT log APIs can be added

**Configuration**:
```python
{
    "timeout": 30,                          # HTTP request timeout
    "max_results": 1000,                    # Max certificates to process
    "include_expired": True,                # Include expired certificates
    "include_wildcards": True,              # Include wildcard domains
    "api_endpoint": "crtsh",                # CT log API to use
    "user_agent": "TLSXtractor CT Plugin"   # Custom User-Agent
}
```

**Example Usage**:
```python
await manager.load_plugin("ct_logs", {
    "max_results": 500,
    "include_expired": False
})

context = ExtractionContext(
    ip="93.184.216.34",
    port=443,
    sni="example.com"
)

results = await manager.execute_plugins(context)
for result in results:
    if result.source == "ct_logs":
        meta = result.metadata
        print(f"Query domain: {meta['query_domain']}")
        print(f"Certificates found: {meta['certificates_found']}")
        print(f"Wildcard domains: {meta['wildcard_domains']}")
```

---

### DNS Records Extractor (`dns_records`)

**Purpose**: Extracts domains from various DNS record types.

**What it discovers**:
- Mail infrastructure (MX records)
- Authoritative name servers (NS records)
- Domain aliases (CNAME records)
- Service providers (TXT records with SPF, DKIM, DMARC)
- Service endpoints (SRV records)

**Record types queried**:
- **MX** - Mail Exchange records
- **NS** - Name Server records
- **CNAME** - Canonical Name records
- **TXT** - Text records (parsed for SPF, DMARC, domains)
- **SRV** - Service records (common services: HTTP, LDAP, SIP, etc.)

**Configuration**:
```python
{
    "timeout": 5,               # DNS query timeout
    "query_mx": True,           # Query MX records
    "query_ns": True,           # Query NS records
    "query_cname": True,        # Query CNAME records
    "query_txt": True,          # Query TXT records
    "query_srv": True,          # Query SRV records
    "parse_txt_records": True   # Extract domains from TXT content
}
```

**Example Usage**:
```python
await manager.load_plugin("dns_records", {
    "timeout": 3,
    "parse_txt_records": True
})

context = ExtractionContext(
    ip="93.184.216.34",
    port=443,
    sni="example.com"
)

results = await manager.execute_plugins(context)
for result in results:
    if result.source == "dns_records":
        meta = result.metadata
        print(f"Records queried: {', '.join(meta['records_queried'])}")
        print(f"Records found: {meta['records_found']}")
        print(f"TXT domains extracted: {meta['txt_domains_extracted']}")
```

---

## Using Plugins

### Basic Usage

```python
import asyncio
from tlsxtractor.plugins.manager import PluginManager
from tlsxtractor.plugins.base import ExtractionContext

async def main():
    # Initialize plugin manager
    manager = PluginManager()

    # Discover available plugins
    plugins = await manager.discover_plugins()
    print(f"Available plugins: {[p.name for p in plugins]}")

    # Load plugins
    await manager.load_plugin("js_extractor")
    await manager.load_plugin("http_headers")
    await manager.load_plugin("subdomain_enum")

    # Create extraction context
    context = ExtractionContext(
        ip="93.184.216.34",
        port=443,
        sni="example.com"
    )

    # Execute all loaded plugins
    results = await manager.execute_plugins(context)

    # Process results
    all_domains = set()
    for result in results:
        print(f"\n{result.source}:")
        print(f"  Domains: {len(result.domains)}")
        print(f"  Confidence: {result.confidence}")
        print(f"  Metadata: {result.metadata}")
        all_domains.update(result.domains)

    print(f"\nTotal unique domains: {len(all_domains)}")

    # Cleanup
    await manager.shutdown()

asyncio.run(main())
```

### Loading Multiple Plugins

```python
# Load multiple plugins with different configs
plugins_config = {
    "js_extractor": {
        "timeout": 30,
        "max_js_files": 15
    },
    "http_headers": {
        "follow_redirects": True
    },
    "subdomain_enum": {
        "max_concurrent": 100,
        "recursive": True
    },
    "ct_logs": {
        "max_results": 500
    },
    "dns_records": {
        "parse_txt_records": True
    }
}

for plugin_name, config in plugins_config.items():
    await manager.load_plugin(plugin_name, config)
```

### Selective Plugin Execution

```python
# Execute only specific plugins
results = await manager.execute_plugins(
    context,
    plugin_names=["js_extractor", "http_headers"]
)
```

---

## Configuration

### Global Plugin Configuration

Create a plugin configuration file:

```yaml
# plugins_config.yaml
plugins:
  js_extractor:
    enabled: true
    timeout: 30
    max_js_files: 15
    follow_external: true

  http_headers:
    enabled: true
    follow_redirects: true
    max_redirects: 5

  subdomain_enum:
    enabled: true
    max_concurrent: 100
    custom_wordlist: "/path/to/wordlist.txt"
    recursive: true
    recursive_depth: 2

  ct_logs:
    enabled: true
    max_results: 1000
    include_expired: false

  dns_records:
    enabled: true
    parse_txt_records: true
```

Load from configuration file:

```python
import yaml

with open('plugins_config.yaml') as f:
    config = yaml.safe_load(f)

for plugin_name, plugin_config in config['plugins'].items():
    if plugin_config.get('enabled', False):
        await manager.load_plugin(plugin_name, plugin_config)
```

### Environment-Based Configuration

```python
import os

# Configure from environment variables
config = {
    "timeout": int(os.getenv("PLUGIN_TIMEOUT", "30")),
    "max_results": int(os.getenv("PLUGIN_MAX_RESULTS", "1000"))
}

await manager.load_plugin("ct_logs", config)
```

---

## Creating Custom Plugins

### Domain Extractor Plugin Template

```python
from typing import Dict, Any
from tlsxtractor.plugins.base import (
    DomainExtractorPlugin,
    PluginMetadata,
    ExtractionContext,
    ExtractionResult,
)

class CustomExtractor(DomainExtractorPlugin):
    """Custom domain extractor plugin."""

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        # Initialize your custom configuration
        self.custom_setting = self.get_config('custom_setting', 'default')

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="custom_extractor",
            version="1.0.0",
            author="Your Name",
            description="Brief description of what this plugin does",
            dependencies=["required-package>=1.0.0"],
            config_schema={
                "custom_setting": {
                    "type": "string",
                    "default": "default",
                    "description": "Description of setting"
                }
            },
            tags=["extractor", "custom"]
        )

    async def initialize(self) -> None:
        """Initialize resources (optional)."""
        self._logger.info("Custom extractor initialized")

    async def cleanup(self) -> None:
        """Cleanup resources (optional)."""
        self._logger.info("Custom extractor cleaned up")

    def validate_config(self) -> bool:
        """Validate configuration (optional)."""
        if not self.custom_setting:
            raise ValueError("custom_setting is required")
        return True

    async def extract_domains(
        self, context: ExtractionContext
    ) -> ExtractionResult:
        """Main extraction logic."""
        domains = set()
        metadata = {}

        try:
            # Your extraction logic here
            # domains.add("discovered-domain.com")

            return ExtractionResult(
                domains=list(domains),
                metadata=metadata,
                confidence=0.9,
                source="custom_extractor"
            )

        except Exception as e:
            error_msg = f"Custom extraction failed: {e}"
            self._logger.error(error_msg)
            return ExtractionResult(
                domains=[],
                metadata=metadata,
                confidence=0.0,
                source="custom_extractor",
                errors=[error_msg]
            )
```

### Filter Plugin Template

```python
from typing import List, Dict, Any
from tlsxtractor.plugins.base import FilterPlugin, PluginMetadata

class CustomFilter(FilterPlugin):
    """Custom domain filter plugin."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="custom_filter",
            version="1.0.0",
            author="Your Name",
            description="Filter domains based on custom criteria",
            tags=["filter", "custom"]
        )

    async def filter_domains(
        self, domains: List[str], context: Dict[str, Any]
    ) -> List[str]:
        """Filter domain list."""
        filtered = []

        for domain in domains:
            # Your filtering logic
            if self._should_keep_domain(domain):
                filtered.append(domain)

        return filtered

    def _should_keep_domain(self, domain: str) -> bool:
        """Determine if domain should be kept."""
        # Your custom logic
        return True
```

### Enrichment Plugin Template

```python
from typing import List, Dict, Any
from tlsxtractor.plugins.base import EnrichmentPlugin, PluginMetadata

class CustomEnrichment(EnrichmentPlugin):
    """Custom domain enrichment plugin."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="custom_enrichment",
            version="1.0.0",
            author="Your Name",
            description="Enrich domains with custom data",
            tags=["enrichment", "custom"]
        )

    async def enrich_domains(
        self, domains: List[str], context: Dict[str, Any]
    ) -> Dict[str, Dict[str, Any]]:
        """Enrich domain data."""
        enriched = {}

        for domain in domains:
            enriched[domain] = {
                "custom_field": "custom_value",
                # Add your enrichment data
            }

        return enriched
```

---

## Plugin Development Best Practices

### 1. Error Handling

Always handle errors gracefully:

```python
try:
    # Your logic
    result = await self._fetch_data()
except SpecificError as e:
    self._logger.error(f"Specific error: {e}")
    return ExtractionResult(
        domains=[],
        metadata={"error": str(e)},
        confidence=0.0,
        source="plugin_name",
        errors=[str(e)]
    )
```

### 2. Resource Management

Use async context managers for resources:

```python
async def initialize(self) -> None:
    self._session = aiohttp.ClientSession()

async def cleanup(self) -> None:
    if self._session:
        await self._session.close()
```

### 3. Configuration Validation

Validate configuration early:

```python
def validate_config(self) -> bool:
    if self.timeout <= 0:
        raise ValueError("timeout must be positive")
    if self.max_results < 1:
        raise ValueError("max_results must be at least 1")
    return True
```

### 4. Logging

Use structured logging:

```python
self._logger.debug(f"Processing domain: {domain}")
self._logger.info(f"Found {len(domains)} domains")
self._logger.warning(f"Rate limit approached")
self._logger.error(f"Failed to fetch data: {error}")
```

### 5. Performance

- Use async/await for I/O operations
- Implement concurrency limits
- Cache expensive operations
- Set reasonable timeouts

```python
semaphore = asyncio.Semaphore(self.max_concurrent)

async with semaphore:
    result = await self._fetch_data(url)
```

### 6. Testing

Write tests for your plugins:

```python
import pytest
from your_plugin import CustomExtractor

@pytest.mark.asyncio
async def test_extract_domains():
    plugin = CustomExtractor({"timeout": 10})
    await plugin.initialize()

    context = ExtractionContext(
        ip="93.184.216.34",
        port=443,
        sni="example.com"
    )

    result = await plugin.extract_domains(context)

    assert result.confidence > 0
    assert len(result.domains) > 0

    await plugin.cleanup()
```

### 7. Documentation

Document your plugin thoroughly:

```python
class CustomExtractor(DomainExtractorPlugin):
    """
    Custom domain extractor plugin.

    This plugin extracts domains from [source] by:
    1. Step one
    2. Step two
    3. Step three

    Useful for finding:
    - Type of domains 1
    - Type of domains 2

    Configuration:
        setting1: Description of setting1
        setting2: Description of setting2

    Example:
        >>> plugin = CustomExtractor({"setting1": "value"})
        >>> await plugin.initialize()
        >>> result = await plugin.extract_domains(context)
    """
```

---

## Installation

### Plugin Dependencies

Each plugin may have specific dependencies. Install them:

```bash
# JavaScript extractor
pip install aiohttp

# HTTP headers extractor
pip install aiohttp

# Subdomain enumeration
pip install aiodns pycares

# Certificate Transparency logs
pip install aiohttp

# DNS records extractor
pip install aiodns pycares
```

Or install all plugin dependencies:

```bash
pip install aiohttp aiodns pycares
```

---

## Troubleshooting

### Plugin Not Loading

```python
# Check if plugin exists in discovery
plugins = await manager.discover_plugins()
plugin_names = [p.name for p in plugins]
print(f"Available plugins: {plugin_names}")
```

### Configuration Errors

```python
# Validate configuration before loading
try:
    plugin = CustomExtractor(config)
    plugin.validate_config()
except ValueError as e:
    print(f"Invalid configuration: {e}")
```

### Timeout Issues

Increase timeouts for slow networks:

```python
config = {
    "timeout": 60,  # Increase from default 30
}
await manager.load_plugin("ct_logs", config)
```

### Memory Issues

Limit concurrent operations and result sizes:

```python
config = {
    "max_concurrent": 10,  # Reduce from default 50
    "max_results": 100,    # Reduce from default 1000
}
```

---

## Contributing

To contribute a plugin:

1. Create your plugin in `plugins/community/`
2. Follow the templates above
3. Add tests in `tests/plugins/`
4. Update this README with documentation
5. Submit a pull request

See [CONTRIBUTING.md](../CONTRIBUTING.md) for more details.

---

## License

See [LICENSE](../LICENSE) for license information.

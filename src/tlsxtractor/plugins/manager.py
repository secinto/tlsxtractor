"""
Plugin manager for loading and executing plugins.
"""

from typing import Dict, List, Any, Optional, Type
from pathlib import Path
import importlib.util
import inspect
import logging
import asyncio

from .base import (
    DomainExtractorPlugin,
    FilterPlugin,
    EnrichmentPlugin,
    PluginMetadata,
    ExtractionContext,
    ExtractionResult,
)


logger = logging.getLogger(__name__)


class PluginManager:
    """
    Manages plugin lifecycle: discovery, loading, validation, and execution.

    The PluginManager handles:
    - Discovering plugins from configured directories
    - Loading plugin classes dynamically
    - Validating plugin configurations
    - Initializing and cleaning up plugin resources
    - Executing plugins in the correct order
    - Handling plugin errors gracefully
    """

    def __init__(self, plugin_dirs: List[str] = None):
        """
        Initialize plugin manager.

        Args:
            plugin_dirs: List of directories to search for plugins.
                        Defaults to standard plugin locations.
        """
        self.plugin_dirs = plugin_dirs or self._get_default_plugin_dirs()
        self._plugins: Dict[str, DomainExtractorPlugin] = {}
        self._filters: Dict[str, FilterPlugin] = {}
        self._enrichments: Dict[str, EnrichmentPlugin] = {}
        self._metadata: Dict[str, PluginMetadata] = {}

    def _get_default_plugin_dirs(self) -> List[str]:
        """Get default plugin search directories."""
        return [
            str(Path(__file__).parent.parent.parent.parent / "plugins" / "core"),
            str(Path(__file__).parent.parent.parent.parent / "plugins" / "community"),
            str(Path.home() / ".tlsxtractor" / "plugins"),
        ]

    async def discover_plugins(self) -> List[PluginMetadata]:
        """
        Discover available plugins in plugin directories.

        Scans all configured plugin directories for Python files
        containing plugin classes.

        Returns:
            List of discovered plugin metadata
        """
        discovered = []

        for plugin_dir in self.plugin_dirs:
            path = Path(plugin_dir).expanduser()
            if not path.exists():
                logger.debug(f"Plugin directory does not exist: {path}")
                continue

            logger.info(f"Scanning for plugins in: {path}")

            # Find all Python files
            for plugin_file in path.glob("*.py"):
                if plugin_file.name.startswith("_"):
                    continue

                try:
                    metadata = await self._discover_plugin_file(plugin_file)
                    if metadata:
                        discovered.extend(metadata)
                        logger.info(
                            f"Discovered {len(metadata)} plugin(s) in {plugin_file.name}"
                        )
                except Exception as e:
                    logger.warning(f"Failed to discover plugins in {plugin_file}: {e}")

        return discovered

    async def _discover_plugin_file(self, plugin_file: Path) -> List[PluginMetadata]:
        """
        Discover plugins in a single file.

        Args:
            plugin_file: Path to plugin file

        Returns:
            List of plugin metadata found in file
        """
        metadata_list = []

        # Load the module
        spec = importlib.util.spec_from_file_location(plugin_file.stem, plugin_file)
        if not spec or not spec.loader:
            return metadata_list

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Find plugin classes
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if name.startswith("_"):
                continue

            # Check if it's a plugin class (but not the base classes)
            if (
                issubclass(obj, DomainExtractorPlugin)
                and obj is not DomainExtractorPlugin
            ):
                try:
                    # Instantiate temporarily to get metadata
                    instance = obj()
                    metadata = instance.get_metadata()
                    metadata_list.append(metadata)
                except Exception as e:
                    logger.warning(f"Failed to get metadata for {name}: {e}")

        return metadata_list

    async def load_plugin(
        self, plugin_name: str, config: Dict[str, Any] = None
    ) -> bool:
        """
        Load and initialize a plugin by name.

        Args:
            plugin_name: Name of the plugin to load
            config: Plugin configuration dictionary

        Returns:
            True if plugin loaded successfully, False otherwise
        """
        try:
            # Find plugin file
            plugin_class = await self._find_plugin_class(plugin_name)
            if not plugin_class:
                logger.error(f"Plugin not found: {plugin_name}")
                return False

            # Instantiate plugin
            plugin = plugin_class(config)

            # Get metadata
            metadata = plugin.get_metadata()

            # Validate configuration
            try:
                plugin.validate_config()
            except ValueError as e:
                logger.error(f"Plugin {plugin_name} configuration invalid: {e}")
                return False

            # Initialize plugin
            await plugin.initialize()

            # Store plugin
            if isinstance(plugin, FilterPlugin):
                self._filters[plugin_name] = plugin
            elif isinstance(plugin, EnrichmentPlugin):
                self._enrichments[plugin_name] = plugin
            else:
                self._plugins[plugin_name] = plugin

            self._metadata[plugin_name] = metadata

            logger.info(f"Loaded plugin: {plugin_name} v{metadata.version}")
            return True

        except Exception as e:
            logger.error(f"Failed to load plugin {plugin_name}: {e}", exc_info=True)
            return False

    async def _find_plugin_class(
        self, plugin_name: str
    ) -> Optional[Type[DomainExtractorPlugin]]:
        """
        Find plugin class by name.

        Searches all plugin directories for a class matching the plugin name.

        Args:
            plugin_name: Name of the plugin to find

        Returns:
            Plugin class or None if not found
        """
        for plugin_dir in self.plugin_dirs:
            path = Path(plugin_dir).expanduser()
            if not path.exists():
                continue

            # Try to find plugin file
            # Look for: plugin_name.py or PluginName.py
            for plugin_file in path.glob("*.py"):
                if plugin_file.stem.lower() == plugin_name.lower():
                    # Load module
                    spec = importlib.util.spec_from_file_location(
                        plugin_file.stem, plugin_file
                    )
                    if not spec or not spec.loader:
                        continue

                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)

                    # Find matching class
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if name.startswith("_"):
                            continue

                        if (
                            issubclass(obj, DomainExtractorPlugin)
                            and obj is not DomainExtractorPlugin
                            and obj is not FilterPlugin
                            and obj is not EnrichmentPlugin
                        ):
                            try:
                                instance = obj()
                                metadata = instance.get_metadata()
                                if metadata.name == plugin_name:
                                    return obj
                            except:
                                pass

        return None

    async def unload_plugin(self, plugin_name: str) -> bool:
        """
        Unload a plugin and clean up its resources.

        Args:
            plugin_name: Name of the plugin to unload

        Returns:
            True if plugin unloaded successfully, False otherwise
        """
        # Try all plugin types
        plugin = (
            self._plugins.get(plugin_name)
            or self._filters.get(plugin_name)
            or self._enrichments.get(plugin_name)
        )

        if not plugin:
            logger.warning(f"Plugin not loaded: {plugin_name}")
            return False

        try:
            # Cleanup plugin resources
            await plugin.cleanup()

            # Remove from storage
            self._plugins.pop(plugin_name, None)
            self._filters.pop(plugin_name, None)
            self._enrichments.pop(plugin_name, None)
            self._metadata.pop(plugin_name, None)

            logger.info(f"Unloaded plugin: {plugin_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to unload plugin {plugin_name}: {e}")
            return False

    def get_plugin(self, plugin_name: str) -> Optional[DomainExtractorPlugin]:
        """
        Get a loaded plugin by name.

        Args:
            plugin_name: Name of the plugin

        Returns:
            Plugin instance or None if not found
        """
        return (
            self._plugins.get(plugin_name)
            or self._filters.get(plugin_name)
            or self._enrichments.get(plugin_name)
        )

    def list_plugins(self, enabled_only: bool = False) -> List[PluginMetadata]:
        """
        List all loaded plugins.

        Args:
            enabled_only: If True, only return enabled plugins

        Returns:
            List of plugin metadata
        """
        if not enabled_only:
            return list(self._metadata.values())

        enabled = []
        for name, metadata in self._metadata.items():
            plugin = self.get_plugin(name)
            if plugin and plugin.is_enabled():
                enabled.append(metadata)

        return enabled

    async def execute_plugins(
        self, context: ExtractionContext
    ) -> List[ExtractionResult]:
        """
        Execute all enabled domain extractor plugins.

        Args:
            context: Extraction context with target information

        Returns:
            List of extraction results from all plugins
        """
        results = []

        for name, plugin in self._plugins.items():
            if not plugin.is_enabled():
                logger.debug(f"Skipping disabled plugin: {name}")
                continue

            try:
                logger.debug(f"Executing plugin: {name}")
                result = await plugin.extract_domains(context)
                results.append(result)
                logger.debug(
                    f"Plugin {name} found {len(result.domains)} domain(s)"
                )
            except Exception as e:
                logger.error(f"Plugin {name} failed: {e}", exc_info=True)
                # Create error result
                results.append(
                    ExtractionResult(
                        domains=[],
                        source=name,
                        confidence=0.0,
                        errors=[str(e)],
                    )
                )

        return results

    async def execute_filters(self, domains: List[str]) -> List[str]:
        """
        Execute all enabled filter plugins.

        Args:
            domains: List of domains to filter

        Returns:
            Filtered list of domains
        """
        filtered = domains

        for name, plugin in self._filters.items():
            if not plugin.is_enabled():
                continue

            try:
                logger.debug(f"Executing filter: {name}")
                before_count = len(filtered)
                filtered = await plugin.filter_domains(filtered)
                after_count = len(filtered)
                logger.debug(
                    f"Filter {name} removed {before_count - after_count} domain(s)"
                )
            except Exception as e:
                logger.error(f"Filter {name} failed: {e}")

        return filtered

    async def execute_enrichments(
        self, domains: List[str]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Execute all enabled enrichment plugins.

        Args:
            domains: List of domains to enrich

        Returns:
            Dictionary mapping domain names to enrichment data from all plugins
        """
        enrichments = {domain: {} for domain in domains}

        for name, plugin in self._enrichments.items():
            if not plugin.is_enabled():
                continue

            try:
                logger.debug(f"Executing enrichment: {name}")
                results = await plugin.enrich_domains(domains)

                # Merge results
                for domain, data in results.items():
                    if domain in enrichments:
                        enrichments[domain][name] = data

                logger.debug(f"Enrichment {name} completed")
            except Exception as e:
                logger.error(f"Enrichment {name} failed: {e}")

        return enrichments

    async def cleanup_all(self) -> None:
        """Clean up all loaded plugins."""
        logger.info("Cleaning up all plugins...")

        for plugin_name in list(self._plugins.keys()):
            await self.unload_plugin(plugin_name)

        for plugin_name in list(self._filters.keys()):
            await self.unload_plugin(plugin_name)

        for plugin_name in list(self._enrichments.keys()):
            await self.unload_plugin(plugin_name)

        logger.info("All plugins cleaned up")

    def get_plugin_stats(self) -> Dict[str, Any]:
        """
        Get plugin statistics.

        Returns:
            Dictionary with plugin statistics
        """
        return {
            "total_plugins": len(self._plugins)
            + len(self._filters)
            + len(self._enrichments),
            "extractor_plugins": len(self._plugins),
            "filter_plugins": len(self._filters),
            "enrichment_plugins": len(self._enrichments),
            "enabled_plugins": len(self.list_plugins(enabled_only=True)),
        }

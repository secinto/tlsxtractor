"""
Plugin system for TLSXtractor.

Enables extensibility through custom domain extractors, filters, and enrichments.
"""

from .base import (
    PluginMetadata,
    ExtractionContext,
    ExtractionResult,
    DomainExtractorPlugin,
    FilterPlugin,
    EnrichmentPlugin,
)
from .manager import PluginManager

__all__ = [
    "PluginMetadata",
    "ExtractionContext",
    "ExtractionResult",
    "DomainExtractorPlugin",
    "FilterPlugin",
    "EnrichmentPlugin",
    "PluginManager",
]

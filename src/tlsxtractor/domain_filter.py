"""
Domain filtering for excluding common third-party services.

Provides configurable filtering of domains based on exact matches,
wildcard patterns, and regex patterns.
"""

import re
from typing import List, Set, Optional, Union
from pathlib import Path
import logging


logger = logging.getLogger(__name__)


class DomainFilter:
    """
    Filters domains based on exclusion lists and patterns.

    Supports:
    - Exact domain matching
    - Wildcard patterns (*.example.com, *.cdn.*)
    - Regex patterns (when enabled)
    - Default exclusions for common CDNs, analytics, ad networks
    """

    # Default exclusion list - common third-party services
    DEFAULT_EXCLUSIONS = {
        # CDNs
        "cloudflare.com",
        "*.cloudflare.com",
        "cloudflare.net",
        "*.cloudflare.net",
        "cloudfront.net",
        "*.cloudfront.net",
        "akamai.net",
        "*.akamai.net",
        "akamaiedge.net",
        "*.akamaiedge.net",
        "fastly.net",
        "*.fastly.net",
        "cdn77.com",
        "*.cdn77.com",
        "cdninstagram.com",
        "*.cdninstagram.com",

        # Google Services
        "googleapis.com",
        "*.googleapis.com",
        "googleusercontent.com",
        "*.googleusercontent.com",
        "gstatic.com",
        "*.gstatic.com",
        "google-analytics.com",
        "*.google-analytics.com",

        # Analytics & Tracking
        "doubleclick.net",
        "*.doubleclick.net",
        "googletagmanager.com",
        "*.googletagmanager.com",
        "segment.com",
        "*.segment.com",
        "mixpanel.com",
        "*.mixpanel.com",
        "amplitude.com",
        "*.amplitude.com",
        "hotjar.com",
        "*.hotjar.com",
        "clarity.ms",
        "*.clarity.ms",

        # Advertising Networks
        "doubleclick.com",
        "*.doubleclick.com",
        "googlesyndication.com",
        "*.googlesyndication.com",
        "googleadservices.com",
        "*.googleadservices.com",
        "adnxs.com",
        "*.adnxs.com",
        "adsrvr.org",
        "*.adsrvr.org",

        # Social Media CDNs
        "facebook.com",
        "*.facebook.com",
        "fbcdn.net",
        "*.fbcdn.net",
        "twitter.com",
        "*.twitter.com",
        "twimg.com",
        "*.twimg.com",

        # Other Common Services
        "jquery.com",
        "*.jquery.com",
        "bootstrapcdn.com",
        "*.bootstrapcdn.com",
        "unpkg.com",
        "*.unpkg.com",
        "jsdelivr.net",
        "*.jsdelivr.net",
    }

    def __init__(
        self,
        use_defaults: bool = True,
        custom_exclusions: Optional[List[str]] = None,
        enable_regex: bool = False
    ):
        """
        Initialize domain filter.

        Args:
            use_defaults: Include default exclusion list
            custom_exclusions: Additional domains/patterns to exclude
            enable_regex: Enable regex pattern matching
        """
        self.enable_regex = enable_regex
        self._filtered_count = 0

        # Separate storage for different pattern types
        self._exact_matches: Set[str] = set()
        self._wildcard_patterns: List[str] = []
        self._regex_patterns: List[re.Pattern] = []

        # Add default exclusions
        if use_defaults:
            self._add_patterns(list(self.DEFAULT_EXCLUSIONS))

        # Add custom exclusions
        if custom_exclusions:
            self._add_patterns(custom_exclusions)

    def _add_patterns(self, patterns: List[str]) -> None:
        """
        Add exclusion patterns to the filter.

        Args:
            patterns: List of domain patterns (exact, wildcard, or regex)
        """
        for pattern in patterns:
            pattern = pattern.strip()
            if not pattern or pattern.startswith("#"):
                continue

            # Check if it's a regex pattern (starts with ^ or ends with $)
            if self.enable_regex and (pattern.startswith("^") or pattern.endswith("$")):
                try:
                    compiled = re.compile(pattern, re.IGNORECASE)
                    self._regex_patterns.append(compiled)
                    logger.debug(f"Added regex pattern: {pattern}")
                except re.error as e:
                    logger.warning(f"Invalid regex pattern '{pattern}': {e}")
            # Check if it's a wildcard pattern
            elif "*" in pattern:
                self._wildcard_patterns.append(pattern.lower())
                logger.debug(f"Added wildcard pattern: {pattern}")
            # Exact match
            else:
                self._exact_matches.add(pattern.lower())
                logger.debug(f"Added exact match: {pattern}")

    def add_exclusions(self, exclusions: Union[str, List[str]]) -> None:
        """
        Add additional exclusion patterns.

        Args:
            exclusions: Single pattern or list of patterns
        """
        if isinstance(exclusions, str):
            exclusions = [exclusions]
        self._add_patterns(exclusions)

    def add_exclusions_from_file(self, file_path: Union[str, Path]) -> None:
        """
        Load exclusion patterns from a file.

        Args:
            file_path: Path to file with one pattern per line
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Exclusion file not found: {file_path}")

        try:
            with open(path, "r") as f:
                patterns = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            self._add_patterns(patterns)
            logger.info(f"Loaded {len(patterns)} exclusion patterns from {file_path}")
        except Exception as e:
            logger.error(f"Error loading exclusions from {file_path}: {e}")
            raise

    def _match_wildcard(self, domain: str, pattern: str) -> bool:
        """
        Match domain against wildcard pattern.

        Supports:
        - *.example.com (matches any subdomain)
        - example.* (matches any TLD)
        - *.cdn.* (matches multiple wildcards)

        Args:
            domain: Domain to check
            pattern: Wildcard pattern

        Returns:
            True if domain matches pattern
        """
        # Convert wildcard pattern to regex
        # Escape special regex chars except *
        regex_pattern = re.escape(pattern).replace(r"\*", ".*")
        regex_pattern = f"^{regex_pattern}$"

        try:
            return bool(re.match(regex_pattern, domain, re.IGNORECASE))
        except re.error:
            logger.warning(f"Error matching wildcard pattern: {pattern}")
            return False

    def should_filter(self, domain: str) -> bool:
        """
        Check if a domain should be filtered out.

        Args:
            domain: Domain name to check

        Returns:
            True if domain should be filtered, False otherwise
        """
        if not domain:
            return False

        domain_lower = domain.strip().lower()

        # Check exact matches first (fastest)
        if domain_lower in self._exact_matches:
            self._filtered_count += 1
            logger.debug(f"Filtered (exact match): {domain}")
            return True

        # Check wildcard patterns
        for pattern in self._wildcard_patterns:
            if self._match_wildcard(domain_lower, pattern):
                self._filtered_count += 1
                logger.debug(f"Filtered (wildcard '{pattern}'): {domain}")
                return True

        # Check regex patterns (if enabled)
        if self.enable_regex:
            for regex in self._regex_patterns:
                if regex.search(domain):
                    self._filtered_count += 1
                    logger.debug(f"Filtered (regex): {domain}")
                    return True

        return False

    def filter_domains(self, domains: List[str]) -> List[str]:
        """
        Filter a list of domains, removing excluded ones.

        Args:
            domains: List of domains to filter

        Returns:
            Filtered list of domains
        """
        return [d for d in domains if not self.should_filter(d)]

    def get_filtered_count(self) -> int:
        """
        Get the number of domains filtered since initialization.

        Returns:
            Count of filtered domains
        """
        return self._filtered_count

    def reset_count(self) -> None:
        """Reset the filtered domains counter."""
        self._filtered_count = 0

    def get_exclusion_stats(self) -> dict:
        """
        Get statistics about loaded exclusion patterns.

        Returns:
            Dictionary with pattern counts
        """
        return {
            "exact_matches": len(self._exact_matches),
            "wildcard_patterns": len(self._wildcard_patterns),
            "regex_patterns": len(self._regex_patterns),
            "total_patterns": len(self._exact_matches) + len(self._wildcard_patterns) + len(self._regex_patterns),
            "filtered_count": self._filtered_count,
        }

    @classmethod
    def from_file(cls, file_path: Union[str, Path], use_defaults: bool = True) -> "DomainFilter":
        """
        Create a DomainFilter from a file.

        Args:
            file_path: Path to exclusion file
            use_defaults: Include default exclusions

        Returns:
            Configured DomainFilter instance
        """
        filter_instance = cls(use_defaults=use_defaults)
        filter_instance.add_exclusions_from_file(file_path)
        return filter_instance

    @classmethod
    def from_comma_separated(cls, patterns_str: str, use_defaults: bool = True) -> "DomainFilter":
        """
        Create a DomainFilter from comma-separated patterns.

        Args:
            patterns_str: Comma-separated list of patterns
            use_defaults: Include default exclusions

        Returns:
            Configured DomainFilter instance
        """
        patterns = [p.strip() for p in patterns_str.split(",") if p.strip()]
        return cls(use_defaults=use_defaults, custom_exclusions=patterns)
"""
Output formatting and JSON export.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Union

# Lazy import for tldextract - will be loaded on first use
_tldextract = None


def _get_extractor():
    """Get or create the cached tldextract instance."""
    global _tldextract
    if _tldextract is None:
        import tldextract
        # Use cached extractor with in-memory cache to avoid PSL reload
        _tldextract = tldextract.TLDExtract(cache_dir=None, include_psl_private_domains=False)
    return _tldextract


if TYPE_CHECKING:
    from .domain_filter import DomainFilter


class HostnameAnalyzer:
    """
    Analyzes and extracts hostnames from scan results.

    Separates subdomains from registrable domains (eTLD+1).
    Uses Mozilla's Public Suffix List via tldextract.
    """

    # Pre-compiled hostname validation pattern
    _HOSTNAME_PATTERN = re.compile(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
    )

    # Cache for tldextract results to avoid redundant extractions
    _extract_cache: Dict[str, Any] = {}

    @classmethod
    def _get_extraction(cls, hostname: str):
        """Get cached tldextract extraction result."""
        if hostname not in cls._extract_cache:
            extractor = _get_extractor()
            cls._extract_cache[hostname] = extractor(hostname)
        return cls._extract_cache[hostname]

    @staticmethod
    def is_wildcard(hostname: str) -> bool:
        """Check if hostname contains wildcard."""
        return "*" in hostname

    @classmethod
    def extract_registrable_domain(cls, hostname: str) -> Optional[str]:
        """
        Extract the registrable domain (eTLD+1) from a hostname.

        Examples:
            api.example.com -> example.com
            example.com -> example.com
            www.example.co.uk -> example.co.uk
            test.or.at -> test.or.at

        Args:
            hostname: The hostname to extract from

        Returns:
            The registrable domain or None if invalid
        """
        if not hostname:
            return None

        try:
            ext = cls._get_extraction(hostname)
            # top_domain_under_public_suffix is the eTLD+1 (e.g., example.com, example.co.uk)
            if ext.top_domain_under_public_suffix:
                return ext.top_domain_under_public_suffix
        except Exception:
            pass

        return None

    @classmethod
    def is_registrable_domain(cls, hostname: str) -> bool:
        """
        Check if hostname is the registrable domain itself (not a subdomain).

        Examples:
            example.com -> True (is registrable domain)
            api.example.com -> False (has subdomain)
            example.co.uk -> True (is registrable domain)
            www.example.co.uk -> False (has subdomain)

        Args:
            hostname: The hostname to check

        Returns:
            True if hostname equals its registrable domain
        """
        if not hostname:
            return False

        try:
            ext = cls._get_extraction(hostname)
            # Check if there's no subdomain and we have a valid domain
            return bool(not ext.subdomain and ext.domain and ext.suffix)
        except Exception:
            return False

    @classmethod
    def is_valid_hostname(cls, hostname: str) -> bool:
        """Validate hostname format."""
        if not hostname:
            return False

        # Basic hostname validation
        # Must have at least one dot (domain.tld)
        if "." not in hostname:
            return False

        # Must not start or end with dot
        if hostname.startswith(".") or hostname.endswith("."):
            return False

        # Use pre-compiled pattern for efficiency
        return bool(cls._HOSTNAME_PATTERN.match(hostname))

    @staticmethod
    def analyze_results(
        results: Any,
        domain_filter: Optional["DomainFilter"] = None,
        input_hostnames: Optional[Set[str]] = None
    ) -> Dict[str, Any]:
        """
        Analyze scan results and extract hostname summary.

        Args:
            results: Scan results (can be list or dict with ips/urls)
            domain_filter: Optional DomainFilter to apply exclusions
            input_hostnames: Optional set of input hostnames to compare against for new discoveries

        Returns:
            Dictionary with hostname analysis:
            {
                "hostnames": [...],       # Subdomains only (e.g., api.example.com)
                "tlds": [...],            # Registrable domains/eTLD+1 (e.g., example.com, example.co.uk)
                "wildcards": [...],       # Wildcards found (informational)
                "total_hostnames": int,   # Count of subdomains
                "total_tlds": int,        # Count of unique registrable domains
                "filtered_count": int,    # Number of filtered domains (if filter provided)
                "new_hostnames": [...],   # Newly discovered subdomains (not in input)
                "new_tlds": [...],        # Newly discovered TLDs (not in input)
                "total_new_hostnames": int,
                "total_new_tlds": int
            }
        """
        all_hostnames: Set[str] = set()
        wildcards: Set[str] = set()
        filtered_count = 0

        # Track domains by source for breakdown
        domains_from_san: Set[str] = set()
        domains_from_cn: Set[str] = set()
        domains_from_csp: Set[str] = set()

        # Helper function to extract from a single result
        def extract_from_result(result: Optional[Dict[str, Any]]) -> None:
            # Skip if result is None or not a dict
            if result is None or not isinstance(result, dict):
                return

            # Extract from SNI
            if result.get("sni"):
                all_hostnames.add(result["sni"])

            # Extract from domain_sources if available (preferred)
            domain_sources = result.get("domain_sources", {})
            if domain_sources:
                for san in domain_sources.get("san", []):
                    all_hostnames.add(san)
                    domains_from_san.add(san.lower())
                for cn in domain_sources.get("cn", []):
                    all_hostnames.add(cn)
                    domains_from_cn.add(cn.lower())
                for csp in domain_sources.get("csp", []):
                    all_hostnames.add(csp)
                    domains_from_csp.add(csp.lower())

            # Extract from domains list (fallback)
            if result.get("domains"):
                for domain in result["domains"]:
                    all_hostnames.add(domain)

            # Extract from certificate SAN (fallback if no domain_sources)
            certificate = result.get("certificate")
            if certificate and certificate.get("san") and not domain_sources:
                for san in certificate["san"]:
                    all_hostnames.add(san)
                    domains_from_san.add(san.lower())

            # Extract from certificate CN (fallback if no domain_sources)
            if certificate and certificate.get("subject") and not domain_sources:
                cert_cn = certificate["subject"].get("commonName")
                if cert_cn:
                    all_hostnames.add(cert_cn)
                    domains_from_cn.add(cert_cn.lower())

        # Handle different result formats
        if isinstance(results, dict):
            # Mixed scan format with ips and urls
            if "ips" in results:
                for result in results["ips"]:
                    extract_from_result(result)
            if "urls" in results:
                for url_result in results["urls"]:
                    # Skip if url_result is None
                    if url_result is None:
                        continue
                    # Add hostname
                    if url_result.get("hostname"):
                        all_hostnames.add(url_result["hostname"])
                    # Extract from connections
                    for conn in url_result.get("connections", []):
                        extract_from_result(conn)
        elif isinstance(results, list):
            # Simple list format (ip_scan or url_scan)
            for result in results:
                if result is not None and isinstance(result, dict):
                    # Check if this is url_scan format with connections
                    if 'connections' in result:
                        # Add hostname from url_scan format
                        if result.get('hostname'):
                            all_hostnames.add(result['hostname'])
                        # Extract from each connection
                        for conn in result.get('connections', []):
                            extract_from_result(conn)
                    else:
                        # ip_scan format - extract directly
                        extract_from_result(result)

        # Separate wildcards, subdomains, and registrable domains
        regular_hostnames: Set[str] = set()  # Subdomains only
        registrable_domains: Set[str] = set()  # eTLD+1 / base domains

        for hostname in all_hostnames:
            hostname = hostname.strip().strip(".")  # Remove leading/trailing dots

            if not hostname:
                continue

            # Apply domain filter if provided
            if domain_filter and domain_filter.should_filter(hostname):
                filtered_count += 1
                continue

            # Check for wildcard
            if HostnameAnalyzer.is_wildcard(hostname):
                wildcards.add(hostname)
                continue

            # Validate hostname format
            if not HostnameAnalyzer.is_valid_hostname(hostname):
                continue

            hostname_lower = hostname.lower()

            # Check if this is a registrable domain (eTLD+1) or a subdomain
            if HostnameAnalyzer.is_registrable_domain(hostname_lower):
                # This IS the base domain (e.g., example.com, example.co.uk)
                registrable_domains.add(hostname_lower)
            else:
                # This is a subdomain (e.g., api.example.com, www.example.co.uk)
                regular_hostnames.add(hostname_lower)

                # Also track its registrable domain
                registrable = HostnameAnalyzer.extract_registrable_domain(hostname_lower)
                if registrable:
                    registrable_domains.add(registrable)

        # Compute new discoveries (hostnames not in input)
        new_hostnames: Set[str] = set()
        new_tlds: Set[str] = set()

        if input_hostnames is not None:
            # Normalize input hostnames to lowercase for comparison
            input_normalized = {h.lower() for h in input_hostnames}

            # Also extract TLDs from input hostnames for comparison
            input_tlds: Set[str] = set()
            for h in input_normalized:
                tld = HostnameAnalyzer.extract_registrable_domain(h)
                if tld:
                    input_tlds.add(tld.lower())
                # If the input itself is a TLD, add it
                if HostnameAnalyzer.is_registrable_domain(h):
                    input_tlds.add(h)

            # Find new subdomains (not in input)
            for hostname in regular_hostnames:
                if hostname not in input_normalized:
                    new_hostnames.add(hostname)
                    # Also extract root domain from new subdomain and add to new_tlds
                    # if it's not already in input TLDs
                    root = HostnameAnalyzer.extract_registrable_domain(hostname)
                    if root and root not in input_tlds:
                        new_tlds.add(root)

            # Find new TLDs (not derived from input hostnames)
            for tld in registrable_domains:
                if tld not in input_tlds:
                    new_tlds.add(tld)

        result = {
            "hostnames": sorted(list(regular_hostnames)),
            "tlds": sorted(list(registrable_domains)),
            "wildcards": sorted(list(wildcards)),
            "total_hostnames": len(regular_hostnames),
            "total_tlds": len(registrable_domains),
            "new_hostnames": sorted(list(new_hostnames)),
            "new_tlds": sorted(list(new_tlds)),
            "total_new_hostnames": len(new_hostnames),
            "total_new_tlds": len(new_tlds),
            "source_breakdown": {
                "san": len(domains_from_san),
                "cn": len(domains_from_cn),
                "csp": len(domains_from_csp),
            },
        }

        # Add filtered count if filtering was applied
        if domain_filter:
            result["filtered_count"] = filtered_count

        return result


class OutputFormatter:
    """
    Handles formatting and exporting scan results.

    Implements Tasks IMPL-013 and IMPL-014:
    - JSON data structure design
    - JSON file writing implementation
    """

    def __init__(
        self,
        output_path: str,
        mode: str = "ip_scan",
        domain_filter: Optional["DomainFilter"] = None,
    ):
        """
        Initialize output formatter.

        Args:
            output_path: Path to output file
            mode: Operation mode ("ip_scan" or "url_scan")
            domain_filter: Optional DomainFilter for excluding domains
        """
        self.output_path = Path(output_path)
        self.mode = mode
        self.domain_filter = domain_filter

    def create_output(
        self,
        results: Union[List[Dict[str, Any]], Dict[str, Any]],
        parameters: Dict[str, Any],
        statistics: Dict[str, Any],
        input_hostnames: Optional[Set[str]] = None,
    ) -> Dict[str, Any]:
        """
        Create structured output dictionary.

        Args:
            results: List of scan results or dict with 'ips' and 'urls' for mixed mode
            parameters: Scan parameters used
            statistics: Scan statistics
            input_hostnames: Optional set of input hostnames for new discovery comparison

        Returns:
            Complete output structure
        """
        # Analyze hostnames from results with optional filtering and input comparison
        hostname_analysis = HostnameAnalyzer.analyze_results(
            results, self.domain_filter, input_hostnames
        )

        # Add filtered count to statistics if filtering was applied
        if self.domain_filter and "filtered_count" in hostname_analysis:
            statistics = dict(statistics)  # Create copy to avoid modifying original
            statistics["domains_filtered"] = hostname_analysis["filtered_count"]

        return {
            "metadata": {
                "version": "1.0",
                "scan_timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "mode": self.mode,
                "parameters": parameters,
                "statistics": statistics,
            },
            "results": results,
            "discovered_hosts": hostname_analysis,
        }

    def write_json(self, data: Dict[str, Any]) -> None:
        """
        Write data to JSON file atomically.

        Args:
            data: Data to write
        """
        # Create parent directory if needed
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write to temporary file first (atomic write)
        temp_path = self.output_path.with_suffix(".tmp")

        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            # Rename to final path (atomic on most systems)
            temp_path.replace(self.output_path)

            # Set restrictive permissions (600)
            self.output_path.chmod(0o600)

        except Exception as e:
            # Clean up temp file on error
            if temp_path.exists():
                temp_path.unlink()
            raise IOError(f"Failed to write output file: {e}") from e

    def write_stdout(self, data: Dict[str, Any]) -> None:
        """
        Write data to stdout.

        Args:
            data: Data to write
        """
        print(json.dumps(data, indent=2, ensure_ascii=False))

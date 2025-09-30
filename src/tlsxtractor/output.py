"""
Output formatting and JSON export.
"""

import json
from typing import List, Dict, Any, Set, Optional
from datetime import datetime, timezone
from pathlib import Path
import re


class HostnameAnalyzer:
    """
    Analyzes and extracts hostnames from scan results.

    Filters out wildcards and TLDs, provides sorted unique hostname lists.
    """

    # Common TLDs (subset - extend as needed)
    COMMON_TLDS = {
        'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
        'co', 'io', 'ai', 'app', 'dev', 'tech', 'info',
        'biz', 'name', 'pro', 'aero', 'museum',
        # Country codes
        'us', 'uk', 'de', 'fr', 'jp', 'cn', 'au', 'ca', 'br', 'in',
        'ru', 'it', 'es', 'nl', 'se', 'no', 'dk', 'fi', 'pl', 'ch',
        'at', 'be', 'cz', 'gr', 'hu', 'ie', 'pt', 'ro', 'sk', 'bg',
        'hr', 'lt', 'lv', 'ee', 'si', 'cy', 'mt', 'lu',
    }

    @staticmethod
    def is_wildcard(hostname: str) -> bool:
        """Check if hostname contains wildcard."""
        return '*' in hostname

    @staticmethod
    def is_tld_only(hostname: str) -> bool:
        """Check if hostname is just a TLD (no subdomain/domain)."""
        # Remove leading/trailing dots and whitespace
        hostname = hostname.strip().strip('.')

        # If it's empty or has no dots, it's likely a TLD
        if not hostname or '.' not in hostname:
            # Check if it's a known TLD
            return hostname.lower() in HostnameAnalyzer.COMMON_TLDS

        return False

    @staticmethod
    def extract_tld(hostname: str) -> str:
        """Extract TLD from hostname."""
        parts = hostname.strip().strip('.').split('.')
        if len(parts) > 0:
            return parts[-1].lower()
        return ""

    @staticmethod
    def is_valid_hostname(hostname: str) -> bool:
        """Validate hostname format."""
        if not hostname:
            return False

        # Basic hostname validation
        # Must have at least one dot (domain.tld)
        if '.' not in hostname:
            return False

        # Must not start or end with dot
        if hostname.startswith('.') or hostname.endswith('.'):
            return False

        # Basic pattern check (alphanumeric, hyphens, dots)
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(pattern, hostname))

    @staticmethod
    def analyze_results(results: Any, domain_filter: Optional['DomainFilter'] = None) -> Dict[str, Any]:
        """
        Analyze scan results and extract hostname summary.

        Args:
            results: Scan results (can be list or dict with ips/urls)
            domain_filter: Optional DomainFilter to apply exclusions

        Returns:
            Dictionary with hostname analysis:
            {
                "hostnames": [...],  # Sorted unique explicit hostnames
                "tlds": [...],       # Sorted unique TLDs
                "wildcards": [...],  # Wildcards found (informational)
                "total_hostnames": int,
                "total_tlds": int,
                "filtered_count": int  # Number of filtered domains (if filter provided)
            }
        """
        all_hostnames: Set[str] = set()
        wildcards: Set[str] = set()
        filtered_count = 0

        # Helper function to extract from a single result
        def extract_from_result(result: Optional[Dict[str, Any]]):
            # Skip if result is None
            if result is None:
                return
                
            # Additional type safety check
            if not isinstance(result, dict):
                return

            # Extract from SNI
            if result and result.get('sni'):
                all_hostnames.add(result['sni'])

            # Extract from domains list
            if result and result.get('domains'):
                for domain in result['domains']:
                    all_hostnames.add(domain)

            # Extract from certificate SAN
            certificate = result.get('certificate') if result else None
            if certificate and certificate.get('san'):
                for san in certificate['san']:
                    all_hostnames.add(san)

            # Extract from certificate CN
            if certificate and certificate.get('subject'):
                cert_cn = certificate['subject'].get('commonName')
                if cert_cn:
                    all_hostnames.add(cert_cn)

        # Handle different result formats
        if isinstance(results, dict):
            # Mixed scan format with ips and urls
            if 'ips' in results:
                for result in results['ips']:
                    extract_from_result(result)
            if 'urls' in results:
                for url_result in results['urls']:
                    # Skip if url_result is None
                    if url_result is None:
                        continue
                    # Add hostname
                    if url_result.get('hostname'):
                        all_hostnames.add(url_result['hostname'])
                    # Extract from connections
                    for conn in url_result.get('connections', []):
                        extract_from_result(conn)
        elif isinstance(results, list):
            # Simple list format (ip_scan or url_scan)
            for result in results:
                if result is not None and isinstance(result, dict):
                    extract_from_result(result)

        # Separate wildcards and regular hostnames
        regular_hostnames: Set[str] = set()
        tlds: Set[str] = set()

        for hostname in all_hostnames:
            hostname = hostname.strip().strip('.')  # Remove leading/trailing dots

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

            # Check if it's just a TLD
            if HostnameAnalyzer.is_tld_only(hostname):
                tlds.add(hostname.lower())
                continue

            # Validate and add
            if HostnameAnalyzer.is_valid_hostname(hostname):
                regular_hostnames.add(hostname.lower())

                # Also extract and track the TLD
                tld = HostnameAnalyzer.extract_tld(hostname)
                if tld and tld != hostname.lower():  # Don't add if hostname is same as TLD
                    tlds.add(tld)

        result = {
            "hostnames": sorted(list(regular_hostnames)),
            "tlds": sorted(list(tlds)),
            "wildcards": sorted(list(wildcards)),
            "total_hostnames": len(regular_hostnames),
            "total_tlds": len(tlds),
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

    def __init__(self, output_path: str, mode: str = "ip_scan", domain_filter: Optional['DomainFilter'] = None):
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
        results: List[Dict[str, Any]],
        parameters: Dict[str, Any],
        statistics: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Create structured output dictionary.

        Args:
            results: List of scan results
            parameters: Scan parameters used
            statistics: Scan statistics

        Returns:
            Complete output structure
        """
        # Analyze hostnames from results with optional filtering
        hostname_analysis = HostnameAnalyzer.analyze_results(results, self.domain_filter)

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
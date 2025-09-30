"""
DNS resolution functionality.

Implements IMPL-011: DNS resolution with caching and timeout handling.
"""

import asyncio
import logging
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
import aiodns
import socket


logger = logging.getLogger(__name__)


@dataclass
class DNSResult:
    """Result from DNS resolution."""

    hostname: str
    ips: List[str]
    status: str  # "success", "nxdomain", "timeout", "error"
    error: Optional[str] = None


class DNSResolver:
    """
    Handles DNS resolution with caching and concurrent lookups.

    Implements IMPL-011: DNS resolution
    """

    def __init__(self, timeout: int = 5, cache_enabled: bool = True):
        """
        Initialize DNS resolver.

        Args:
            timeout: DNS query timeout in seconds
            cache_enabled: Enable DNS response caching
        """
        self.timeout = timeout
        self.cache_enabled = cache_enabled
        self._cache: Dict[str, DNSResult] = {}
        self._resolver = aiodns.DNSResolver(timeout=timeout)

    async def resolve_hostname(self, hostname: str) -> DNSResult:
        """
        Resolve a hostname to IP addresses.

        Args:
            hostname: Hostname to resolve

        Returns:
            DNSResult with resolved IPs or error
        """
        # Check cache first
        if self.cache_enabled and hostname in self._cache:
            logger.debug(f"DNS cache hit for {hostname}")
            return self._cache[hostname]

        try:
            # Try to resolve as IPv4 first
            ips: Set[str] = set()

            # Query A records (IPv4)
            try:
                a_records = await asyncio.wait_for(
                    self._resolver.query(hostname, "A"), timeout=self.timeout
                )
                for record in a_records:
                    ips.add(record.host)
                logger.debug(f"Resolved {hostname} A records: {len(a_records)}")
            except aiodns.error.DNSError as e:
                if e.args[0] == aiodns.error.ARES_ENOTFOUND:
                    # No A records, try AAAA
                    pass
                else:
                    logger.debug(f"DNS A query error for {hostname}: {e}")
            except asyncio.TimeoutError:
                logger.debug(f"DNS A query timeout for {hostname}")

            # Query AAAA records (IPv6)
            try:
                aaaa_records = await asyncio.wait_for(
                    self._resolver.query(hostname, "AAAA"), timeout=self.timeout
                )
                for record in aaaa_records:
                    ips.add(record.host)
                logger.debug(f"Resolved {hostname} AAAA records: {len(aaaa_records)}")
            except aiodns.error.DNSError as e:
                if e.args[0] == aiodns.error.ARES_ENOTFOUND:
                    pass
                else:
                    logger.debug(f"DNS AAAA query error for {hostname}: {e}")
            except asyncio.TimeoutError:
                logger.debug(f"DNS AAAA query timeout for {hostname}")

            if not ips:
                # No records found
                result = DNSResult(
                    hostname=hostname,
                    ips=[],
                    status="nxdomain",
                    error="No DNS records found",
                )
            else:
                result = DNSResult(
                    hostname=hostname, ips=sorted(list(ips)), status="success"
                )

        except asyncio.TimeoutError:
            logger.debug(f"DNS timeout for {hostname}")
            result = DNSResult(
                hostname=hostname, ips=[], status="timeout", error="DNS query timeout"
            )
        except aiodns.error.DNSError as e:
            logger.debug(f"DNS error for {hostname}: {e}")
            error_msg = self._parse_dns_error(e)
            result = DNSResult(
                hostname=hostname, ips=[], status="error", error=error_msg
            )
        except Exception as e:
            logger.debug(f"Unexpected DNS error for {hostname}: {e}")
            result = DNSResult(
                hostname=hostname,
                ips=[],
                status="error",
                error=f"DNS resolution failed: {str(e)}",
            )

        # Cache result
        if self.cache_enabled:
            self._cache[hostname] = result

        return result

    async def resolve_multiple(
        self, hostnames: List[str], concurrency: int = 10
    ) -> Dict[str, DNSResult]:
        """
        Resolve multiple hostnames concurrently.

        Args:
            hostnames: List of hostnames to resolve
            concurrency: Maximum concurrent resolutions

        Returns:
            Dictionary mapping hostname to DNSResult
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def resolve_with_semaphore(hostname: str):
            async with semaphore:
                return hostname, await self.resolve_hostname(hostname)

        tasks = [resolve_with_semaphore(hostname) for hostname in hostnames]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Build result dictionary
        result_dict = {}
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"DNS resolution exception: {result}")
                continue
            hostname, dns_result = result
            result_dict[hostname] = dns_result

        return result_dict

    @staticmethod
    def _parse_dns_error(error: aiodns.error.DNSError) -> str:
        """
        Parse aiodns error into user-friendly message.

        Args:
            error: aiodns DNSError

        Returns:
            Error message string
        """
        error_code = error.args[0] if error.args else None

        error_messages = {
            aiodns.error.ARES_ENOTFOUND: "Domain not found (NXDOMAIN)",
            aiodns.error.ARES_ENODATA: "No DNS data available",
            aiodns.error.ARES_ESERVFAIL: "DNS server failure",
            aiodns.error.ARES_ETIMEOUT: "DNS query timeout",
            aiodns.error.ARES_ECONNREFUSED: "DNS server connection refused",
        }

        return error_messages.get(error_code, f"DNS error: {str(error)}")

    def clear_cache(self) -> None:
        """Clear the DNS resolution cache."""
        self._cache.clear()
        logger.debug("DNS cache cleared")

    def get_cache_stats(self) -> Dict[str, int]:
        """
        Get DNS cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        return {
            "cached_entries": len(self._cache),
            "successful": sum(
                1 for r in self._cache.values() if r.status == "success"
            ),
            "failed": sum(1 for r in self._cache.values() if r.status != "success"),
        }
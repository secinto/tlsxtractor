"""
DNS resolution functionality.

Implements IMPL-011: DNS resolution with caching and timeout handling.
"""

import asyncio
import logging
import time
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass
from collections import OrderedDict
import aiodns
import socket


logger = logging.getLogger(__name__)


class LRUCache:
    """
    Simple LRU (Least Recently Used) cache with TTL support.

    This cache automatically evicts least recently used entries when the cache
    is full and supports time-to-live for entries.
    """

    def __init__(self, maxsize: int = 10000, ttl: int = 3600):
        """
        Initialize LRU cache.

        Args:
            maxsize: Maximum number of entries to cache
            ttl: Time-to-live in seconds (default: 1 hour)
        """
        self.maxsize = maxsize
        self.ttl = ttl
        self._cache: OrderedDict[str, Tuple[DNSResult, float]] = OrderedDict()

    def get(self, key: str) -> Optional["DNSResult"]:
        """
        Get value from cache if exists and not expired.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        if key not in self._cache:
            return None

        value, timestamp = self._cache[key]

        # Check if expired
        if time.time() - timestamp > self.ttl:
            del self._cache[key]
            logger.debug(f"DNS cache entry expired for {key}")
            return None

        # Move to end (mark as recently used)
        self._cache.move_to_end(key)
        return value

    def put(self, key: str, value: "DNSResult") -> None:
        """
        Put value in cache.

        Args:
            key: Cache key
            value: Value to cache
        """
        # Remove if already exists
        if key in self._cache:
            del self._cache[key]

        # Add new entry
        self._cache[key] = (value, time.time())

        # Evict oldest if cache is full
        if len(self._cache) > self.maxsize:
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]
            logger.debug(f"DNS cache evicted oldest entry: {oldest_key}")

    def clear(self) -> None:
        """Clear all cache entries."""
        self._cache.clear()

    def size(self) -> int:
        """Get current cache size."""
        return len(self._cache)

    def stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        return {
            "size": len(self._cache),
            "maxsize": self.maxsize,
            "ttl": self.ttl,
        }


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

    def __init__(
        self,
        timeout: int = 5,
        cache_enabled: bool = True,
        cache_maxsize: int = 10000,
        cache_ttl: int = 3600,
    ):
        """
        Initialize DNS resolver.

        Args:
            timeout: DNS query timeout in seconds
            cache_enabled: Enable DNS response caching
            cache_maxsize: Maximum number of entries in cache
            cache_ttl: Time-to-live for cache entries in seconds
        """
        self.timeout = timeout
        self.cache_enabled = cache_enabled
        self._cache = LRUCache(maxsize=cache_maxsize, ttl=cache_ttl) if cache_enabled else None
        self._resolver = aiodns.DNSResolver(timeout=timeout)
        self._cache_hits = 0
        self._cache_misses = 0

    async def resolve_hostname(self, hostname: str) -> DNSResult:
        """
        Resolve a hostname to IP addresses.

        Args:
            hostname: Hostname to resolve

        Returns:
            DNSResult with resolved IPs or error
        """
        # Check cache first
        if self.cache_enabled and self._cache:
            cached = self._cache.get(hostname)
            if cached:
                self._cache_hits += 1
                logger.debug(f"DNS cache hit for {hostname} (hits: {self._cache_hits})")
                return cached
            self._cache_misses += 1

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
        if self.cache_enabled and self._cache:
            self._cache.put(hostname, result)
            logger.debug(f"DNS cached result for {hostname} (cache size: {self._cache.size()})")

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
        if self._cache:
            self._cache.clear()
            self._cache_hits = 0
            self._cache_misses = 0
            logger.debug("DNS cache cleared")

    def get_cache_stats(self) -> Dict[str, any]:
        """
        Get DNS cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        if not self._cache:
            return {
                "enabled": False,
                "hits": self._cache_hits,
                "misses": self._cache_misses,
            }

        cache_stats = self._cache.stats()
        hit_rate = (
            self._cache_hits / (self._cache_hits + self._cache_misses)
            if (self._cache_hits + self._cache_misses) > 0
            else 0
        )

        return {
            "enabled": True,
            "size": cache_stats["size"],
            "maxsize": cache_stats["maxsize"],
            "ttl": cache_stats["ttl"],
            "hits": self._cache_hits,
            "misses": self._cache_misses,
            "hit_rate": f"{hit_rate * 100:.2f}%",
        }
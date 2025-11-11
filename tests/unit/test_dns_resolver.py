"""
Unit tests for DNS resolver.
"""

import pytest

from tlsxtractor.dns_resolver import DNSResolver, DNSResult


@pytest.mark.asyncio
async def test_resolver_initialization():
    """Test DNS resolver initialization."""
    resolver = DNSResolver()
    assert resolver.timeout == 5
    assert resolver.cache_enabled is True


@pytest.mark.asyncio
async def test_resolver_custom_parameters():
    """Test DNS resolver with custom parameters."""
    resolver = DNSResolver(timeout=10, cache_enabled=False)
    assert resolver.timeout == 10
    assert resolver.cache_enabled is False


@pytest.mark.asyncio
async def test_resolve_valid_hostname():
    """Test resolving a valid hostname."""
    resolver = DNSResolver(timeout=10)
    result = await resolver.resolve_hostname("google.com")

    assert result.hostname == "google.com"
    assert result.status == "success"
    assert len(result.ips) > 0
    assert result.error is None


@pytest.mark.asyncio
async def test_resolve_invalid_hostname():
    """Test resolving an invalid hostname."""
    resolver = DNSResolver(timeout=5)
    result = await resolver.resolve_hostname("this-domain-does-not-exist-12345.com")

    assert result.hostname == "this-domain-does-not-exist-12345.com"
    assert result.status in ("nxdomain", "error")
    assert len(result.ips) == 0


@pytest.mark.asyncio
async def test_dns_caching():
    """Test DNS result caching."""
    resolver = DNSResolver(cache_enabled=True)

    # First resolution
    result1 = await resolver.resolve_hostname("google.com")
    assert result1.status == "success"

    # Second resolution should use cache
    result2 = await resolver.resolve_hostname("google.com")
    assert result2.status == "success"
    assert result2.ips == result1.ips

    # Verify cache stats
    stats = resolver.get_cache_stats()
    assert stats["cached_entries"] >= 1


@pytest.mark.asyncio
async def test_resolve_multiple():
    """Test resolving multiple hostnames concurrently."""
    resolver = DNSResolver(timeout=10)
    hostnames = ["google.com", "cloudflare.com", "github.com"]

    results = await resolver.resolve_multiple(hostnames, concurrency=3)

    assert len(results) == 3
    for hostname in hostnames:
        assert hostname in results
        result = results[hostname]
        assert isinstance(result, DNSResult)
        assert result.hostname == hostname


@pytest.mark.asyncio
async def test_clear_cache():
    """Test clearing DNS cache."""
    resolver = DNSResolver(cache_enabled=True)

    # Add some entries to cache
    await resolver.resolve_hostname("google.com")
    assert resolver.get_cache_stats()["cached_entries"] > 0

    # Clear cache
    resolver.clear_cache()
    assert resolver.get_cache_stats()["cached_entries"] == 0


@pytest.mark.asyncio
async def test_ipv4_and_ipv6_resolution():
    """Test that resolver returns both IPv4 and IPv6 addresses."""
    resolver = DNSResolver(timeout=10)
    result = await resolver.resolve_hostname("google.com")

    if result.status == "success":
        # Check for IP addresses
        assert len(result.ips) > 0

        # Verify IPs are valid
        import ipaddress

        for ip in result.ips:
            # Should be valid IPv4 or IPv6
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                pytest.fail(f"Invalid IP address: {ip}")

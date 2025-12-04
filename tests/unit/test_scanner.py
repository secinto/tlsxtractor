"""
Unit tests for TLS scanner.
"""

import pytest

from tlsxtractor.scanner import ScanResult, TLSScanner


@pytest.mark.asyncio
async def test_scanner_initialization():
    """Test scanner initialization with default parameters."""
    scanner = TLSScanner()
    assert scanner.timeout == 5
    assert scanner.retry_count == 3
    assert scanner.port == 443


@pytest.mark.asyncio
async def test_scanner_custom_parameters():
    """Test scanner initialization with custom parameters."""
    scanner = TLSScanner(timeout=10, retry_count=5, port=8443)
    assert scanner.timeout == 10
    assert scanner.retry_count == 5
    assert scanner.port == 8443


@pytest.mark.asyncio
async def test_scan_valid_target():
    """Test scanning a valid DNS server."""
    scanner = TLSScanner(timeout=10, retry_count=1)
    result = await scanner.scan_target("1.1.1.1", 443)

    assert result.ip == "1.1.1.1"
    assert result.port == 443
    assert result.status == "success"
    assert len(result.domains) > 0
    assert "cloudflare-dns.com" in result.domains


@pytest.mark.asyncio
async def test_scan_invalid_target():
    """Test scanning an invalid/unreachable target."""
    scanner = TLSScanner(timeout=2, retry_count=1)
    result = await scanner.scan_target("192.0.2.1", 443)  # TEST-NET-1 (should not respond)

    assert result.ip == "192.0.2.1"
    assert result.port == 443
    assert result.status in ("timeout", "error", "refused")


@pytest.mark.asyncio
async def test_scan_multiple_targets():
    """Test scanning multiple targets concurrently."""
    scanner = TLSScanner(timeout=10, retry_count=1)
    targets = [
        ("1.1.1.1", 443, None),
        ("8.8.8.8", 443, None),
    ]

    results = await scanner.scan_multiple(targets, concurrency=2)

    assert len(results) == 2
    assert all(isinstance(r, ScanResult) for r in results)

    # At least one should succeed
    successful = [r for r in results if r.status == "success"]
    assert len(successful) > 0


@pytest.mark.asyncio
async def test_scan_with_sni():
    """Test scanning with SNI provided."""
    scanner = TLSScanner(timeout=10, retry_count=1)
    result = await scanner.scan_target("1.1.1.1", 443, sni="cloudflare-dns.com")

    assert result.sni == "cloudflare-dns.com"
    if result.status == "success":
        assert len(result.domains) > 0

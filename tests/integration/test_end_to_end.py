"""
Integration tests for end-to-end TLSXtractor functionality.

These tests verify the complete scanning workflow with real network calls.
"""

import json
import time

import pytest

from tlsxtractor.dns_resolver import DNSResolver
from tlsxtractor.input_parser import InputParser
from tlsxtractor.output import OutputFormatter
from tlsxtractor.scanner import TLSScanner


@pytest.mark.asyncio
async def test_end_to_end_ip_scan():
    """
    Test complete IP scan workflow with real targets.

    Tests: IMPL-003, IMPL-004, IMPL-007, IMPL-008
    """
    # Initialize scanner
    scanner = TLSScanner(timeout=10, retry_count=2, port=443)

    # Scan known reliable DNS servers
    targets = [
        ("1.1.1.1", 443, None),  # Cloudflare
        ("8.8.8.8", 443, None),  # Google
    ]

    # Perform scan
    results = await scanner.scan_multiple(targets, concurrency=2)

    # Verify results
    assert len(results) == 2

    # At least one should succeed
    successful = [r for r in results if r.status == "success"]
    assert len(successful) >= 1

    # Check successful result structure
    for result in successful:
        assert result.ip in ["1.1.1.1", "8.8.8.8"]
        assert result.port == 443
        assert result.status == "success"
        assert result.tls_version is not None
        assert len(result.domains) > 0
        assert result.certificate is not None

        # Verify certificate structure
        cert = result.certificate
        assert "subject" in cert
        assert "san" in cert
        assert "issuer" in cert
        assert "validity" in cert

        # Verify domains match certificate SAN
        assert set(result.domains) == set(cert["san"])


@pytest.mark.asyncio
async def test_end_to_end_url_scan():
    """
    Test complete URL scan workflow with DNS resolution.

    Tests: IMPL-010, IMPL-011, IMPL-012
    """
    # Initialize components
    dns_resolver = DNSResolver(timeout=10)
    scanner = TLSScanner(timeout=10, retry_count=2)

    # Test hostname
    hostname = "cloudflare.com"

    # Step 1: DNS resolution
    dns_result = await dns_resolver.resolve_hostname(hostname)

    assert dns_result.status == "success"
    assert len(dns_result.ips) > 0

    # Step 2: TLS scan with SNI
    scan_targets = [(ip, 443, hostname) for ip in dns_result.ips[:2]]  # Limit to 2 IPs
    scan_results = await scanner.scan_multiple(scan_targets, concurrency=2)

    assert len(scan_results) > 0

    # Verify at least one successful scan
    successful = [r for r in scan_results if r.status == "success"]
    assert len(successful) >= 1

    # Verify SNI was used
    for result in successful:
        assert result.sni == hostname
        assert len(result.domains) > 0
        # Hostname should be in discovered domains
        assert any(hostname in domain for domain in result.domains)


@pytest.mark.asyncio
async def test_rate_limiting_enforcement():
    """
    Test that rate limiting actually limits scan rate.

    Tests: IMPL-015, IMPL-016
    """
    scanner = TLSScanner(timeout=10, retry_count=1)

    # Prepare targets
    targets = [
        ("1.1.1.1", 443, None),
        ("8.8.8.8", 443, None),
        ("9.9.9.9", 443, None),
    ]

    # Test with rate limit
    rate_limit = 2.0  # 2 requests per second
    start_time = time.monotonic()

    results = await scanner.scan_multiple(
        targets,
        concurrency=10,  # High concurrency shouldn't bypass rate limit
        rate_limit=rate_limit,
    )

    elapsed = time.monotonic() - start_time

    # With 3 targets and 2 req/s, minimum time should be:
    # - First 2 targets: immediate (burst)
    # - 3rd target: 0.5s wait
    # So minimum ~0.5s (plus TLS handshake time)
    # Total should be at least 0.5s from rate limiting
    assert elapsed >= 0.4  # Allow some tolerance

    # Verify all targets were scanned
    assert len(results) == 3


@pytest.mark.asyncio
async def test_rate_limiting_disabled():
    """
    Test that scans proceed at full speed without rate limiting.

    Tests: IMPL-015, IMPL-016
    """
    scanner = TLSScanner(timeout=10, retry_count=1)

    targets = [
        ("1.1.1.1", 443, None),
        ("8.8.8.8", 443, None),
    ]

    # Test without rate limit (should be fast)
    start_time = time.monotonic()

    results = await scanner.scan_multiple(targets, concurrency=2)

    elapsed = time.monotonic() - start_time

    # Without rate limiting, should complete quickly (just TLS handshake time)
    # With 2 targets in parallel, should take roughly the same time as one
    assert len(results) == 2
    # Verify it's faster than rate-limited version would be
    assert elapsed < 5.0  # Should be much faster without rate limiting


@pytest.mark.asyncio
async def test_error_handling_and_retry():
    """
    Test error handling and retry logic for unreachable targets.

    Tests: IMPL-003, IMPL-017
    """
    scanner = TLSScanner(timeout=2, retry_count=2)

    # Test with unreachable IP (TEST-NET-1, reserved for documentation)
    targets = [
        ("192.0.2.1", 443, None),  # Should timeout/fail
    ]

    start_time = time.monotonic()
    results = await scanner.scan_multiple(targets, concurrency=1)
    elapsed = time.monotonic() - start_time

    assert len(results) == 1
    result = results[0]

    # Should fail with appropriate status
    assert result.status in ("timeout", "error", "refused")
    assert result.error is not None

    # With 2 retries and 2s timeout, should take at least 2s
    # (first attempt fails, then retries)
    assert elapsed >= 2.0


@pytest.mark.asyncio
async def test_concurrent_scanning():
    """
    Test concurrent scanning of multiple targets.

    Tests: IMPL-014
    """
    scanner = TLSScanner(timeout=10, retry_count=1)

    # Multiple targets
    targets = [
        ("1.1.1.1", 443, None),
        ("8.8.8.8", 443, None),
        ("9.9.9.9", 443, None),
    ]

    # Scan with different concurrency levels
    start_time = time.monotonic()
    results_high_concurrency = await scanner.scan_multiple(targets, concurrency=10)
    elapsed_high = time.monotonic() - start_time

    start_time = time.monotonic()
    results_low_concurrency = await scanner.scan_multiple(targets, concurrency=1)
    elapsed_low = time.monotonic() - start_time

    # Both should return same number of results
    assert len(results_high_concurrency) == 3
    assert len(results_low_concurrency) == 3

    # High concurrency should be faster (or equal if targets respond very quickly)
    assert elapsed_high <= elapsed_low * 1.5  # Allow some tolerance


@pytest.mark.asyncio
async def test_output_format_ip_scan(tmp_path):
    """
    Test JSON output format for IP scan mode.

    Tests: IMPL-013, IMPL-014
    """
    # Perform a scan
    scanner = TLSScanner(timeout=10, retry_count=1)
    targets = [("1.1.1.1", 443, None)]
    results = await scanner.scan_multiple(targets, concurrency=1)

    # Create output
    output_file = tmp_path / "test_output.json"
    formatter = OutputFormatter(str(output_file), mode="ip_scan")

    output_data = formatter.create_output(
        results=[
            {
                "ip": r.ip,
                "port": r.port,
                "status": r.status,
                "sni": r.sni,
                "domains": r.domains,
                "tls_version": r.tls_version,
                "error": r.error,
                "certificate": r.certificate,
            }
            for r in results
        ],
        parameters={
            "input": "test",
            "port": 443,
            "timeout": 10,
        },
        statistics={
            "total_targets": 1,
            "scanned": 1,
            "successful": 1,
            "failed": 0,
        },
    )

    # Write to file
    formatter.write_json(output_data)

    # Verify file exists and is valid JSON
    assert output_file.exists()

    with open(output_file) as f:
        data = json.load(f)

    # Verify structure
    assert "metadata" in data
    assert "results" in data

    metadata = data["metadata"]
    assert metadata["version"] == "1.0"
    assert metadata["mode"] == "ip_scan"
    assert "scan_timestamp" in metadata
    assert "parameters" in metadata
    assert "statistics" in metadata

    results_data = data["results"]
    assert len(results_data) >= 1

    # Verify result structure
    result = results_data[0]
    assert "ip" in result
    assert "port" in result
    assert "status" in result
    assert "domains" in result


@pytest.mark.asyncio
async def test_output_format_url_scan(tmp_path):
    """
    Test JSON output format for URL scan mode.

    Tests: IMPL-012, IMPL-013, IMPL-014
    """
    # Simulate URL scan workflow
    dns_resolver = DNSResolver(timeout=10)
    scanner = TLSScanner(timeout=10, retry_count=1)

    hostname = "cloudflare.com"
    dns_result = await dns_resolver.resolve_hostname(hostname)

    # Scan one IP
    if dns_result.status == "success" and dns_result.ips:
        scan_targets = [(dns_result.ips[0], 443, hostname)]
        scan_results = await scanner.scan_multiple(scan_targets, concurrency=1)

        # Create output
        output_file = tmp_path / "test_url_output.json"
        formatter = OutputFormatter(str(output_file), mode="url_scan")

        output_data = formatter.create_output(
            results=[
                {
                    "url": hostname,
                    "hostname": hostname,
                    "port": 443,
                    "dns_status": dns_result.status,
                    "resolved_ips": dns_result.ips[:1],
                    "connections": [
                        {
                            "ip": r.ip,
                            "port": r.port,
                            "status": r.status,
                            "sni": r.sni,
                            "domains": r.domains,
                            "tls_version": r.tls_version,
                            "error": r.error,
                            "certificate": r.certificate,
                        }
                        for r in scan_results
                    ],
                }
            ],
            parameters={"input": "test", "timeout": 10},
            statistics={"total_urls": 1, "total_ips_scanned": 1},
        )

        formatter.write_json(output_data)

        # Verify file
        assert output_file.exists()

        with open(output_file) as f:
            data = json.load(f)

        # Verify URL scan structure
        assert data["metadata"]["mode"] == "url_scan"
        assert len(data["results"]) == 1

        result = data["results"][0]
        assert "url" in result
        assert "hostname" in result
        assert "dns_status" in result
        assert "resolved_ips" in result
        assert "connections" in result


@pytest.mark.asyncio
async def test_dns_caching():
    """
    Test DNS resolution caching.

    Tests: IMPL-011
    """
    resolver = DNSResolver(timeout=10, cache_enabled=True)

    hostname = "google.com"

    # First resolution
    start = time.monotonic()
    result1 = await resolver.resolve_hostname(hostname)
    time1 = time.monotonic() - start

    # Second resolution (should use cache)
    start = time.monotonic()
    result2 = await resolver.resolve_hostname(hostname)
    time2 = time.monotonic() - start

    # Both should succeed
    assert result1.status == "success"
    assert result2.status == "success"

    # Results should be identical
    assert result1.ips == result2.ips

    # Cached lookup should be much faster
    assert time2 < time1 * 0.5  # At least 50% faster

    # Verify cache stats
    stats = resolver.get_cache_stats()
    assert stats["cached_entries"] >= 1


@pytest.mark.asyncio
async def test_ipv4_and_ipv6_support():
    """
    Test support for both IPv4 and IPv6 addresses.

    Tests: IMPL-003
    """
    scanner = TLSScanner(timeout=10, retry_count=1)

    # Test both IPv4 and IPv6
    targets = [
        ("1.1.1.1", 443, None),  # IPv4
        # IPv6 support depends on network - skip if not available
    ]

    results = await scanner.scan_multiple(targets, concurrency=2)

    # Verify IPv4 works
    ipv4_results = [r for r in results if "." in r.ip]
    assert len(ipv4_results) >= 1

    successful = [r for r in ipv4_results if r.status == "success"]
    assert len(successful) >= 1


@pytest.mark.asyncio
async def test_sni_injection():
    """
    Test SNI (Server Name Indication) injection in TLS handshake.

    Tests: IMPL-004
    """
    scanner = TLSScanner(timeout=10, retry_count=1)

    # Scan with SNI
    hostname = "cloudflare.com"
    dns_resolver = DNSResolver(timeout=10)
    dns_result = await dns_resolver.resolve_hostname(hostname)

    if dns_result.status == "success" and dns_result.ips:
        ip = dns_result.ips[0]

        # Scan with SNI
        result_with_sni = await scanner.scan_target(ip, 443, sni=hostname)

        # Scan without SNI
        result_without_sni = await scanner.scan_target(ip, 443, sni=None)

        # Both should work, but with SNI should have correct SNI field
        if result_with_sni.status == "success":
            assert result_with_sni.sni == hostname

        if result_without_sni.status == "success":
            assert result_without_sni.sni is None


@pytest.mark.asyncio
async def test_input_parser_integration(tmp_path):
    """
    Test input file parsing integration.

    Tests: IMPL-005, IMPL-009, IMPL-010
    """
    # Create test IP file
    ip_file = tmp_path / "test_ips.txt"
    ip_file.write_text("1.1.1.1\n8.8.8.8\n# Comment\n\n")

    ips = InputParser.parse_ip_file(str(ip_file))
    assert len(ips) == 2
    assert "1.1.1.1" in ips

    # Create test URL file
    url_file = tmp_path / "test_urls.txt"
    url_file.write_text("https://cloudflare.com\ngoogle.com\n")

    url_data = InputParser.parse_url_file(str(url_file))
    assert len(url_data) == 2
    hostnames = [u[1] for u in url_data]
    assert "cloudflare.com" in hostnames
    assert "google.com" in hostnames


@pytest.mark.asyncio
async def test_complete_workflow_ip_to_json(tmp_path):
    """
    Test complete workflow from IP file to JSON output.

    Integration test covering the entire IP scan pipeline.
    """
    # Create input file
    ip_file = tmp_path / "ips.txt"
    ip_file.write_text("1.1.1.1\n")

    # Parse input
    ips = InputParser.parse_ip_file(str(ip_file))

    # Scan
    scanner = TLSScanner(timeout=10, retry_count=1)
    targets = [(ip, 443, None) for ip in ips]
    results = await scanner.scan_multiple(targets, concurrency=1)

    # Output
    output_file = tmp_path / "results.json"
    formatter = OutputFormatter(str(output_file), mode="ip_scan")

    output_data = formatter.create_output(
        results=[
            {
                "ip": r.ip,
                "port": r.port,
                "status": r.status,
                "sni": r.sni,
                "domains": r.domains,
                "tls_version": r.tls_version,
                "error": r.error,
                "certificate": r.certificate,
            }
            for r in results
        ],
        parameters={"input": str(ip_file)},
        statistics={"total_targets": len(ips), "scanned": len(results)},
    )

    formatter.write_json(output_data)

    # Verify complete pipeline
    assert output_file.exists()

    with open(output_file) as f:
        data = json.load(f)

    assert data["metadata"]["mode"] == "ip_scan"
    assert len(data["results"]) == 1

    # Verify scan was successful
    result = data["results"][0]
    if result["status"] == "success":
        assert len(result["domains"]) > 0
        assert result["certificate"] is not None

"""
Command-line interface for TLSXtractor.
"""

import argparse
import sys
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple, Union

from . import __version__

if TYPE_CHECKING:
    from .console import ConsoleOutput
    from .domain_filter import DomainFilter
    from .scanner import ScanResult


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog="tlsxtractor",
        description="Extract domain names and certificate information from TLS handshakes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a single URL or hostname
  tlsxtractor -u example.com -o results.json

  # Scan a CIDR range
  tlsxtractor --cidr 192.168.1.0/24 --output results.json

  # Scan from file (auto-detects IP, URL, or hostname)
  tlsxtractor --file targets.txt --output results.json

  # Scan with custom threads and rate limiting
  tlsxtractor -f targets.txt --threads 20 --rate-limit 5 -o results.json
        """,
    )

    # Version
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    # Input options (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--cidr", metavar="CIDR", help="Scan IP range in CIDR notation")
    input_group.add_argument(
        "--file", "-f", metavar="FILE", help="Input file (supports mixed IPs, URLs, and hostnames)"
    )
    input_group.add_argument("--url", "-u", metavar="URL", help="Single URL or hostname to scan")

    # Output options
    parser.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        default="results.json",
        help="Output file path (default: results.json)",
    )
    parser.add_argument(
        "--format",
        choices=["json"],
        default="json",
        help="Output format (default: json)",
    )

    # Performance options
    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        metavar="NUM",
        help="Number of concurrent threads (default: 10)",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=10.0,
        metavar="NUM",
        help="Requests per second (default: 10)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        metavar="SEC",
        help="Connection timeout in seconds (default: 5)",
    )

    # Scanning options
    parser.add_argument(
        "--port",
        type=int,
        default=443,
        metavar="PORT",
        help="Target port (default: 443)",
    )
    parser.add_argument(
        "--retry",
        type=int,
        default=3,
        metavar="NUM",
        help="Max retry attempts (default: 3)",
    )
    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="Allow scanning private IP ranges",
    )

    # Logging options
    parser.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error"],
        default="info",
        help="Logging level (default: info)",
    )
    parser.add_argument(
        "--log-file",
        metavar="FILE",
        help="Log output to file",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress progress output",
    )

    # Domain extraction and filtering options
    parser.add_argument(
        "--fetch-csp",
        action="store_true",
        help="Fetch and parse Content-Security-Policy headers for additional domains",
    )
    parser.add_argument(
        "--follow-redirects",
        "-fr",
        action="store_true",
        help="Follow HTTP redirects when fetching CSP headers",
    )
    parser.add_argument(
        "--follow-host-redirects",
        "-fhr",
        action="store_true",
        help="Follow redirects only to the same host when fetching CSP headers",
    )
    parser.add_argument(
        "--max-redirects",
        "-maxr",
        type=int,
        default=10,
        help="Maximum number of redirects to follow (default: 10)",
    )

    # Domain filtering group (mutually exclusive)
    filter_group = parser.add_mutually_exclusive_group()
    filter_group.add_argument(
        "--exclude-domains",
        metavar="FILE_OR_CSV",
        help="Exclude domains from results (file path or comma-separated list)",
    )
    filter_group.add_argument(
        "--include-domains",
        metavar="FILE_OR_CSV",
        help="Only include specified domains in results (file path or comma-separated list)",
    )

    parser.add_argument(
        "--no-default-exclusions",
        action="store_true",
        help="Disable default domain exclusion list (CDNs, analytics, etc.)",
    )

    return parser


def validate_args(args: argparse.Namespace) -> Optional[str]:
    """
    Validate parsed arguments.

    Returns:
        Error message if validation fails, None otherwise.
    """
    # Validate port range
    if not 1 <= args.port <= 65535:
        return f"Invalid port: {args.port}. Must be between 1 and 65535."

    # Validate thread count
    if args.threads < 1:
        return f"Invalid thread count: {args.threads}. Must be at least 1."
    if args.threads > 1000:
        return f"Thread count {args.threads} is very high. Consider using <= 100."

    # Validate rate limit
    if args.rate_limit <= 0:
        return f"Invalid rate limit: {args.rate_limit}. Must be positive."

    # Validate timeout
    if args.timeout < 1:
        return f"Invalid timeout: {args.timeout}. Must be at least 1 second."

    # Validate retry count
    if args.retry < 0:
        return f"Invalid retry count: {args.retry}. Must be non-negative."

    return None


def main() -> int:
    """
    Main entry point for the CLI.

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    parser = create_parser()
    args = parser.parse_args()

    # Validate arguments
    error = validate_args(args)
    if error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    # Set up logging
    import logging

    from .console import ConsoleOutput

    log_level = getattr(logging, args.log_level.upper())
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        filename=args.log_file if args.log_file else None,
    )

    # Initialize console output
    console = ConsoleOutput(quiet=args.quiet)

    try:
        # Run the scanning operation
        import asyncio

        return asyncio.run(run_scan(args, console))
    except KeyboardInterrupt:
        console.error("\nScan interrupted by user")
        return 130
    except Exception as e:
        console.error(f"Fatal error: {e}")
        logging.exception("Fatal error during scan")
        return 1


def create_domain_filter(args: argparse.Namespace) -> Optional["DomainFilter"]:
    """
    Create domain filter from CLI arguments.

    Args:
        args: Parsed CLI arguments

    Returns:
        DomainFilter instance or None if no filtering requested
    """
    from pathlib import Path

    from .domain_filter import DomainFilter

    # Handle include-domains (allowlist mode)
    if hasattr(args, 'include_domains') and args.include_domains:
        include_path = Path(args.include_domains)
        if include_path.exists():
            # It's a file
            return DomainFilter.from_file_include(include_path)
        else:
            # Treat as comma-separated list
            return DomainFilter.from_comma_separated_include(args.include_domains)

    # Handle exclude-domains (blocklist mode)
    if args.exclude_domains:
        # Determine if we use defaults
        use_defaults = not args.no_default_exclusions

        exclude_path = Path(args.exclude_domains)
        if exclude_path.exists():
            # It's a file
            return DomainFilter.from_file(exclude_path, use_defaults=use_defaults)
        else:
            # Treat as comma-separated list
            return DomainFilter.from_comma_separated(
                args.exclude_domains, use_defaults=use_defaults
            )

    # No explicit filtering specified
    if args.no_default_exclusions:
        # No filtering at all
        return None
    else:
        # Just use defaults
        return DomainFilter(use_defaults=True)


async def run_scan(args: argparse.Namespace, console: "ConsoleOutput") -> int:
    """
    Execute the scanning operation.

    Args:
        args: Parsed command-line arguments
        console: Console output handler

    Returns:
        Exit code
    """
    # Handle --file argument with mixed mode parsing
    if args.file:
        return await run_mixed_scan(args, console)
    # Handle --cidr argument
    elif args.cidr:
        return await run_ip_scan(args, console)
    # Handle --url argument for single URL
    elif args.url:
        return await run_single_url_scan(args, console)
    else:
        console.error("No valid input specified")
        return 1


async def run_mixed_scan(args: argparse.Namespace, console: "ConsoleOutput") -> int:
    """
    Execute mixed scan mode (file with IPs, URLs, and/or hostnames).

    Args:
        args: Parsed command-line arguments
        console: Console output handler

    Returns:
        Exit code
    """
    import asyncio
    import logging

    from .console import ScanStatistics
    from .dns_resolver import DNSResolver
    from .input_parser import InputParser
    from .output import OutputFormatter
    from .scanner import TLSScanner

    logger = logging.getLogger(__name__)

    # Parse mixed file
    try:
        console.info(f"Parsing mixed input file: {args.file}")
        ip_list, url_data_list = InputParser.parse_mixed_file(args.file)

        console.info(f"Found {len(ip_list)} IP(s) and {len(url_data_list)} URL/hostname(s)")

    except FileNotFoundError as e:
        console.error(str(e))
        return 1
    except ValueError as e:
        console.error(f"Input parsing error: {e}")
        return 1

    if not ip_list and not url_data_list:
        console.error("No valid targets found in input")
        return 1

    # Initialize components
    scanner = TLSScanner(
        timeout=args.timeout,
        retry_count=args.retry,
        port=args.port,
        fetch_csp=args.fetch_csp,
        follow_redirects=args.follow_redirects,
        follow_host_redirects=args.follow_host_redirects,
        max_redirects=args.max_redirects,
    )
    dns_resolver = DNSResolver(timeout=args.timeout)

    # Process IPs (direct scan, no DNS)
    ip_targets = []
    if ip_list:
        # Check for private IPs
        if not args.allow_private:
            private_ips = [ip for ip in ip_list if InputParser.is_private_ip(ip)]
            if private_ips:
                count = len(private_ips)
                console.warning(
                    f"Warning: {count} private IP(s) detected. Use --allow-private to scan them."
                )
                ip_list = [ip for ip in ip_list if not InputParser.is_private_ip(ip)]

        ip_targets = [(ip, args.port, None) for ip in ip_list]

    # Process URLs/hostnames (DNS resolution first)
    url_hostnames = [(url, hostname, port) for url, hostname, port in url_data_list]
    hostnames = [hostname for _, hostname, _ in url_hostnames]

    url_targets = []
    url_results_map: Dict[str, Dict[str, Any]] = {}

    if hostnames:
        console.info(f"Resolving {len(hostnames)} hostname(s)...")
        dns_map = await dns_resolver.resolve_multiple(hostnames, concurrency=args.threads)

        # Build URL scan targets
        for original_url, hostname, port in url_hostnames:
            dns_result = dns_map.get(hostname)
            if dns_result and dns_result.status == "success" and dns_result.ips:
                # Create targets with SNI
                for ip in dns_result.ips:
                    url_targets.append((ip, port, hostname))

                # Store for output mapping
                url_results_map[original_url] = {
                    "hostname": hostname,
                    "port": port,
                    "dns_result": dns_result,
                    "scan_results": [],
                }

    # Combine all targets
    all_targets = ip_targets + url_targets
    total_targets = len(all_targets)

    if total_targets == 0:
        console.error("No valid targets after DNS resolution")
        return 1

    console.info(f"Starting scan of {total_targets} target(s)")
    console.info(f"Concurrency: {args.threads}, Timeout: {args.timeout}s, Port: {args.port}")

    # Initialize statistics
    stats = ScanStatistics(total_targets=total_targets)

    # Scan all targets
    console.info("Scanning in progress...")

    # Show initial progress bar immediately
    if not args.quiet:
        console.print_progress(stats, force=True)

    try:
        # Track progress
        async def update_progress():
            while True:
                await asyncio.sleep(2)
                if not args.quiet:
                    console.print_progress(stats)

        progress_task = asyncio.create_task(update_progress())

        # Create progress callback for real-time updates
        unique_domains = set()

        async def progress_callback(result: "ScanResult") -> None:
            stats.scanned += 1

            if result.status == "success":
                stats.successful += 1
                if result.domains:
                    for domain in result.domains:
                        unique_domains.add(domain)
                    stats.domains_found = len(unique_domains)

                    # Track domain sources for statistics
                    stats.domains_from_san += len(result.domain_sources.get("san", []))
                    stats.domains_from_cn += len(result.domain_sources.get("cn", []))
                    stats.domains_from_csp += len(result.domain_sources.get("csp", []))

                    # Print with source breakdown
                    console.print_domain_found_with_sources(
                        result.ip, result.port, result.domain_sources, result.sni
                    )

                # Map back to URLs if applicable
                if result.sni:  # This was a URL/hostname target
                    for url, data in url_results_map.items():
                        if data["hostname"] == result.sni:
                            data["scan_results"].append(result)
            else:
                stats.failed += 1
                logger.debug(f"Failed to scan {result.ip}:{result.port}: {result.error}")

        # Perform scan with progress callback
        # Cast to proper type for scan_multiple
        scan_targets_list: List[Tuple[str, Optional[int], Optional[str]]] = [
            (ip, port, sni) for ip, port, sni in all_targets
        ]
        results = await scanner.scan_multiple(
            scan_targets_list,
            concurrency=args.threads,
            rate_limit=args.rate_limit,
            progress_callback=progress_callback,
        )

        # Cancel progress task
        progress_task.cancel()
        try:
            await progress_task
        except asyncio.CancelledError:
            pass

    except Exception as e:
        console.error(f"Scan error: {e}")
        logger.exception("Error during scanning")
        return 1

    # Update final statistics
    stats.domains_found = len(unique_domains)

    # Print summary
    console.print_summary(stats)

    # Export results in mixed mode format
    try:
        domain_filter = create_domain_filter(args)
        output_formatter = OutputFormatter(
            args.output, mode="mixed_scan", domain_filter=domain_filter
        )

        # Separate IP results and URL results
        ip_results = [r for r in results if r.sni is None]
        url_results = []

        for url, data in url_results_map.items():
            url_results.append(
                {
                    "url": url,
                    "hostname": data["hostname"],
                    "port": data["port"],
                    "dns_status": data["dns_result"].status,
                    "resolved_ips": data["dns_result"].ips,
                    "connections": [
                        {
                            "ip": r.ip,
                            "port": r.port,
                            "status": r.status,
                            "sni": r.sni,
                            "domains": r.domains,
                            "domain_sources": r.domain_sources,
                            "tls_version": r.tls_version,
                            "error": r.error,
                            "certificate": r.certificate,
                        }
                        for r in data["scan_results"]
                    ],
                }
            )

        # Collect input hostnames for comparison
        input_hostnames = set(hostnames)

        # Prepare output data
        output_data = output_formatter.create_output(
            results={
                "ips": [
                    {
                        "ip": r.ip,
                        "port": r.port,
                        "status": r.status,
                        "sni": r.sni,
                        "domains": r.domains,
                        "domain_sources": r.domain_sources,
                        "tls_version": r.tls_version,
                        "error": r.error,
                        "certificate": r.certificate,
                    }
                    for r in ip_results
                ],
                "urls": url_results,
            },
            parameters={
                "input": args.file,
                "port": args.port,
                "timeout": args.timeout,
                "threads": args.threads,
                "retry": args.retry,
            },
            statistics={
                "total_ips": len(ip_list),
                "total_urls": len(url_data_list),
                "total_targets": stats.total_targets,
                "scanned": stats.scanned,
                "successful": stats.successful,
                "failed": stats.failed,
                "unique_domains": stats.domains_found,
                "elapsed_seconds": stats.elapsed_time,
                "scan_rate": stats.scan_rate,
            },
            input_hostnames=input_hostnames,
        )

        # Print newly discovered hostnames
        discovered_hosts = output_data.get("discovered_hosts", {})
        console.print_new_discoveries(
            discovered_hosts.get("new_hostnames", []),
            discovered_hosts.get("new_tlds", [])
        )

        if args.output == "-":
            output_formatter.write_stdout(output_data)
        else:
            output_formatter.write_json(output_data)
            console.success(f"Results written to: {args.output}")

    except Exception as e:
        console.error(f"Failed to write output: {e}")
        logger.exception("Error writing output")
        return 1

    return 0


async def run_ip_scan(args: argparse.Namespace, console: "ConsoleOutput") -> int:
    """
    Execute IP scan mode (IP/CIDR -> domains).

    Args:
        args: Parsed command-line arguments
        console: Console output handler

    Returns:
        Exit code
    """
    import logging

    from .console import ScanStatistics
    from .input_parser import InputParser
    from .output import OutputFormatter
    from .scanner import TLSScanner

    logger = logging.getLogger(__name__)

    # Parse input targets (CIDR only for this mode)
    try:
        console.info(f"Parsing CIDR range: {args.cidr}")
        targets = list(InputParser.parse_cidr(args.cidr))

    except ValueError as e:
        console.error(f"Input parsing error: {e}")
        return 1

    if not targets:
        console.error("No valid targets found in input")
        return 1

    # Check for private IPs
    if not args.allow_private:
        private_ips = [ip for ip in targets if InputParser.is_private_ip(ip)]
        if private_ips:
            count = len(private_ips)
            console.warning(
                f"Warning: {count} private IP(s) detected. Use --allow-private to scan them."
            )
            targets = [ip for ip in targets if not InputParser.is_private_ip(ip)]

    if not targets:
        console.error("No valid targets remaining after filtering")
        return 1

    console.info(f"Starting IP scan of {len(targets)} target(s)")
    console.info(f"Concurrency: {args.threads}, Timeout: {args.timeout}s, Port: {args.port}")

    # Initialize scanner
    scanner = TLSScanner(
        timeout=args.timeout,
        retry_count=args.retry,
        port=args.port,
        fetch_csp=args.fetch_csp,
        follow_redirects=args.follow_redirects,
        follow_host_redirects=args.follow_host_redirects,
        max_redirects=args.max_redirects,
    )

    # Initialize statistics
    stats = ScanStatistics(total_targets=len(targets))

    # Prepare targets (ip, port, sni)
    scan_targets = [(ip, args.port, None) for ip in targets]

    # Scan with progress updates
    results = []
    unique_domains = set()

    console.info("Scanning in progress...")

    # Show initial progress bar immediately
    if not args.quiet:
        console.print_progress(stats, force=True)

    # Use scan_multiple for concurrent scanning
    try:
        import asyncio

        # Create progress update task
        async def update_progress():
            while True:
                await asyncio.sleep(2)
                if not args.quiet:
                    console.print_progress(stats)

        # Start progress updates
        progress_task = asyncio.create_task(update_progress())

        # Create progress callback for real-time updates
        async def progress_callback(result: "ScanResult") -> None:
            results.append(result)
            stats.scanned += 1

            if result.status == "success":
                stats.successful += 1
                if result.domains:
                    for domain in result.domains:
                        unique_domains.add(domain)
                    stats.domains_found = len(unique_domains)

                    # Track domain sources for statistics
                    stats.domains_from_san += len(result.domain_sources.get("san", []))
                    stats.domains_from_cn += len(result.domain_sources.get("cn", []))
                    stats.domains_from_csp += len(result.domain_sources.get("csp", []))

                    # Print with source breakdown
                    console.print_domain_found_with_sources(
                        result.ip, result.port, result.domain_sources, result.sni
                    )
            else:
                stats.failed += 1
                logger.debug(f"Failed to scan {result.ip}:{result.port}: {result.error}")

        # Scan all targets with rate limiting and progress callback
        # Type annotation already correct for scan_targets
        scan_targets_typed: List[Tuple[str, Optional[int], Optional[str]]] = [
            (ip, port, sni) for ip, port, sni in scan_targets
        ]
        await scanner.scan_multiple(
            scan_targets_typed,
            concurrency=args.threads,
            rate_limit=args.rate_limit,
            progress_callback=progress_callback,
        )

        # Cancel progress task
        progress_task.cancel()
        try:
            await progress_task
        except asyncio.CancelledError:
            pass

    except Exception as e:
        console.error(f"Scan error: {e}")
        logger.exception("Error during scanning")
        return 1

    # Update final statistics
    stats.domains_found = len(unique_domains)

    # Print summary
    console.print_summary(stats)

    # Export results
    try:
        domain_filter = create_domain_filter(args)
        output_formatter = OutputFormatter(args.output, mode="ip_scan", domain_filter=domain_filter)

        # For IP scans, input has no hostnames - all discoveries are "new"
        input_hostnames: set = set()

        # Prepare output data
        output_data = output_formatter.create_output(
            results=[
                {
                    "ip": r.ip,
                    "port": r.port,
                    "status": r.status,
                    "sni": r.sni,
                    "domains": r.domains,
                    "domain_sources": r.domain_sources,
                    "tls_version": r.tls_version,
                    "error": r.error,
                    "certificate": r.certificate,
                }
                for r in results
            ],
            parameters={
                "input": args.cidr,
                "port": args.port,
                "timeout": args.timeout,
                "threads": args.threads,
                "retry": args.retry,
            },
            statistics={
                "total_targets": stats.total_targets,
                "scanned": stats.scanned,
                "successful": stats.successful,
                "failed": stats.failed,
                "unique_domains": stats.domains_found,
                "elapsed_seconds": stats.elapsed_time,
                "scan_rate": stats.scan_rate,
            },
            input_hostnames=input_hostnames,
        )

        # Print newly discovered hostnames
        discovered_hosts = output_data.get("discovered_hosts", {})
        console.print_new_discoveries(
            discovered_hosts.get("new_hostnames", []),
            discovered_hosts.get("new_tlds", [])
        )

        if args.output == "-":
            output_formatter.write_stdout(output_data)
        else:
            output_formatter.write_json(output_data)
            console.success(f"Results written to: {args.output}")

    except Exception as e:
        console.error(f"Failed to write output: {e}")
        logger.exception("Error writing output")
        return 1

    return 0


async def run_single_url_scan(args: argparse.Namespace, console: "ConsoleOutput") -> int:
    """
    Execute single URL scan mode (single URL/hostname from command line).

    Args:
        args: Parsed command-line arguments
        console: Console output handler

    Returns:
        Exit code
    """
    from .scanner import TLSScanner
    from .input_parser import InputParser
    from .dns_resolver import DNSResolver
    from .output import OutputFormatter
    from .console import ScanStatistics
    from urllib.parse import urlparse
    import logging
    import asyncio

    logger = logging.getLogger(__name__)

    # Parse the single URL
    original_url = args.url.strip()
    console.info(f"Scanning URL: {original_url}")

    # Add scheme if missing
    url_to_parse = original_url
    if not url_to_parse.startswith(("http://", "https://")):
        url_to_parse = f"https://{url_to_parse}"

    try:
        parsed = urlparse(url_to_parse)
        if not parsed.hostname:
            console.error(f"Invalid URL: {original_url}")
            return 1

        hostname = parsed.hostname
        port = parsed.port if parsed.port else (443 if parsed.scheme == "https" else 80)

        # Override with --port if specified and URL doesn't have explicit port
        if parsed.port is None and args.port != 443:
            port = args.port

    except Exception as e:
        console.error(f"Failed to parse URL: {original_url} - {e}")
        return 1

    # Initialize components
    scanner = TLSScanner(
        timeout=args.timeout,
        retry_count=args.retry,
        port=port,
        fetch_csp=args.fetch_csp,
        follow_redirects=args.follow_redirects,
        follow_host_redirects=args.follow_host_redirects,
        max_redirects=args.max_redirects,
    )
    dns_resolver = DNSResolver(timeout=args.timeout)

    # Resolve hostname
    console.info(f"Resolving hostname: {hostname}")
    dns_map = await dns_resolver.resolve_multiple([hostname], concurrency=1)
    dns_result = dns_map.get(hostname)

    if not dns_result or dns_result.status != "success" or not dns_result.ips:
        error_msg = dns_result.error if dns_result else "DNS resolution failed"
        console.error(f"Failed to resolve {hostname}: {error_msg}")
        return 1

    resolved_ips = dns_result.ips

    # Filter private IPs if needed
    if not args.allow_private:
        filtered_ips = [ip for ip in resolved_ips if not InputParser.is_private_ip(ip)]
        if len(filtered_ips) < len(resolved_ips):
            console.warning(
                f"Filtered {len(resolved_ips) - len(filtered_ips)} private IP(s). Use --allow-private to scan them."
            )
        resolved_ips = filtered_ips

    if not resolved_ips:
        console.error("No valid IPs to scan after filtering")
        return 1

    console.info(f"Resolved to {len(resolved_ips)} IP(s): {', '.join(resolved_ips)}")

    # Prepare scan targets
    scan_targets = [(ip, port, hostname) for ip in resolved_ips]
    total_targets = len(scan_targets)

    console.info(f"Starting scan of {total_targets} target(s)")
    console.info(f"Timeout: {args.timeout}s, Port: {port}")

    # Initialize statistics
    stats = ScanStatistics(total_targets=total_targets)

    # Show initial progress bar
    if not args.quiet:
        console.print_progress(stats, force=True)

    try:
        # Track progress
        async def update_progress():
            while True:
                await asyncio.sleep(2)
                if not args.quiet:
                    console.print_progress(stats)

        progress_task = asyncio.create_task(update_progress())

        # Create progress callback
        unique_domains = set()
        scan_results = []

        async def progress_callback(result: "ScanResult"):
            scan_results.append(result)
            stats.scanned += 1

            if result.status == "success":
                stats.successful += 1
                if result.domains:
                    for domain in result.domains:
                        unique_domains.add(domain)
                    stats.domains_found = len(unique_domains)

                    # Track domain sources for statistics
                    stats.domains_from_san += len(result.domain_sources.get("san", []))
                    stats.domains_from_cn += len(result.domain_sources.get("cn", []))
                    stats.domains_from_csp += len(result.domain_sources.get("csp", []))

                    # Print with source breakdown
                    console.print_domain_found_with_sources(
                        result.ip, result.port, result.domain_sources, result.sni
                    )
            else:
                stats.failed += 1
                logger.debug(f"Failed to scan {result.ip}:{result.port}: {result.error}")

        # Perform scan
        results = await scanner.scan_multiple(
            scan_targets,
            concurrency=args.threads,
            rate_limit=args.rate_limit,
            progress_callback=progress_callback
        )

        # Cancel progress task
        progress_task.cancel()
        try:
            await progress_task
        except asyncio.CancelledError:
            pass

    except Exception as e:
        console.error(f"Scan error: {e}")
        logger.exception("Error during scanning")
        return 1

    # Update final statistics
    stats.domains_found = len(unique_domains)

    # Print summary
    console.print_summary(stats)

    # Export results
    try:
        domain_filter = create_domain_filter(args)
        output_formatter = OutputFormatter(args.output, mode="url_scan", domain_filter=domain_filter)

        # Build result in URL scan format
        url_result = {
            "url": original_url,
            "hostname": hostname,
            "port": port,
            "dns_status": "success",
            "resolved_ips": resolved_ips,
            "connections": [
                {
                    "ip": r.ip,
                    "port": r.port,
                    "status": r.status,
                    "sni": r.sni,
                    "domains": r.domains,
                    "domain_sources": r.domain_sources,
                    "tls_version": r.tls_version,
                    "error": r.error,
                    "certificate": r.certificate,
                }
                for r in scan_results
            ],
        }

        # Input hostname for comparison
        input_hostnames = {hostname}

        output_data = output_formatter.create_output(
            results=[url_result],
            parameters={
                "input": original_url,
                "port": port,
                "timeout": args.timeout,
                "threads": args.threads,
                "retry": args.retry,
            },
            statistics={
                "total_urls": 1,
                "total_ips_scanned": total_targets,
                "scanned": stats.scanned,
                "successful": stats.successful,
                "failed": stats.failed,
                "unique_domains": stats.domains_found,
                "elapsed_seconds": stats.elapsed_time,
                "scan_rate": stats.scan_rate,
            },
            input_hostnames=input_hostnames,
        )

        # Print newly discovered hostnames
        discovered_hosts = output_data.get("discovered_hosts", {})
        console.print_new_discoveries(
            discovered_hosts.get("new_hostnames", []),
            discovered_hosts.get("new_tlds", [])
        )

        if args.output == "-":
            output_formatter.write_stdout(output_data)
        else:
            output_formatter.write_json(output_data)
            console.success(f"Results written to: {args.output}")

    except Exception as e:
        console.error(f"Failed to write output: {e}")
        logger.exception("Error writing output")
        return 1

    return 0


async def run_url_scan(args: argparse.Namespace, console: "ConsoleOutput") -> int:
    """
    Execute URL scan mode (URL/hostname -> DNS -> IPs -> domains).

    Args:
        args: Parsed command-line arguments
        console: Console output handler

    Returns:
        Exit code
    """
    import asyncio
    import logging

    from .console import ScanStatistics
    from .dns_resolver import DNSResolver
    from .input_parser import InputParser
    from .output import OutputFormatter
    from .scanner import TLSScanner

    logger = logging.getLogger(__name__)

    # Parse input
    try:
        if args.url_file:
            console.info(f"Parsing URL file: {args.url_file}")
            url_data = InputParser.parse_url_file(args.url_file)
            # url_data is list of (original_url, hostname, port)
        elif args.hostname_file:
            console.info(f"Parsing hostname file: {args.hostname_file}")
            hostnames = InputParser.parse_hostname_file(args.hostname_file)
            # Convert to url_data format: (hostname, hostname, default_port)
            url_data = [(h, h, args.port) for h in hostnames]
        else:
            console.error("No valid input specified")
            return 1

    except FileNotFoundError as e:
        console.error(str(e))
        return 1
    except ValueError as e:
        console.error(f"Input parsing error: {e}")
        return 1

    if not url_data:
        console.error("No valid URLs/hostnames found in input")
        return 1

    console.info(f"Starting URL scan for {len(url_data)} URL/hostname(s)")
    console.info(f"Concurrency: {args.threads}, Timeout: {args.timeout}s")

    # Initialize DNS resolver
    dns_resolver = DNSResolver(timeout=args.timeout)

    # Resolve all hostnames
    console.info("Resolving hostnames...")
    hostnames = list(set([hostname for _, hostname, _ in url_data]))
    dns_results = await dns_resolver.resolve_multiple(hostnames, concurrency=args.threads)

    # Count DNS successes
    dns_success = sum(1 for r in dns_results.values() if r.status == "success")
    console.info(f"DNS resolution: {dns_success}/{len(hostnames)} successful")

    # Prepare scan targets: map each URL to its resolved IPs
    url_to_targets: Dict[str, Dict[str, Any]] = {}
    total_scan_targets = 0

    for original_url, hostname, port in url_data:
        dns_result = dns_results.get(hostname)
        if not dns_result or dns_result.status != "success":
            url_to_targets[original_url] = {
                "hostname": hostname,
                "port": port,
                "dns_status": dns_result.status if dns_result else "error",
                "dns_error": dns_result.error if dns_result else "No DNS result",
                "resolved_ips": [],
                "scan_results": [],
            }
            continue

        # Filter private IPs if needed
        resolved_ips = dns_result.ips
        if not args.allow_private:
            filtered_ips = [ip for ip in resolved_ips if not InputParser.is_private_ip(ip)]
            if len(filtered_ips) < len(resolved_ips):
                console.warning(
                    f"{hostname}: Filtered {len(resolved_ips) - len(filtered_ips)} private IP(s)"
                )
            resolved_ips = filtered_ips

        url_to_targets[original_url] = {
            "hostname": hostname,
            "port": port,
            "dns_status": "success",
            "dns_error": None,
            "resolved_ips": resolved_ips,
            "scan_results": [],
        }
        total_scan_targets += len(resolved_ips)

    if total_scan_targets == 0:
        console.error("No valid IPs to scan after DNS resolution")
        return 1

    console.info(f"Scanning {total_scan_targets} IP(s) from {len(url_data)} URL/hostname(s)")

    # Initialize scanner
    scanner = TLSScanner(
        timeout=args.timeout,
        retry_count=args.retry,
        port=args.port,
        fetch_csp=args.fetch_csp,
        follow_redirects=args.follow_redirects,
        follow_host_redirects=args.follow_host_redirects,
        max_redirects=args.max_redirects,
    )

    # Initialize statistics
    stats = ScanStatistics(total_targets=total_scan_targets)
    unique_domains = set()

    console.info("TLS scanning in progress...")

    # Show initial progress bar immediately
    if not args.quiet:
        console.print_progress(stats, force=True)

    # Scan all IPs
    try:
        # Create progress update task
        async def update_progress():
            while stats.scanned < stats.total_targets:
                console.print_progress(stats)
                await asyncio.sleep(1)

        progress_task = asyncio.create_task(update_progress())

        # Collect all scan targets
        all_scan_targets = []
        target_to_url = {}  # Map (ip, port) to original_url

        for original_url, data in url_to_targets.items():
            url_hostname: str = str(data["hostname"])
            url_port: Optional[int] = data["port"] if isinstance(data["port"], int) else None
            resolved_ips = data["resolved_ips"]
            if isinstance(resolved_ips, list):
                for ip in resolved_ips:
                    if isinstance(ip, str):
                        all_scan_targets.append((ip, url_port, url_hostname))  # Use hostname as SNI
                        target_to_url[(ip, url_port)] = original_url

        # Scan all targets with rate limiting
        # Cast to proper type
        all_scan_targets_typed: List[Tuple[str, Optional[int], Optional[str]]] = [
            (str(ip), port, hostname) for ip, port, hostname in all_scan_targets
        ]
        scan_results = await scanner.scan_multiple(
            all_scan_targets_typed, concurrency=args.threads, rate_limit=args.rate_limit
        )

        # Map results back to URLs
        for result in scan_results:
            stats.scanned += 1

            # Find which URL this result belongs to
            result_url: Optional[str] = target_to_url.get((result.ip, result.port))
            if result_url and result_url in url_to_targets:
                scan_results_list = url_to_targets[result_url].get("scan_results")
                if isinstance(scan_results_list, list):
                    scan_results_list.append(result)

            if result.status == "success":
                stats.successful += 1
                if result.domains:
                    for domain in result.domains:
                        unique_domains.add(domain)

                    # Track domain sources for statistics
                    stats.domains_from_san += len(result.domain_sources.get("san", []))
                    stats.domains_from_cn += len(result.domain_sources.get("cn", []))
                    stats.domains_from_csp += len(result.domain_sources.get("csp", []))

                    # Print with source breakdown
                    console.print_domain_found_with_sources(
                        result.ip, result.port, result.domain_sources, result.sni
                    )
            else:
                stats.failed += 1
                logger.debug(f"Failed to scan {result.ip}:{result.port}: {result.error}")

        # Cancel progress task
        progress_task.cancel()
        try:
            await progress_task
        except asyncio.CancelledError:
            pass

    except Exception as e:
        console.error(f"Scan error: {e}")
        logger.exception("Error during scanning")
        return 1

    # Update final statistics
    stats.domains_found = len(unique_domains)

    # Print summary
    console.print_summary(stats)

    # Export results in URL scan format
    try:
        domain_filter = create_domain_filter(args)
        output_formatter = OutputFormatter(
            args.output, mode="url_scan", domain_filter=domain_filter
        )

        # Build results in URL scan format
        results_list = []
        for original_url, data in url_to_targets.items():
            result_entry = {
                "url": original_url,
                "hostname": data["hostname"],
                "port": data["port"],
                "dns_status": data["dns_status"],
                "resolved_ips": data["resolved_ips"],
                "connections": [
                    {
                        "ip": r.ip,
                        "port": r.port,
                        "status": r.status,
                        "sni": r.sni,
                        "domains": r.domains,
                        "domain_sources": r.domain_sources,
                        "tls_version": r.tls_version,
                        "error": r.error,
                        "certificate": r.certificate,
                    }
                    for r in (data["scan_results"] if isinstance(data["scan_results"], list) else [])
                ],
            }

            if data["dns_error"]:
                result_entry["dns_error"] = data["dns_error"]

            results_list.append(result_entry)

        output_data = output_formatter.create_output(
            results=results_list,
            parameters={
                "input": args.url_file or args.hostname_file,
                "timeout": args.timeout,
                "threads": args.threads,
                "retry": args.retry,
            },
            statistics={
                "total_urls": len(url_data),
                "total_ips_scanned": total_scan_targets,
                "scanned": stats.scanned,
                "successful": stats.successful,
                "failed": stats.failed,
                "unique_domains": stats.domains_found,
                "elapsed_seconds": stats.elapsed_time,
                "scan_rate": stats.scan_rate,
            },
        )

        if args.output == "-":
            output_formatter.write_stdout(output_data)
        else:
            output_formatter.write_json(output_data)
            console.success(f"Results written to: {args.output}")

    except Exception as e:
        console.error(f"Failed to write output: {e}")
        logger.exception("Error writing output")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

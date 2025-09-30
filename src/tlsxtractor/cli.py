"""
Command-line interface for TLSXtractor.
"""

import argparse
import sys
from typing import Optional

from . import __version__


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog="tlsxtractor",
        description="Extract domain names and certificate information from TLS handshakes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a CIDR range
  tlsxtractor --cidr 192.168.1.0/24 --output results.json

  # Scan from file (auto-detects IP, URL, or hostname)
  tlsxtractor --file targets.txt --output results.json

  # Scan with custom threads and rate limiting
  tlsxtractor -f targets.txt --threads 20 --rate-limit 5 -o results.json
        """,
    )

    # Version
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    # Input options (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--cidr", metavar="CIDR", help="Scan IP range in CIDR notation")
    input_group.add_argument("--file", "-f", metavar="FILE", help="Input file (supports mixed IPs, URLs, and hostnames)")

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
    from .scanner import TLSScanner
    from .input_parser import InputParser
    from .dns_resolver import DNSResolver
    from .output import OutputFormatter
    from .console import ScanStatistics
    import logging
    import asyncio

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
    url_results_map = {}

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

        async def progress_callback(result: "ScanResult"):
            stats.scanned += 1

            if result.status == "success":
                stats.successful += 1
                if result.domains:
                    for domain in result.domains:
                        unique_domains.add(domain)
                    stats.domains_found = len(unique_domains)
                    console.print_domain_found(result.ip, result.port, result.domains)

                # Map back to URLs if applicable
                if result.sni:  # This was a URL/hostname target
                    for url, data in url_results_map.items():
                        if data["hostname"] == result.sni:
                            data["scan_results"].append(result)
            else:
                stats.failed += 1
                logger.debug(f"Failed to scan {result.ip}:{result.port}: {result.error}")

        # Perform scan with progress callback
        results = await scanner.scan_multiple(
            all_targets,
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

    # Export results in mixed mode format
    try:
        output_formatter = OutputFormatter(args.output, mode="mixed_scan")

        # Separate IP results and URL results
        ip_results = [r for r in results if r.sni is None]
        url_results = []

        for url, data in url_results_map.items():
            url_results.append({
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
                        "tls_version": r.tls_version,
                        "error": r.error,
                        "certificate": r.certificate,
                    }
                    for r in data["scan_results"]
                ],
            })

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
    from .scanner import TLSScanner
    from .input_parser import InputParser
    from .output import OutputFormatter
    from .console import ScanStatistics
    import logging

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
    )

    # Initialize statistics
    stats = ScanStatistics(total_targets=len(targets))

    # Prepare targets (ip, port, sni)
    scan_targets = [(ip, args.port, None) for ip in targets]

    # Scan with progress updates
    results = []
    unique_domains = set()

    console.info("Scanning in progress...")

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
        async def progress_callback(result: "ScanResult"):
            results.append(result)
            stats.scanned += 1

            if result.status == "success":
                stats.successful += 1
                if result.domains:
                    for domain in result.domains:
                        unique_domains.add(domain)
                    stats.domains_found = len(unique_domains)
                    console.print_domain_found(result.ip, result.port, result.domains)
            else:
                stats.failed += 1
                logger.debug(f"Failed to scan {result.ip}:{result.port}: {result.error}")

        # Scan all targets with rate limiting and progress callback
        scan_results = await scanner.scan_multiple(
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
        output_formatter = OutputFormatter(args.output, mode="ip_scan")

        # Prepare output data
        output_data = output_formatter.create_output(
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
    from .scanner import TLSScanner
    from .input_parser import InputParser
    from .dns_resolver import DNSResolver
    from .output import OutputFormatter
    from .console import ScanStatistics
    import logging
    import asyncio

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
    url_to_targets = {}
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
    )

    # Initialize statistics
    stats = ScanStatistics(total_targets=total_scan_targets)
    unique_domains = set()

    console.info("TLS scanning in progress...")

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
            hostname = data["hostname"]
            port = data["port"]
            for ip in data["resolved_ips"]:
                all_scan_targets.append((ip, port, hostname))  # Use hostname as SNI
                target_to_url[(ip, port)] = original_url

        # Scan all targets with rate limiting
        scan_results = await scanner.scan_multiple(
            all_scan_targets, concurrency=args.threads, rate_limit=args.rate_limit
        )

        # Map results back to URLs
        for result in scan_results:
            stats.scanned += 1

            # Find which URL this result belongs to
            original_url = target_to_url.get((result.ip, result.port))
            if original_url:
                url_to_targets[original_url]["scan_results"].append(result)

            if result.status == "success":
                stats.successful += 1
                if result.domains:
                    for domain in result.domains:
                        unique_domains.add(domain)
                    console.print_domain_found(result.ip, result.port, result.domains)
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
        output_formatter = OutputFormatter(args.output, mode="url_scan")

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
                        "tls_version": r.tls_version,
                        "error": r.error,
                        "certificate": r.certificate,
                    }
                    for r in data["scan_results"]
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
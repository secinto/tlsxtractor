"""
TLS connection and scanning functionality.
"""

import asyncio
import logging
import ssl
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, Awaitable, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# Constants
BACKOFF_BASE = 2  # Base for exponential backoff calculation
DEFAULT_TIMEOUT = 5  # Default connection timeout in seconds
DEFAULT_RETRY_COUNT = 3  # Default number of retry attempts
DEFAULT_PORT = 443  # Default HTTPS port
SSL_SHUTDOWN_TIMEOUT = 2  # Timeout for SSL shutdown (some servers hang)


@dataclass
class ScanResult:
    """Result from scanning a single target."""

    ip: str
    port: int
    status: str
    sni: Optional[str] = None
    certificate: Optional[Dict[str, Any]] = None
    # Aggregate list for backward compatibility
    domains: List[str] = field(default_factory=list)
    domain_sources: Dict[str, List[str]] = field(
        default_factory=lambda: {
            "sni": [], "san": [], "cn": [], "csp": []
        }
    )
    error: Optional[str] = None
    tls_version: Optional[str] = None

    # Enhanced failure diagnostics
    error_code: Optional[str] = None  # e.g., "CONN_TIMEOUT", "TLS_HANDSHAKE_FAILED"
    error_category: Optional[str] = None  # e.g., "timeout", "tls", "network"
    error_details: Optional[Dict[str, Any]] = None  # SSL lib, errno, etc.
    retry_count: int = 0  # Number of retry attempts made
    successful_attempt: Optional[int] = None  # Which attempt succeeded (1-indexed)


class TLSScanner:
    """
    Handles TLS connections and domain extraction.

    Implements Tasks IMPL-003 and IMPL-004:
    - Basic TLS connection establishment
    - SNI capture and extraction
    """

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        retry_count: int = DEFAULT_RETRY_COUNT,
        port: int = DEFAULT_PORT,
        fetch_csp: bool = False,
        follow_redirects: bool = False,
        follow_host_redirects: bool = False,
        max_redirects: int = 10,
    ):
        """
        Initialize TLS scanner.

        Args:
            timeout: Connection timeout in seconds
            retry_count: Maximum number of retry attempts
            port: Default target port
            fetch_csp: Whether to fetch and parse CSP headers
            follow_redirects: Follow all HTTP redirects when fetching CSP
            follow_host_redirects: Follow redirects only to same host
            max_redirects: Maximum number of redirects to follow
        """
        self.timeout = timeout
        self.retry_count = retry_count
        self.port = port
        self.fetch_csp = fetch_csp
        self._ssl_context = self._create_ssl_context()

        # Initialize CSP extractor if enabled
        self._csp_extractor = None
        if self.fetch_csp:
            from .csp_extractor import CSPExtractor

            self._csp_extractor = CSPExtractor(
                timeout=timeout,
                follow_redirects=follow_redirects,
                follow_host_redirects=follow_host_redirects,
                max_redirects=max_redirects,
            )

    def _create_ssl_context(self) -> ssl.SSLContext:
        """
        Create SSL context for scanning.

        Returns:
            Configured SSL context
        """
        context = ssl.create_default_context()
        # Disable certificate verification for scanning purposes
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        # Allow all TLS/SSL versions for maximum compatibility when scanning
        # This enables connecting to legacy servers with TLS 1.0/1.1
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        context.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
        return context

    @staticmethod
    async def _safe_close_writer(writer: asyncio.StreamWriter) -> None:
        """
        Safely close a StreamWriter with timeout for SSL shutdown.

        Some servers (e.g., stripe.com) hang during SSL shutdown,
        so we use a timeout to avoid blocking indefinitely.

        Args:
            writer: The StreamWriter to close
        """
        writer.close()
        try:
            await asyncio.wait_for(
                writer.wait_closed(),
                timeout=SSL_SHUTDOWN_TIMEOUT
            )
        except asyncio.TimeoutError:
            # SSL shutdown timed out, but connection is closed
            logger.debug("SSL shutdown timed out, continuing")
        except Exception:
            # Ignore other errors during cleanup
            pass

    async def scan_target(
        self,
        ip: str,
        port: Optional[int] = None,
        sni: Optional[str] = None,
    ) -> ScanResult:
        """
        Scan a single target IP address.

        Args:
            ip: Target IP address
            port: Target port (uses default if not specified)
            sni: Server Name Indication to send

        Returns:
            ScanResult containing discovered information
        """
        from .errors import (
            ErrorCategory,
            ErrorCode,
            TLSScanError,
            classify_os_error,
        )

        target_port = port or self.port

        # Attempt connection with retries
        for attempt in range(self.retry_count + 1):
            try:
                result = await self._connect_and_scan(ip, target_port, sni)
                # Record successful attempt info
                result.retry_count = attempt
                result.successful_attempt = attempt + 1
                return result
            except asyncio.TimeoutError:
                logger.debug(
                    f"Timeout connecting to {ip}:{target_port} "
                    f"(attempt {attempt + 1})"
                )
                if attempt == self.retry_count:
                    return ScanResult(
                        ip=ip,
                        port=target_port,
                        status="timeout",
                        error="Connection timeout",
                        error_code=ErrorCode.CONN_TIMEOUT.value,
                        error_category=ErrorCategory.TIMEOUT.value,
                        error_details={"attempts": attempt + 1},
                        retry_count=attempt,
                    )
            except ConnectionRefusedError:
                logger.debug(f"Connection refused by {ip}:{target_port}")
                return ScanResult(
                    ip=ip,
                    port=target_port,
                    status="refused",
                    error="Connection refused",
                    error_code=ErrorCode.CONN_REFUSED.value,
                    error_category=ErrorCategory.REFUSED.value,
                    error_details={"attempt": attempt + 1},
                    retry_count=attempt,
                )
            except TLSScanError as e:
                # Custom TLS error with classification
                logger.debug(
                    f"TLS error connecting to {ip}:{target_port}: {e}"
                )
                if attempt == self.retry_count:
                    return ScanResult(
                        ip=ip,
                        port=target_port,
                        status="tls_error",
                        error=str(e),
                        error_code=e.error_code.value,
                        error_category=e.error_category.value,
                        error_details=e.error_details,
                        retry_count=attempt,
                    )
            except OSError as e:
                logger.debug(
                    f"Network error connecting to {ip}:{target_port}: {e}"
                )
                if attempt == self.retry_count:
                    error_code, error_category, error_details = classify_os_error(e)
                    return ScanResult(
                        ip=ip,
                        port=target_port,
                        status="error",
                        error=f"Network error: {str(e)}",
                        error_code=error_code.value,
                        error_category=error_category.value,
                        error_details=error_details,
                        retry_count=attempt,
                    )
            except Exception as e:
                logger.debug(
                    f"Unexpected error scanning {ip}:{target_port}: {e}"
                )
                return ScanResult(
                    ip=ip,
                    port=target_port,
                    status="error",
                    error=f"Error: {str(e)}",
                    error_code=ErrorCode.UNKNOWN_ERROR.value,
                    error_category=ErrorCategory.UNKNOWN.value,
                    error_details={
                        "exception_type": type(e).__name__,
                        "raw_message": str(e),
                    },
                    retry_count=attempt,
                )

            # Exponential backoff between retries
            if attempt < self.retry_count:
                await asyncio.sleep(BACKOFF_BASE**attempt)

        # Should not reach here, but return error if it does
        return ScanResult(
            ip=ip,
            port=target_port,
            status="error",
            error="Max retries exceeded",
            error_code=ErrorCode.MAX_RETRIES.value,
            error_category=ErrorCategory.UNKNOWN.value,
            error_details={"max_retries": self.retry_count},
            retry_count=self.retry_count,
        )

    async def _connect_and_scan(
        self,
        ip: str,
        port: int,
        sni: Optional[str] = None,
    ) -> ScanResult:
        """
        Connect to target and perform TLS handshake.

        Args:
            ip: Target IP address
            port: Target port
            sni: Server Name Indication to send

        Returns:
            ScanResult with certificate information
        """
        from .errors import TLSScanError, classify_ssl_error

        # If SNI is provided, use it; otherwise None (no SNI)
        server_hostname = sni if sni else None

        # Open TLS connection directly using asyncio
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    ip,
                    port,
                    ssl=self._ssl_context,
                    server_hostname=server_hostname,
                ),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            raise
        except ConnectionRefusedError:
            raise
        except ssl.SSLError as e:
            logger.debug(f"SSL error connecting to {ip}:{port}: {e}")
            error_code, error_category, error_details = classify_ssl_error(e)
            raise TLSScanError(
                message=str(e),
                error_code=error_code,
                error_category=error_category,
                error_details=error_details,
            )
        except OSError as e:
            # Re-raise OSError directly to preserve errno
            raise
        except Exception as e:
            # Wrap other exceptions preserving as much info as possible
            raise OSError(f"Failed to connect: {e}") from e

        try:
            # Get SSL object from transport
            ssl_object = writer.get_extra_info("ssl_object")

            if ssl_object is None:
                await self._safe_close_writer(writer)
                raise OSError("Failed to establish TLS connection")

            # Extract certificate in DER format
            cert_der = ssl_object.getpeercert(binary_form=True)
            tls_version = ssl_object.version()

            # Close connection safely (some servers hang during SSL shutdown)
            await self._safe_close_writer(writer)

            if cert_der is None:
                return ScanResult(
                    ip=ip,
                    port=port,
                    status="no_certificate",
                    sni=sni,
                    error="No certificate received",
                    tls_version=tls_version,
                )

            # Parse certificate to extract domains
            from .certificate import CertificateParser

            cert_info = CertificateParser.parse_certificate(cert_der)

            # Extract domains from different sources
            domain_sources: Dict[str, List[str]] = {"sni": [], "san": [], "cn": [], "csp": []}

            # Extract from SNI (if provided)
            if sni:
                domain_sources["sni"].append(sni)

            # Extract from SAN (Subject Alternative Names)
            san_list = cert_info.get("san", [])
            domain_sources["san"] = san_list.copy()

            # Extract from CN (Common Name)
            subject = cert_info.get("subject", {})
            common_name = subject.get("commonName")
            if common_name:
                domain_sources["cn"].append(common_name)

            # Fetch CSP if enabled
            if self._csp_extractor and sni:
                try:
                    logger.debug(
                        f"Fetching CSP from {ip}:{port} (SNI: {sni})"
                    )
                    csp_result = (
                        await self._csp_extractor
                        .fetch_and_extract_domains(
                            ip=ip, port=port, sni=sni, path="/"
                        )
                    )
                    _, csp_domains = csp_result
                    if csp_domains:
                        domain_sources["csp"] = csp_domains
                        logger.debug(
                            f"Extracted {len(csp_domains)} "
                            f"domains from CSP"
                        )
                except Exception as e:
                    # CSP extraction failure should not break the scan
                    logger.debug(
                        f"CSP extraction failed for {ip}:{port}: {e}"
                    )

            # Build aggregate domains list for backward compatibility
            # Deduplicate across all sources
            all_domains = set()
            for source_domains in [
                domain_sources["sni"],
                domain_sources["san"],
                domain_sources["cn"],
                domain_sources["csp"],
            ]:
                all_domains.update(source_domains)
            domains = list(all_domains)

            return ScanResult(
                ip=ip,
                port=port,
                status="success",
                sni=sni,
                certificate=cert_info,
                domains=domains,
                domain_sources=domain_sources,
                tls_version=tls_version,
            )

        except Exception:
            # Ensure cleanup
            await self._safe_close_writer(writer)
            raise

    async def scan_multiple(
        self,
        targets: List[tuple[str, Optional[int], Optional[str]]],
        concurrency: int = 50,
        rate_limit: Optional[float] = None,
        progress_callback: Optional[Callable[[ScanResult], Awaitable[None]]] = None,
    ) -> List[ScanResult]:
        """
        Scan multiple targets concurrently with optional rate limiting.

        Args:
            targets: List of (ip, port, sni) tuples
            concurrency: Maximum number of concurrent scans (default: 50)
            rate_limit: Optional rate limit in requests per second (None = unlimited)
            progress_callback: Optional callback function called after each scan completes
                             with signature: callback(result: ScanResult)

        Returns:
            List of scan results
        """
        from .rate_limiter import RateLimiter

        semaphore = asyncio.Semaphore(concurrency)
        rate_limiter = RateLimiter(rate_limit) if rate_limit else None

        async def scan_with_semaphore(target):
            async with semaphore:
                # Apply rate limiting before scanning
                if rate_limiter:
                    await rate_limiter.acquire()

                target_ip, target_port, target_sni = target
                result = await self.scan_target(
                    target_ip, target_port, target_sni
                )

                # Call progress callback if provided
                if progress_callback:
                    try:
                        await progress_callback(result)
                    except Exception as e:
                        logger.warning(f"Progress callback error: {e}")

                return result

        tasks = [scan_with_semaphore(target) for target in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Convert exceptions to error results
        processed_results: List[ScanResult] = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                ip, port, _ = targets[i]
                processed_results.append(
                    ScanResult(
                        ip=ip,
                        port=port or self.port,
                        status="error",
                        error=f"Scan failed: {str(result)}",
                    )
                )
            elif isinstance(result, ScanResult):
                processed_results.append(result)

        return processed_results

    async def scan_streaming(
        self,
        target_generator: "AsyncGenerator[tuple[str, Optional[int], Optional[str]], None]",
        concurrency: int = 50,
        rate_limit: Optional[float] = None,
        progress_callback: Optional[Callable[[ScanResult], Awaitable[None]]] = None,
    ) -> List[ScanResult]:
        """
        Scan targets from an async generator, enabling pipeline parallelism.

        This method allows DNS resolution and scanning to happen concurrently
        by accepting targets as they become available from an async generator.

        Args:
            target_generator: Async generator yielding (ip, port, sni) tuples
            concurrency: Maximum number of concurrent scans (default: 50)
            rate_limit: Optional rate limit in requests per second (None = unlimited)
            progress_callback: Optional callback called after each scan completes

        Returns:
            List of scan results
        """
        from .rate_limiter import RateLimiter

        semaphore = asyncio.Semaphore(concurrency)
        rate_limiter = RateLimiter(rate_limit) if rate_limit else None
        results: List[ScanResult] = []
        pending_tasks: set = set()

        async def scan_with_semaphore(target: tuple[str, Optional[int], Optional[str]]) -> ScanResult:
            async with semaphore:
                if rate_limiter:
                    await rate_limiter.acquire()

                target_ip, target_port, target_sni = target
                result = await self.scan_target(target_ip, target_port, target_sni)

                if progress_callback:
                    try:
                        await progress_callback(result)
                    except Exception as e:
                        logger.warning(f"Progress callback error: {e}")

                return result

        # Process targets as they arrive from the generator
        async for target in target_generator:
            task = asyncio.create_task(scan_with_semaphore(target))
            pending_tasks.add(task)
            task.add_done_callback(pending_tasks.discard)

            # Limit pending tasks to prevent memory buildup
            if len(pending_tasks) >= concurrency * 2:
                done, pending_tasks_set = await asyncio.wait(
                    pending_tasks, return_when=asyncio.FIRST_COMPLETED
                )
                pending_tasks = pending_tasks_set
                for done_task in done:
                    try:
                        result = done_task.result()
                        if isinstance(result, ScanResult):
                            results.append(result)
                    except Exception as e:
                        logger.warning(f"Scan task error: {e}")

        # Wait for remaining tasks
        if pending_tasks:
            done_tasks = await asyncio.gather(*pending_tasks, return_exceptions=True)
            for result in done_tasks:
                if isinstance(result, ScanResult):
                    results.append(result)
                elif isinstance(result, Exception):
                    logger.warning(f"Scan task exception: {result}")

        return results

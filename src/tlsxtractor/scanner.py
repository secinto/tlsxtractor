"""
TLS connection and scanning functionality.
"""

import asyncio
import ssl
import socket
from typing import Optional, Dict, Any, List, Callable, Awaitable
from dataclasses import dataclass, field
import logging


logger = logging.getLogger(__name__)

# Constants
BACKOFF_BASE = 2  # Base for exponential backoff calculation
DEFAULT_TIMEOUT = 5  # Default connection timeout in seconds
DEFAULT_RETRY_COUNT = 3  # Default number of retry attempts
DEFAULT_PORT = 443  # Default HTTPS port


@dataclass
class ScanResult:
    """Result from scanning a single target."""

    ip: str
    port: int
    status: str
    sni: Optional[str] = None
    certificate: Optional[Dict[str, Any]] = None
    domains: List[str] = field(default_factory=list)  # Aggregate list for backward compatibility
    domain_sources: Dict[str, List[str]] = field(default_factory=lambda: {
        "sni": [],
        "san": [],
        "cn": [],
        "csp": []
    })
    error: Optional[str] = None
    tls_version: Optional[str] = None


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
    ):
        """
        Initialize TLS scanner.

        Args:
            timeout: Connection timeout in seconds
            retry_count: Maximum number of retry attempts
            port: Default target port
            fetch_csp: Whether to fetch and parse CSP headers
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
            self._csp_extractor = CSPExtractor(timeout=timeout)

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
        # Support TLS 1.2 and 1.3
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

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
        target_port = port or self.port

        # Attempt connection with retries
        for attempt in range(self.retry_count + 1):
            try:
                result = await self._connect_and_scan(ip, target_port, sni)
                return result
            except asyncio.TimeoutError:
                logger.debug(f"Timeout connecting to {ip}:{target_port} (attempt {attempt + 1})")
                if attempt == self.retry_count:
                    return ScanResult(
                        ip=ip,
                        port=target_port,
                        status="timeout",
                        error="Connection timeout",
                    )
            except ConnectionRefusedError:
                logger.debug(f"Connection refused by {ip}:{target_port}")
                return ScanResult(
                    ip=ip,
                    port=target_port,
                    status="refused",
                    error="Connection refused",
                )
            except OSError as e:
                logger.debug(f"Network error connecting to {ip}:{target_port}: {e}")
                if attempt == self.retry_count:
                    return ScanResult(
                        ip=ip,
                        port=target_port,
                        status="error",
                        error=f"Network error: {str(e)}",
                    )
            except Exception as e:
                logger.debug(f"Unexpected error scanning {ip}:{target_port}: {e}")
                return ScanResult(
                    ip=ip,
                    port=target_port,
                    status="error",
                    error=f"Error: {str(e)}",
                )

            # Exponential backoff between retries
            if attempt < self.retry_count:
                await asyncio.sleep(BACKOFF_BASE ** attempt)

        # Should not reach here, but return error if it does
        return ScanResult(
            ip=ip,
            port=target_port,
            status="error",
            error="Max retries exceeded",
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
            raise OSError(f"SSL error: {e}")
        except Exception as e:
            raise OSError(f"Failed to connect: {e}")

        try:
            # Get SSL object from transport
            ssl_object = writer.get_extra_info("ssl_object")

            if ssl_object is None:
                writer.close()
                await writer.wait_closed()
                raise OSError("Failed to establish TLS connection")

            # Extract certificate in DER format
            cert_der = ssl_object.getpeercert(binary_form=True)
            tls_version = ssl_object.version()

            # Close connection
            writer.close()
            await writer.wait_closed()

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
            domain_sources = {
                "sni": [],
                "san": [],
                "cn": [],
                "csp": []
            }

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
                    logger.debug(f"Fetching CSP from {ip}:{port} (SNI: {sni})")
                    _, csp_domains = await self._csp_extractor.fetch_and_extract_domains(
                        ip=ip,
                        port=port,
                        sni=sni,
                        path="/"
                    )
                    if csp_domains:
                        domain_sources["csp"] = csp_domains
                        logger.debug(f"Extracted {len(csp_domains)} domains from CSP")
                except Exception as e:
                    # CSP extraction failure should not break the scan
                    logger.debug(f"CSP extraction failed for {ip}:{port}: {e}")

            # Build aggregate domains list for backward compatibility
            # Deduplicate across all sources
            all_domains = set()
            for source_domains in [domain_sources["sni"], domain_sources["san"], domain_sources["cn"], domain_sources["csp"]]:
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

        except Exception as e:
            # Ensure cleanup
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            raise

    async def scan_multiple(
        self,
        targets: List[tuple[str, Optional[int], Optional[str]]],
        concurrency: int = 10,
        rate_limit: Optional[float] = None,
        progress_callback: Optional[Callable[[ScanResult], Awaitable[None]]] = None,
    ) -> List[ScanResult]:
        """
        Scan multiple targets concurrently with optional rate limiting.

        Args:
            targets: List of (ip, port, sni) tuples
            concurrency: Maximum number of concurrent scans
            rate_limit: Optional rate limit in requests per second
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

                ip, port, sni = target
                result = await self.scan_target(ip, port, sni)

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
        processed_results = []
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
            else:
                processed_results.append(result)

        return processed_results
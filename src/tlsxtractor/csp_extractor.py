"""
Content Security Policy (CSP) extraction and parsing.

Fetches CSP headers from HTTPS endpoints and extracts domain names
from various CSP directives.
"""

import asyncio
import logging
import ssl
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Timeout for SSL shutdown (some servers hang)
SSL_SHUTDOWN_TIMEOUT = 2


class CSPExtractor:
    """
    Extracts and parses Content-Security-Policy headers.

    Fetches CSP headers via HTTPS and extracts domain names from
    various CSP directives while filtering out CSP keywords.
    """

    # CSP directives that may contain domain names
    DOMAIN_DIRECTIVES = {
        "default-src",
        "script-src",
        "style-src",
        "img-src",
        "connect-src",
        "font-src",
        "frame-src",
        "media-src",
        "object-src",
        "child-src",
        "worker-src",
        "manifest-src",
        "form-action",
        "frame-ancestors",
    }

    # CSP keywords to ignore (not domains)
    CSP_KEYWORDS = {
        "'self'",
        "'unsafe-inline'",
        "'unsafe-eval'",
        "'unsafe-hashes'",
        "'none'",
        "'strict-dynamic'",
        "'report-sample'",
        "data:",
        "blob:",
        "filesystem:",
        "mediastream:",
        "about:",
    }

    # HTTP redirect status codes
    REDIRECT_CODES = {301, 302, 303, 307, 308}

    def __init__(
        self,
        timeout: int = 5,
        user_agent: str = "TLSXtractor/1.0",
        follow_redirects: bool = False,
        follow_host_redirects: bool = False,
        max_redirects: int = 10,
    ):
        """
        Initialize CSP extractor.

        Args:
            timeout: Request timeout in seconds
            user_agent: User-Agent header to send
            follow_redirects: Follow all HTTP redirects
            follow_host_redirects: Follow redirects only to same host
            max_redirects: Maximum number of redirects to follow
        """
        self.timeout = timeout
        self.user_agent = user_agent
        self.follow_redirects = follow_redirects
        self.follow_host_redirects = follow_host_redirects
        self.max_redirects = max_redirects
        self._ssl_context = self._create_ssl_context()

    def _create_ssl_context(self) -> ssl.SSLContext:
        """
        Create SSL context for HTTPS requests.

        Returns:
            Configured SSL context
        """
        context = ssl.create_default_context()
        # Disable certificate verification for scanning purposes
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
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

    def _parse_redirect_location(
        self, location: str, current_host: str, current_port: int
    ) -> Optional[Tuple[str, int, str]]:
        """
        Parse redirect Location header.

        Args:
            location: The Location header value
            current_host: Current hostname
            current_port: Current port

        Returns:
            Tuple of (host, port, path) or None if invalid
        """
        if not location:
            return None

        # Handle relative URLs (e.g., "/new-path")
        if location.startswith("/"):
            return (current_host, current_port, location)

        # Handle absolute URLs
        try:
            parsed = urlparse(location)

            # Get scheme - default to https
            scheme = parsed.scheme.lower() if parsed.scheme else "https"
            if scheme not in ("http", "https"):
                return None

            # Get host
            host = parsed.hostname
            if not host:
                return None

            # Get port - default based on scheme
            if parsed.port:
                port = parsed.port
            else:
                port = 443 if scheme == "https" else 80

            # Get path
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"

            return (host, port, path)

        except Exception:
            return None

    def _extract_csp_from_headers(self, headers: Dict[str, str]) -> Optional[str]:
        """
        Extract CSP header value from headers dict.

        Args:
            headers: Dictionary of header name -> value

        Returns:
            CSP header value or None
        """
        for header_name, header_value in headers.items():
            if header_name.lower() in (
                "content-security-policy",
                "content-security-policy-report-only",
            ):
                return header_value
        return None

    def _extract_status_code(self, status_line: bytes) -> int:
        """
        Extract HTTP status code from status line.

        Args:
            status_line: Raw HTTP status line

        Returns:
            Status code as int, or 0 if parse fails
        """
        try:
            # e.g., "HTTP/1.1 301 Moved Permanently"
            parts = status_line.decode("utf-8", errors="ignore").split()
            if len(parts) >= 2:
                return int(parts[1])
        except (ValueError, IndexError):
            pass
        return 0

    async def _fetch_headers_with_status(
        self, host: str, port: int, hostname: str, path: str
    ) -> Tuple[int, Dict[str, str]]:
        """
        Fetch HTTP headers from endpoint with status code.

        Args:
            host: Target IP/host to connect to
            port: Target port
            hostname: Hostname for Host header and SNI
            path: HTTP path to request

        Returns:
            Tuple of (status_code, headers_dict)
        """
        try:
            # Open SSL connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host,
                    port,
                    ssl=self._ssl_context,
                    server_hostname=hostname,
                ),
                timeout=self.timeout,
            )

            # Send HTTP HEAD request
            request = (
                f"HEAD {path} HTTP/1.1\r\n"
                f"Host: {hostname}\r\n"
                f"User-Agent: {self.user_agent}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )

            writer.write(request.encode())
            await writer.drain()

            # Read status line
            status_line = await asyncio.wait_for(
                reader.readline(), timeout=self.timeout
            )
            status_code = self._extract_status_code(status_line)

            # Read headers
            headers: Dict[str, str] = {}
            while True:
                line = await asyncio.wait_for(
                    reader.readline(), timeout=self.timeout
                )
                if not line or line == b"\r\n" or line == b"\n":
                    break
                line_str = line.decode("utf-8", errors="ignore").strip()
                if ":" in line_str:
                    name, value = line_str.split(":", 1)
                    headers[name.strip()] = value.strip()

            # Close connection
            await self._safe_close_writer(writer)

            return (status_code, headers)

        except asyncio.TimeoutError:
            logger.debug(f"Timeout fetching headers from {host}:{port}")
            return (0, {})
        except Exception as e:
            logger.debug(f"Error fetching headers from {host}:{port}: {e}")
            return (0, {})

    async def fetch_csp(
        self, ip: str, port: int = 443, sni: Optional[str] = None, path: str = "/"
    ) -> Optional[str]:
        """
        Fetch Content-Security-Policy header from HTTPS endpoint.

        Supports following redirects if enabled.

        Args:
            ip: Target IP address
            port: Target port (default 443)
            sni: Server Name Indication hostname
            path: HTTP path to request (default /)

        Returns:
            CSP header value or None if not found/error
        """
        # Current connection target
        current_host = ip
        current_hostname = sni if sni else ip
        current_port = port
        current_path = path
        original_hostname = current_hostname
        redirect_count = 0
        visited_urls: Set[str] = set()

        while redirect_count <= self.max_redirects:
            # Build URL key for loop detection
            url_key = f"{current_hostname}:{current_port}{current_path}"
            if url_key in visited_urls:
                logger.debug(f"Redirect loop detected: {url_key}")
                break
            visited_urls.add(url_key)

            # Fetch headers with status code
            status_code, headers = await self._fetch_headers_with_status(
                current_host, current_port, current_hostname, current_path
            )

            if status_code == 0:
                # Connection failed
                break

            # Check for CSP in response
            csp_value = self._extract_csp_from_headers(headers)
            if csp_value:
                logger.debug(
                    f"Found CSP header on {current_hostname}:{current_port}: "
                    f"{csp_value[:100]}..."
                )
                return csp_value

            # Check for redirect
            if status_code in self.REDIRECT_CODES:
                location = headers.get("Location") or headers.get("location")
                if not location:
                    logger.debug(f"Redirect {status_code} but no Location header")
                    break

                # Check redirect policy
                if not self.follow_redirects and not self.follow_host_redirects:
                    logger.debug(
                        f"Redirect to {location} ignored (redirect following disabled)"
                    )
                    break

                # Parse redirect target
                redirect_info = self._parse_redirect_location(
                    location, current_hostname, current_port
                )
                if not redirect_info:
                    logger.debug(f"Failed to parse redirect location: {location}")
                    break

                new_host, new_port, new_path = redirect_info

                # Check same-host restriction
                if self.follow_host_redirects and not self.follow_redirects:
                    if new_host.lower() != original_hostname.lower():
                        logger.debug(
                            f"Blocked cross-host redirect: "
                            f"{current_hostname} -> {new_host}"
                        )
                        break

                # Update for next iteration
                # For redirects, we connect to the new host and use it for SNI
                current_host = new_host
                current_hostname = new_host
                current_port = new_port
                current_path = new_path
                redirect_count += 1

                logger.debug(
                    f"Following redirect {redirect_count}/{self.max_redirects}: "
                    f"{location}"
                )
                continue

            # No redirect, no CSP found
            break

        return None

    async def _read_http_headers(self, reader: asyncio.StreamReader) -> Dict[str, str]:
        """
        Read HTTP response headers.

        Args:
            reader: Stream reader

        Returns:
            Dictionary of header name -> value
        """
        headers: Dict[str, str] = {}

        # Read status line
        try:
            status_line = await asyncio.wait_for(reader.readline(), timeout=self.timeout)
            if not status_line:
                return headers

            # Read headers until blank line
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=self.timeout)

                if not line or line == b"\r\n" or line == b"\n":
                    break

                # Parse header
                line_str = line.decode("utf-8", errors="ignore").strip()
                if ":" in line_str:
                    name, value = line_str.split(":", 1)
                    headers[name.strip()] = value.strip()

        except asyncio.TimeoutError:
            logger.debug("Timeout reading HTTP headers")
        except Exception as e:
            logger.debug(f"Error reading HTTP headers: {e}")

        return headers

    def parse_csp_header(self, csp_header: str) -> Dict[str, List[str]]:
        """
        Parse CSP header value into directives.

        Args:
            csp_header: Raw CSP header value

        Returns:
            Dictionary mapping directive names to their values
        """
        if not csp_header:
            return {}

        directives = {}

        # Split by semicolon to get individual directives
        parts = csp_header.split(";")

        for part in parts:
            part = part.strip()
            if not part:
                continue

            # Split directive name from values
            tokens = part.split()
            if not tokens:
                continue

            directive_name = tokens[0].lower()
            directive_values = tokens[1:] if len(tokens) > 1 else []

            directives[directive_name] = directive_values

        return directives

    def extract_domains_from_csp(self, csp_directives: Dict[str, List[str]]) -> List[str]:
        """
        Extract domain names from CSP directives.

        Args:
            csp_directives: Parsed CSP directives

        Returns:
            List of unique domain names
        """
        domains: Set[str] = set()

        for directive_name, values in csp_directives.items():
            # Only process directives that may contain domains
            if directive_name not in self.DOMAIN_DIRECTIVES:
                continue

            for value in values:
                # Skip CSP keywords
                if self._is_csp_keyword(value):
                    continue

                # Skip nonce/hash values
                if value.startswith("'nonce-") or value.startswith("'sha"):
                    continue

                # Extract domain from value
                domain = self._extract_domain(value)
                if domain:
                    domains.add(domain)

        return sorted(list(domains))

    def _is_csp_keyword(self, value: str) -> bool:
        """
        Check if value is a CSP keyword (not a domain).

        Args:
            value: CSP value to check

        Returns:
            True if it's a CSP keyword
        """
        value_lower = value.lower()

        # Check exact matches
        if value_lower in self.CSP_KEYWORDS:
            return True

        # Check if starts with known keyword prefix
        for keyword in self.CSP_KEYWORDS:
            if value_lower.startswith(keyword):
                return True

        return False

    def _extract_domain(self, value: str) -> Optional[str]:
        """
        Extract domain name from CSP value.

        Handles:
        - Plain domains: example.com
        - Domains with scheme: https://example.com
        - Domains with port: example.com:443
        - Wildcard subdomains: *.example.com

        Args:
            value: CSP value

        Returns:
            Extracted domain or None
        """
        if not value:
            return None

        # Remove quotes if present
        value = value.strip("'\"")

        # Parse as URL if it contains a scheme
        if "://" in value:
            try:
                parsed = urlparse(value)
                # Get hostname without port
                domain = parsed.hostname or parsed.netloc.split(":")[0]
                if domain:
                    return domain
            except Exception:
                # If URL parsing fails, try to extract manually
                pass

        # Handle scheme-relative URLs
        if value.startswith("//"):
            value = value[2:]

        # Split by / to get just the host part
        host_part = value.split("/")[0]

        # Remove port if present
        if ":" in host_part:
            # Handle IPv6 addresses in brackets
            if "[" in host_part:
                # IPv6 - not a domain name
                return None
            # Remove port
            host_part = host_part.split(":")[0]

        # Remove path/query if somehow still present
        host_part = host_part.split("?")[0]

        # Validate it looks like a domain
        if not host_part or " " in host_part:
            return None

        # Must contain at least one dot (unless it's localhost or wildcard)
        if "." not in host_part and host_part not in ("localhost",):
            return None

        # Clean up and return
        return host_part.strip()

    async def fetch_and_extract_domains(
        self, ip: str, port: int = 443, sni: Optional[str] = None, path: str = "/"
    ) -> Tuple[Optional[str], List[str]]:
        """
        Fetch CSP header and extract domains in one call.

        Args:
            ip: Target IP address
            port: Target port
            sni: Server Name Indication hostname
            path: HTTP path to request

        Returns:
            Tuple of (raw_csp_header, extracted_domains)
        """
        csp_header = await self.fetch_csp(ip, port, sni, path)

        if not csp_header:
            return None, []

        directives = self.parse_csp_header(csp_header)
        domains = self.extract_domains_from_csp(directives)

        return csp_header, domains

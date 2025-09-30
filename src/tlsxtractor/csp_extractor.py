"""
Content Security Policy (CSP) extraction and parsing.

Fetches CSP headers from HTTPS endpoints and extracts domain names
from various CSP directives.
"""

import asyncio
import ssl
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urlparse
import logging


logger = logging.getLogger(__name__)


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

    def __init__(self, timeout: int = 5, user_agent: str = "TLSXtractor/1.0"):
        """
        Initialize CSP extractor.

        Args:
            timeout: Request timeout in seconds
            user_agent: User-Agent header to send
        """
        self.timeout = timeout
        self.user_agent = user_agent
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

    async def fetch_csp(
        self,
        ip: str,
        port: int = 443,
        sni: Optional[str] = None,
        path: str = "/"
    ) -> Optional[str]:
        """
        Fetch Content-Security-Policy header from HTTPS endpoint.

        Args:
            ip: Target IP address
            port: Target port (default 443)
            sni: Server Name Indication hostname
            path: HTTP path to request (default /)

        Returns:
            CSP header value or None if not found/error
        """
        # Determine hostname for HTTP request
        hostname = sni if sni else ip

        try:
            # Open SSL connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    ip,
                    port,
                    ssl=self._ssl_context,
                    server_hostname=sni if sni else None,
                ),
                timeout=self.timeout,
            )

            # Send HTTP HEAD request (faster than GET, only needs headers)
            request = (
                f"HEAD {path} HTTP/1.1\r\n"
                f"Host: {hostname}\r\n"
                f"User-Agent: {self.user_agent}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )

            writer.write(request.encode())
            await writer.drain()

            # Read response headers
            headers = await self._read_http_headers(reader)

            # Close connection
            writer.close()
            await writer.wait_closed()

            # Look for CSP header (case-insensitive)
            csp_value = None
            for header_name, header_value in headers.items():
                if header_name.lower() in ("content-security-policy", "content-security-policy-report-only"):
                    csp_value = header_value
                    logger.debug(f"Found CSP header on {ip}:{port}: {csp_value[:100]}...")
                    break

            return csp_value

        except asyncio.TimeoutError:
            logger.debug(f"Timeout fetching CSP from {ip}:{port}")
            return None
        except Exception as e:
            logger.debug(f"Error fetching CSP from {ip}:{port}: {e}")
            return None

    async def _read_http_headers(self, reader: asyncio.StreamReader) -> Dict[str, str]:
        """
        Read HTTP response headers.

        Args:
            reader: Stream reader

        Returns:
            Dictionary of header name -> value
        """
        headers = {}

        # Read status line
        try:
            status_line = await asyncio.wait_for(
                reader.readline(),
                timeout=self.timeout
            )
            if not status_line:
                return headers

            # Read headers until blank line
            while True:
                line = await asyncio.wait_for(
                    reader.readline(),
                    timeout=self.timeout
                )

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
        self,
        ip: str,
        port: int = 443,
        sni: Optional[str] = None,
        path: str = "/"
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
"""
Input file parsing and IP range expansion.
"""

import ipaddress
import logging
from pathlib import Path
from typing import Iterator, List, Literal, Optional, Union
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class InputParser:
    """
    Handles parsing of input files and IP range expansion.

    Implements Tasks IMPL-005, IMPL-009, IMPL-010:
    - Simple IP list input processing
    - CIDR notation parsing and IP range generation
    - URL parsing and hostname extraction
    """

    @staticmethod
    def parse_ip_file(file_path: str) -> List[str]:
        """
        Parse file containing IP addresses.

        Args:
            file_path: Path to file with one IP per line

        Returns:
            List of valid IP addresses
        """
        ips = []
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"IP file not found: {file_path}")

        with open(path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue

                # Validate IP address
                try:
                    ipaddress.ip_address(line)
                    ips.append(line)
                except ValueError:
                    logger.warning(f"Invalid IP at line {line_num}: {line}")

        return ips

    @staticmethod
    def parse_cidr(cidr: str) -> Iterator[str]:
        """
        Parse CIDR notation and generate IP addresses.

        Args:
            cidr: CIDR notation (e.g., "192.168.1.0/24")

        Yields:
            IP addresses in the range
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            for ip in network.hosts():
                yield str(ip)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR notation: {cidr}") from e

    @staticmethod
    def parse_url_file(file_path: str) -> List[tuple[str, str, Optional[int]]]:
        """
        Parse file containing URLs and extract URL, hostname, and port.

        Args:
            file_path: Path to file with one URL per line

        Returns:
            List of tuples (original_url, hostname, port)
        """
        from urllib.parse import urlparse

        url_data: List[tuple[str, str, Optional[int]]] = []
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"URL file not found: {file_path}")

        with open(path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                original_line = line.strip()

                # Skip empty lines and comments
                if not original_line or original_line.startswith("#"):
                    continue

                # Parse URL
                try:
                    # Add scheme if missing
                    line = original_line
                    if not line.startswith(("http://", "https://")):
                        line = f"https://{line}"

                    parsed = urlparse(line)
                    if parsed.hostname:
                        # Determine port
                        port = parsed.port
                        if port is None:
                            # Default ports based on scheme
                            port = 443 if parsed.scheme == "https" else 80

                        url_data.append((original_line, parsed.hostname, port))
                    else:
                        print(f"Warning: No hostname in URL at line {line_num}: {original_line}")
                except Exception as e:
                    print(f"Warning: Invalid URL at line {line_num}: {original_line} - {e}")

        return url_data

    @staticmethod
    def parse_hostname_file(file_path: str) -> List[str]:
        """
        Parse file containing hostnames.

        Args:
            file_path: Path to file with one hostname per line

        Returns:
            List of hostnames
        """
        hostnames = []
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"Hostname file not found: {file_path}")

        with open(path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue

                # Basic validation - hostname should not contain scheme
                if line.startswith(("http://", "https://")):
                    print(
                        f"Warning: Line {line_num} looks like a URL, not a hostname. Use --url-file instead."
                    )
                    continue

                hostnames.append(line)

        return hostnames

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """
        Check if an IP address is in a private range.

        Args:
            ip: IP address string

        Returns:
            True if IP is private, False otherwise
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False

    @staticmethod
    def detect_file_type(file_path: str, sample_size: int = 20) -> Literal["ip", "url", "hostname"]:
        """
        Automatically detect the type of input file by analyzing first lines.

        Args:
            file_path: Path to input file
            sample_size: Number of non-empty lines to analyze (default: 10)

        Returns:
            File type: "ip", "url", or "hostname"

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If file type cannot be determined
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Input file not found: {file_path}")

        # Read first N non-empty, non-comment lines
        sample_lines = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    sample_lines.append(line)
                    if len(sample_lines) >= sample_size:
                        break

        if not sample_lines:
            raise ValueError(f"File is empty or contains only comments: {file_path}")

        # Analyze sample lines to detect type
        ip_count = 0
        url_count = 0
        hostname_count = 0

        for line in sample_lines:
            # Check if it's an IP address
            try:
                ipaddress.ip_address(line)
                ip_count += 1
                continue
            except ValueError:
                pass

            # Check if it's a URL (has scheme or looks like URL with path)
            if line.startswith(("http://", "https://")):
                url_count += 1
                continue

            # Try parsing as URL with added scheme
            try:
                test_url = (
                    f"https://{line}" if not line.startswith(("http://", "https://")) else line
                )
                parsed = urlparse(test_url)

                # If it has a path component beyond '/', it's likely a URL
                if parsed.path and parsed.path != "/":
                    url_count += 1
                    continue

                # If it has query or fragment, it's a URL
                if parsed.query or parsed.fragment:
                    url_count += 1
                    continue
            except Exception:
                pass

            # Otherwise, treat as hostname
            hostname_count += 1

        # Determine file type based on majority with URL priority
        # If we have any URLs detected, prioritize URL type since URLs are more specific
        if url_count > 0 and url_count >= ip_count * 0.5:
            # If at least 50% as many URLs as IPs, treat as URL file
            return "url"
        elif ip_count > 0 and ip_count > url_count:
            return "ip"
        elif url_count > 0:
            return "url"
        elif ip_count > 0:
            return "ip"
        else:
            return "hostname"

    @staticmethod
    def detect_line_type(line: str) -> Literal["ip", "url", "hostname"]:
        """
        Detect the type of a single line.

        Args:
            line: Input line (trimmed)

        Returns:
            Line type: "ip", "url", or "hostname"
        """
        # Check if it's an IP address
        try:
            ipaddress.ip_address(line)
            return "ip"
        except ValueError:
            pass

        # Check if it's a URL (has scheme)
        if line.startswith(("http://", "https://")):
            return "url"

        # Try parsing as URL with added scheme
        try:
            test_url = f"https://{line}"
            parsed = urlparse(test_url)

            # If it has a path component beyond '/', it's likely a URL
            if parsed.path and parsed.path != "/":
                return "url"

            # If it has query or fragment, it's a URL
            if parsed.query or parsed.fragment:
                return "url"
        except Exception:
            pass

        # Otherwise, treat as hostname
        return "hostname"

    @staticmethod
    def parse_mixed_file(file_path: str) -> tuple[List[str], List[tuple[str, str, Optional[int]]]]:
        """
        Parse a mixed file containing IPs, URLs, and/or hostnames.
        Detects type for each line individually.

        Args:
            file_path: Path to input file

        Returns:
            Tuple of (ip_list, url_data_list) where:
            - ip_list: List of IP addresses
            - url_data_list: List of (original_url, hostname, port) tuples

        Raises:
            FileNotFoundError: If file doesn't exist
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Input file not found: {file_path}")

        ip_list = []
        url_data_list: List[tuple[str, str, Optional[int]]] = []

        with open(path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                original_line = line.strip()

                # Skip empty lines and comments
                if not original_line or original_line.startswith("#"):
                    continue

                # Detect line type
                line_type = InputParser.detect_line_type(original_line)

                if line_type == "ip":
                    # Validate and add IP
                    try:
                        ipaddress.ip_address(original_line)
                        ip_list.append(original_line)
                    except ValueError:
                        print(f"Warning: Invalid IP at line {line_num}: {original_line}")

                else:  # url or hostname
                    # Parse as URL/hostname
                    try:
                        # Add scheme if missing
                        line = original_line
                        if not line.startswith(("http://", "https://")):
                            line = f"https://{line}"

                        parsed = urlparse(line)
                        if parsed.hostname:
                            # Determine port
                            port = parsed.port
                            if port is None:
                                port = 443 if parsed.scheme == "https" else 80

                            url_data_list.append((original_line, parsed.hostname, port))
                        else:
                            print(
                                f"Warning: No hostname in URL at line {line_num}: {original_line}"
                            )
                    except Exception as e:
                        print(
                            f"Warning: Invalid URL/hostname at line {line_num}: {original_line} - {e}"
                        )

        return ip_list, url_data_list

    @staticmethod
    def parse_file(
        file_path: str, file_type: Optional[str] = None
    ) -> Union[List[str], List[tuple[str, str, Optional[int]]], tuple[List[str], List[tuple[str, str, Optional[int]]]]]:
        """
        Parse input file with automatic or specified type detection.

        Args:
            file_path: Path to input file
            file_type: Optional explicit type ("ip", "url", "hostname", "mixed"). If None, uses mixed mode.

        Returns:
            Parsed data in appropriate format based on file type

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If file type cannot be determined
        """
        # Default to mixed mode for maximum flexibility
        if file_type is None:
            return InputParser.parse_mixed_file(file_path)

        # Parse based on specified type
        if file_type == "ip":
            return InputParser.parse_ip_file(file_path)
        elif file_type == "url":
            return InputParser.parse_url_file(file_path)
        elif file_type == "hostname":
            return InputParser.parse_hostname_file(file_path)
        elif file_type == "mixed":
            return InputParser.parse_mixed_file(file_path)
        else:
            raise ValueError(f"Invalid file type: {file_type}")

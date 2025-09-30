"""
Unit tests for input parser.
"""

import pytest
from pathlib import Path
from tlsxtractor.input_parser import InputParser


def test_parse_cidr_ipv4():
    """Test parsing IPv4 CIDR notation."""
    ips = list(InputParser.parse_cidr("192.168.1.0/30"))
    assert len(ips) == 2  # .1 and .2 (no network/broadcast for /30)
    assert "192.168.1.1" in ips
    assert "192.168.1.2" in ips


def test_parse_cidr_single_ip():
    """Test parsing single IP as /32."""
    ips = list(InputParser.parse_cidr("192.168.1.1/32"))
    assert len(ips) == 1  # Single host address
    assert ips[0] == "192.168.1.1"


def test_parse_cidr_invalid():
    """Test parsing invalid CIDR."""
    with pytest.raises(ValueError):
        list(InputParser.parse_cidr("not-a-cidr"))


def test_parse_ip_file(tmp_path):
    """Test parsing IP file."""
    # Create test file
    test_file = tmp_path / "test_ips.txt"
    test_file.write_text("1.1.1.1\n8.8.8.8\n# Comment\n\n9.9.9.9\n")

    ips = InputParser.parse_ip_file(str(test_file))
    assert len(ips) == 3
    assert "1.1.1.1" in ips
    assert "8.8.8.8" in ips
    assert "9.9.9.9" in ips


def test_parse_ip_file_not_found():
    """Test parsing non-existent IP file."""
    with pytest.raises(FileNotFoundError):
        InputParser.parse_ip_file("/nonexistent/file.txt")


def test_parse_ip_file_invalid_ip(tmp_path, capsys):
    """Test parsing file with invalid IPs."""
    test_file = tmp_path / "test_ips.txt"
    test_file.write_text("1.1.1.1\ninvalid-ip\n8.8.8.8\n")

    ips = InputParser.parse_ip_file(str(test_file))
    assert len(ips) == 2
    assert "1.1.1.1" in ips
    assert "8.8.8.8" in ips

    # Check warning was printed
    captured = capsys.readouterr()
    assert "Invalid IP" in captured.out


def test_is_private_ip():
    """Test private IP detection."""
    assert InputParser.is_private_ip("192.168.1.1") is True
    assert InputParser.is_private_ip("10.0.0.1") is True
    assert InputParser.is_private_ip("172.16.0.1") is True
    assert InputParser.is_private_ip("127.0.0.1") is True

    assert InputParser.is_private_ip("1.1.1.1") is False
    assert InputParser.is_private_ip("8.8.8.8") is False


def test_parse_url_file(tmp_path):
    """Test parsing URL file."""
    test_file = tmp_path / "test_urls.txt"
    test_file.write_text("https://example.com\nexample.org\n# Comment\n\n")

    url_data = InputParser.parse_url_file(str(test_file))
    assert len(url_data) == 2

    # url_data is list of (original_url, hostname, port) tuples
    urls = [u[0] for u in url_data]
    hostnames = [u[1] for u in url_data]
    ports = [u[2] for u in url_data]

    assert "https://example.com" in urls
    assert "example.org" in urls
    assert "example.com" in hostnames
    assert "example.org" in hostnames
    assert 443 in ports


def test_parse_hostname_file(tmp_path):
    """Test parsing hostname file."""
    test_file = tmp_path / "test_hostnames.txt"
    test_file.write_text("example.com\nexample.org\n# Comment\n\n")

    hostnames = InputParser.parse_hostname_file(str(test_file))
    assert len(hostnames) == 2
    assert "example.com" in hostnames
    assert "example.org" in hostnames


def test_detect_file_type_ip(tmp_path):
    """Test auto-detection of IP file."""
    test_file = tmp_path / "test_ips.txt"
    test_file.write_text("1.1.1.1\n8.8.8.8\n9.9.9.9\n")

    file_type = InputParser.detect_file_type(str(test_file))
    assert file_type == "ip"


def test_detect_file_type_url(tmp_path):
    """Test auto-detection of URL file."""
    test_file = tmp_path / "test_urls.txt"
    test_file.write_text("https://example.com\nhttps://example.org\nexample.net/path\n")

    file_type = InputParser.detect_file_type(str(test_file))
    assert file_type == "url"


def test_detect_file_type_hostname(tmp_path):
    """Test auto-detection of hostname file."""
    test_file = tmp_path / "test_hostnames.txt"
    test_file.write_text("example.com\nexample.org\nexample.net\n")

    file_type = InputParser.detect_file_type(str(test_file))
    assert file_type == "hostname"


def test_detect_file_type_mixed_ip_dominant(tmp_path):
    """Test auto-detection with mixed content (IPs dominant)."""
    test_file = tmp_path / "test_mixed.txt"
    test_file.write_text("1.1.1.1\n8.8.8.8\nexample.com\n")

    file_type = InputParser.detect_file_type(str(test_file))
    assert file_type == "ip"


def test_detect_file_type_with_comments(tmp_path):
    """Test auto-detection skipping comments."""
    test_file = tmp_path / "test_with_comments.txt"
    test_file.write_text("# This is a comment\n1.1.1.1\n# Another comment\n8.8.8.8\n9.9.9.9\n")

    file_type = InputParser.detect_file_type(str(test_file))
    assert file_type == "ip"


def test_detect_file_type_empty(tmp_path):
    """Test auto-detection on empty file."""
    test_file = tmp_path / "test_empty.txt"
    test_file.write_text("\n\n\n")

    with pytest.raises(ValueError, match="empty or contains only comments"):
        InputParser.detect_file_type(str(test_file))


def test_detect_file_type_not_found():
    """Test auto-detection on non-existent file."""
    with pytest.raises(FileNotFoundError):
        InputParser.detect_file_type("/nonexistent/file.txt")


def test_parse_file_auto_detect_ip(tmp_path):
    """Test parse_file with auto-detection for IPs."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("1.1.1.1\n8.8.8.8\n")

    result = InputParser.parse_file(str(test_file))
    assert isinstance(result, list)
    assert len(result) == 2
    assert "1.1.1.1" in result


def test_parse_file_explicit_type(tmp_path):
    """Test parse_file with explicit type specification."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("example.com\nexample.org\n")

    result = InputParser.parse_file(str(test_file), file_type="hostname")
    assert isinstance(result, list)
    assert len(result) == 2
    assert "example.com" in result
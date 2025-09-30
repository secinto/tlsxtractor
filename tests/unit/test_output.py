"""
Unit tests for output module.
"""

import pytest
from tlsxtractor.output import HostnameAnalyzer


class TestHostnameAnalyzer:
    """Test HostnameAnalyzer class."""

    def test_analyze_results_with_none_values(self):
        """Test that None values in results don't cause errors."""
        # Create results with None values
        results = {
            "ips": [
                {
                    "ip": "1.1.1.1",
                    "port": 443,
                    "status": "success",
                    "domains": ["example.com"],
                    "certificate": {
                        "san": ["example.com", "www.example.com"],
                        "subject": {"commonName": "example.com"},
                    },
                },
                None,  # This should not cause an error
                {
                    "ip": "8.8.8.8",
                    "port": 443,
                    "status": "success",
                    "domains": ["google.com"],
                },
            ]
        }

        # Should not raise an exception
        result = HostnameAnalyzer.analyze_results(results)

        # Verify expected hostnames are extracted
        assert "example.com" in result["hostnames"]
        assert "www.example.com" in result["hostnames"]
        assert "google.com" in result["hostnames"]
        assert result["total_hostnames"] == 3

    def test_analyze_results_filters_wildcards(self):
        """Test that wildcard domains are filtered out."""
        results = {
            "ips": [
                {
                    "domains": ["example.com", "*.example.com", "test.example.com"],
                }
            ]
        }

        result = HostnameAnalyzer.analyze_results(results)

        assert "example.com" in result["hostnames"]
        assert "test.example.com" in result["hostnames"]
        assert "*.example.com" not in result["hostnames"]
        assert "*.example.com" in result["wildcards"]

    def test_analyze_results_filters_tlds(self):
        """Test that bare TLDs are filtered out."""
        results = {
            "ips": [
                {
                    "domains": ["example.com", "com", "org", ".net"],
                }
            ]
        }

        result = HostnameAnalyzer.analyze_results(results)

        assert "example.com" in result["hostnames"]
        assert "com" not in result["hostnames"]
        assert "org" not in result["hostnames"]
        assert "net" not in result["hostnames"]
        assert "com" in result["tlds"]

    def test_is_wildcard(self):
        """Test wildcard detection."""
        assert HostnameAnalyzer.is_wildcard("*.example.com")
        assert HostnameAnalyzer.is_wildcard("*")
        assert not HostnameAnalyzer.is_wildcard("example.com")

    def test_is_tld_only(self):
        """Test TLD detection."""
        assert HostnameAnalyzer.is_tld_only("com")
        assert HostnameAnalyzer.is_tld_only(".com")
        assert HostnameAnalyzer.is_tld_only("org")
        assert not HostnameAnalyzer.is_tld_only("example.com")

    def test_is_valid_hostname(self):
        """Test hostname validation."""
        assert HostnameAnalyzer.is_valid_hostname("example.com")
        assert HostnameAnalyzer.is_valid_hostname("sub.example.com")
        assert HostnameAnalyzer.is_valid_hostname("test-site.example.com")
        assert not HostnameAnalyzer.is_valid_hostname("com")
        assert not HostnameAnalyzer.is_valid_hostname("")
        assert not HostnameAnalyzer.is_valid_hostname(".")

    def test_analyze_empty_results(self):
        """Test analysis with empty results."""
        result = HostnameAnalyzer.analyze_results({"ips": []})
        assert result["total_hostnames"] == 0
        assert len(result["hostnames"]) == 0

    def test_analyze_results_with_urls(self):
        """Test analysis with URL results."""
        results = {
            "urls": [
                {
                    "url": "https://example.com",
                    "hostname": "example.com",
                    "connections": [
                        {
                            "domains": ["example.com", "www.example.com"],
                        }
                    ],
                },
                None,  # This should not cause an error
            ]
        }

        result = HostnameAnalyzer.analyze_results(results)

        assert "example.com" in result["hostnames"]
        assert "www.example.com" in result["hostnames"]

    def test_analyze_results_with_list_format(self):
        """Test analysis with list format results."""
        results = [
            {
                "domains": ["example.com"],
            },
            None,  # This should not cause an error
            {
                "domains": ["test.com"],
            },
        ]

        result = HostnameAnalyzer.analyze_results(results)

        assert "example.com" in result["hostnames"]
        assert "test.com" in result["hostnames"]
        assert result["total_hostnames"] == 2
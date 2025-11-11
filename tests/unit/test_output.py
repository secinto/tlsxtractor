"""
Unit tests for output module.
"""


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

        # example.com and google.com are registrable domains -> in tlds
        assert "example.com" in result["tlds"]
        assert "google.com" in result["tlds"]
        # www.example.com is a subdomain -> in hostnames
        assert "www.example.com" in result["hostnames"]
        assert result["total_hostnames"] == 1
        assert result["total_tlds"] == 2

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

        # example.com is registrable domain -> in tlds
        assert "example.com" in result["tlds"]
        # test.example.com is subdomain -> in hostnames
        assert "test.example.com" in result["hostnames"]
        # Wildcards should not be in hostnames
        assert "*.example.com" not in result["hostnames"]
        assert "*.example.com" in result["wildcards"]

    def test_analyze_results_separates_base_domains(self):
        """Test that base domains (eTLD+1) are separated into tlds category."""
        results = {
            "ips": [
                {
                    "domains": ["example.com", "api.example.com", "www.example.com"],
                }
            ]
        }

        result = HostnameAnalyzer.analyze_results(results)

        # example.com is the registrable domain -> in tlds
        assert "example.com" in result["tlds"]
        assert "example.com" not in result["hostnames"]

        # Subdomains should be in hostnames
        assert "api.example.com" in result["hostnames"]
        assert "www.example.com" in result["hostnames"]

        assert result["total_hostnames"] == 2
        assert result["total_tlds"] == 1

    def test_analyze_results_handles_multi_part_tlds(self):
        """Test handling of multi-part TLDs like co.uk, or.at."""
        results = {
            "ips": [
                {
                    "domains": [
                        "example.co.uk",
                        "www.example.co.uk",
                        "test.or.at",
                        "sub.test.or.at",
                    ],
                }
            ]
        }

        result = HostnameAnalyzer.analyze_results(results)

        # Registrable domains should be in tlds
        assert "example.co.uk" in result["tlds"]
        assert "test.or.at" in result["tlds"]

        # Subdomains should be in hostnames
        assert "www.example.co.uk" in result["hostnames"]
        assert "sub.test.or.at" in result["hostnames"]

        assert result["total_hostnames"] == 2
        assert result["total_tlds"] == 2

    def test_is_wildcard(self):
        """Test wildcard detection."""
        assert HostnameAnalyzer.is_wildcard("*.example.com")
        assert HostnameAnalyzer.is_wildcard("*")
        assert not HostnameAnalyzer.is_wildcard("example.com")

    def test_is_registrable_domain(self):
        """Test registrable domain detection."""
        # These ARE registrable domains (no subdomain)
        assert HostnameAnalyzer.is_registrable_domain("example.com")
        assert HostnameAnalyzer.is_registrable_domain("example.co.uk")
        assert HostnameAnalyzer.is_registrable_domain("test.or.at")

        # These are NOT registrable domains (have subdomains)
        assert not HostnameAnalyzer.is_registrable_domain("www.example.com")
        assert not HostnameAnalyzer.is_registrable_domain("api.example.com")
        assert not HostnameAnalyzer.is_registrable_domain("sub.example.co.uk")

    def test_extract_registrable_domain(self):
        """Test extracting registrable domain from hostname."""
        # Simple TLD
        assert HostnameAnalyzer.extract_registrable_domain("example.com") == "example.com"
        assert HostnameAnalyzer.extract_registrable_domain("www.example.com") == "example.com"
        assert HostnameAnalyzer.extract_registrable_domain("api.sub.example.com") == "example.com"

        # Multi-part TLD
        assert HostnameAnalyzer.extract_registrable_domain("example.co.uk") == "example.co.uk"
        assert HostnameAnalyzer.extract_registrable_domain("www.example.co.uk") == "example.co.uk"
        assert HostnameAnalyzer.extract_registrable_domain("test.or.at") == "test.or.at"
        assert HostnameAnalyzer.extract_registrable_domain("sub.test.or.at") == "test.or.at"

        # Invalid
        assert HostnameAnalyzer.extract_registrable_domain("") is None
        assert HostnameAnalyzer.extract_registrable_domain(None) is None

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
        assert result["total_tlds"] == 0
        assert len(result["hostnames"]) == 0
        assert len(result["tlds"]) == 0

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

        # example.com is registrable domain -> in tlds
        assert "example.com" in result["tlds"]
        # www.example.com is subdomain -> in hostnames
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

        # Both are registrable domains -> in tlds
        assert "example.com" in result["tlds"]
        assert "test.com" in result["tlds"]
        assert result["total_tlds"] == 2
        assert result["total_hostnames"] == 0

    def test_analyze_results_deduplicates(self):
        """Test that duplicate domains are deduplicated."""
        results = [
            {
                "domains": ["example.com", "example.com", "www.example.com"],
            },
            {
                "domains": ["www.example.com", "api.example.com"],
            },
        ]

        result = HostnameAnalyzer.analyze_results(results)

        # Only one instance of example.com in tlds
        assert result["tlds"].count("example.com") == 1
        assert result["total_tlds"] == 1

        # Only one instance of each subdomain
        assert result["hostnames"].count("www.example.com") == 1
        assert result["hostnames"].count("api.example.com") == 1
        assert result["total_hostnames"] == 2

    def test_analyze_results_mixed_registrable_and_subdomains(self):
        """Test with mix of registrable domains and subdomains."""
        results = [
            {
                "domains": [
                    "example.com",  # registrable
                    "api.example.com",  # subdomain
                    "test.org",  # registrable
                    "www.test.org",  # subdomain
                    "example.co.uk",  # registrable (multi-part TLD)
                    "cdn.example.co.uk",  # subdomain of multi-part TLD
                ],
            },
        ]

        result = HostnameAnalyzer.analyze_results(results)

        # Registrable domains
        assert "example.com" in result["tlds"]
        assert "test.org" in result["tlds"]
        assert "example.co.uk" in result["tlds"]
        assert result["total_tlds"] == 3

        # Subdomains
        assert "api.example.com" in result["hostnames"]
        assert "www.test.org" in result["hostnames"]
        assert "cdn.example.co.uk" in result["hostnames"]
        assert result["total_hostnames"] == 3

"""
Unit tests for CSP extraction module.
"""


from tlsxtractor.csp_extractor import CSPExtractor


class TestCSPExtractor:
    """Test CSPExtractor class."""

    def test_initialization(self):
        """Test CSPExtractor initialization."""
        extractor = CSPExtractor(timeout=10, user_agent="TestAgent/1.0")
        assert extractor.timeout == 10
        assert extractor.user_agent == "TestAgent/1.0"
        assert extractor._ssl_context is not None

    def test_initialization_defaults(self):
        """Test CSPExtractor with default parameters."""
        extractor = CSPExtractor()
        assert extractor.timeout == 5
        assert extractor.user_agent == "TLSXtractor/1.0"


class TestCSPHeaderParsing:
    """Test CSP header parsing."""

    def test_parse_simple_csp(self):
        """Test parsing simple CSP header."""
        extractor = CSPExtractor()
        csp = "default-src 'self'; script-src https://cdn.example.com"

        directives = extractor.parse_csp_header(csp)

        assert "default-src" in directives
        assert "script-src" in directives
        assert directives["default-src"] == ["'self'"]
        assert directives["script-src"] == ["https://cdn.example.com"]

    def test_parse_complex_csp(self):
        """Test parsing complex CSP with multiple directives."""
        extractor = CSPExtractor()
        csp = """
        default-src 'self';
        script-src 'self' 'unsafe-inline' https://cdn.example.com https://api.example.com;
        style-src 'self' https://fonts.googleapis.com;
        img-src * data: blob:;
        connect-src 'self' wss://socket.example.com
        """

        directives = extractor.parse_csp_header(csp)

        assert len(directives) == 5
        assert "default-src" in directives
        assert "script-src" in directives
        assert len(directives["script-src"]) == 4
        assert "https://cdn.example.com" in directives["script-src"]

    def test_parse_empty_csp(self):
        """Test parsing empty CSP header."""
        extractor = CSPExtractor()
        directives = extractor.parse_csp_header("")
        assert directives == {}

    def test_parse_none_csp(self):
        """Test parsing None CSP header."""
        extractor = CSPExtractor()
        directives = extractor.parse_csp_header(None)
        assert directives == {}

    def test_parse_csp_with_semicolons(self):
        """Test CSP with trailing semicolons."""
        extractor = CSPExtractor()
        csp = "default-src 'self';;; script-src https://example.com;;"

        directives = extractor.parse_csp_header(csp)

        assert "default-src" in directives
        assert "script-src" in directives


class TestCSPKeywordFiltering:
    """Test CSP keyword filtering."""

    def test_is_csp_keyword_self(self):
        """Test detection of 'self' keyword."""
        extractor = CSPExtractor()
        assert extractor._is_csp_keyword("'self'") is True
        assert extractor._is_csp_keyword("'SELF'") is True

    def test_is_csp_keyword_unsafe(self):
        """Test detection of unsafe keywords."""
        extractor = CSPExtractor()
        assert extractor._is_csp_keyword("'unsafe-inline'") is True
        assert extractor._is_csp_keyword("'unsafe-eval'") is True
        assert extractor._is_csp_keyword("'unsafe-hashes'") is True

    def test_is_csp_keyword_schemes(self):
        """Test detection of special schemes."""
        extractor = CSPExtractor()
        assert extractor._is_csp_keyword("data:") is True
        assert extractor._is_csp_keyword("blob:") is True
        assert extractor._is_csp_keyword("filesystem:") is True
        assert extractor._is_csp_keyword("mediastream:") is True

    def test_is_csp_keyword_none(self):
        """Test detection of 'none' keyword."""
        extractor = CSPExtractor()
        assert extractor._is_csp_keyword("'none'") is True

    def test_is_csp_keyword_domain(self):
        """Test that domains are not keywords."""
        extractor = CSPExtractor()
        assert extractor._is_csp_keyword("example.com") is False
        assert extractor._is_csp_keyword("https://example.com") is False


class TestDomainExtraction:
    """Test domain extraction from CSP values."""

    def test_extract_plain_domain(self):
        """Test extracting plain domain."""
        extractor = CSPExtractor()
        domain = extractor._extract_domain("example.com")
        assert domain == "example.com"

    def test_extract_domain_with_scheme(self):
        """Test extracting domain from URL with scheme."""
        extractor = CSPExtractor()
        domain = extractor._extract_domain("https://example.com")
        assert domain == "example.com"

    def test_extract_domain_with_port(self):
        """Test extracting domain with port."""
        extractor = CSPExtractor()
        domain = extractor._extract_domain("example.com:443")
        assert domain == "example.com"

    def test_extract_domain_with_path(self):
        """Test extracting domain from URL with path."""
        extractor = CSPExtractor()
        domain = extractor._extract_domain("https://example.com/path/to/resource")
        assert domain == "example.com"

    def test_extract_domain_wildcard(self):
        """Test extracting wildcard domain."""
        extractor = CSPExtractor()
        domain = extractor._extract_domain("*.example.com")
        assert domain == "*.example.com"

    def test_extract_domain_websocket(self):
        """Test extracting domain from WebSocket URL."""
        extractor = CSPExtractor()
        domain = extractor._extract_domain("wss://socket.example.com:8080")
        assert domain == "socket.example.com"

    def test_extract_domain_scheme_relative(self):
        """Test extracting domain from scheme-relative URL."""
        extractor = CSPExtractor()
        domain = extractor._extract_domain("//cdn.example.com/script.js")
        assert domain == "cdn.example.com"

    def test_extract_domain_with_quotes(self):
        """Test extracting domain with quotes."""
        extractor = CSPExtractor()
        domain = extractor._extract_domain("'example.com'")
        assert domain == "example.com"

    def test_extract_domain_invalid(self):
        """Test extracting from invalid values."""
        extractor = CSPExtractor()

        # No domain
        assert extractor._extract_domain("") is None
        assert extractor._extract_domain(None) is None

        # No dot (not a domain) - except localhost which is allowed
        assert extractor._extract_domain("localhost") == "localhost"
        assert extractor._extract_domain("notadomain") is None

        # IPv6 (not a domain name)
        assert extractor._extract_domain("[::1]:443") is None


class TestExtractDomainsFromCSP:
    """Test full domain extraction from CSP directives."""

    def test_extract_domains_basic(self):
        """Test basic domain extraction from CSP."""
        extractor = CSPExtractor()
        directives = {
            "default-src": ["'self'"],
            "script-src": ["https://cdn.example.com", "https://api.example.com"],
            "style-src": ["https://fonts.googleapis.com"],
        }

        domains = extractor.extract_domains_from_csp(directives)

        assert len(domains) == 3
        assert "cdn.example.com" in domains
        assert "api.example.com" in domains
        assert "fonts.googleapis.com" in domains

    def test_extract_domains_filters_keywords(self):
        """Test that CSP keywords are filtered out."""
        extractor = CSPExtractor()
        directives = {
            "script-src": ["'self'", "'unsafe-inline'", "https://example.com", "data:", "blob:"]
        }

        domains = extractor.extract_domains_from_csp(directives)

        assert len(domains) == 1
        assert domains[0] == "example.com"

    def test_extract_domains_filters_nonces(self):
        """Test that nonce values are filtered out."""
        extractor = CSPExtractor()
        directives = {"script-src": ["'nonce-abc123'", "'sha256-xyz'", "https://example.com"]}

        domains = extractor.extract_domains_from_csp(directives)

        assert len(domains) == 1
        assert "example.com" in domains

    def test_extract_domains_from_multiple_directives(self):
        """Test extracting from multiple CSP directives."""
        extractor = CSPExtractor()
        directives = {
            "script-src": ["https://script.example.com"],
            "style-src": ["https://style.example.com"],
            "img-src": ["https://images.example.com"],
            "connect-src": ["wss://socket.example.com"],
            "font-src": ["https://fonts.example.com"],
        }

        domains = extractor.extract_domains_from_csp(directives)

        assert len(domains) == 5
        assert "script.example.com" in domains
        assert "socket.example.com" in domains

    def test_extract_domains_ignores_non_domain_directives(self):
        """Test that non-domain directives are ignored."""
        extractor = CSPExtractor()
        directives = {
            "script-src": ["https://example.com"],
            "report-uri": ["/csp-report"],  # Not a domain directive
            "upgrade-insecure-requests": [],  # Not a domain directive
        }

        domains = extractor.extract_domains_from_csp(directives)

        assert len(domains) == 1
        assert "example.com" in domains

    def test_extract_domains_deduplicates(self):
        """Test that duplicate domains are removed."""
        extractor = CSPExtractor()
        directives = {
            "script-src": ["https://example.com"],
            "style-src": ["https://example.com"],
            "img-src": ["example.com"],
        }

        domains = extractor.extract_domains_from_csp(directives)

        assert len(domains) == 1
        assert "example.com" in domains

    def test_extract_domains_empty_directives(self):
        """Test extracting from empty directives."""
        extractor = CSPExtractor()
        domains = extractor.extract_domains_from_csp({})
        assert domains == []

    def test_extract_domains_wildcard_subdomains(self):
        """Test extracting wildcard subdomains."""
        extractor = CSPExtractor()
        directives = {"script-src": ["*.example.com", "*.cdn.example.net"]}

        domains = extractor.extract_domains_from_csp(directives)

        assert len(domains) == 2
        assert "*.example.com" in domains
        assert "*.cdn.example.net" in domains

    def test_extract_domains_sorted(self):
        """Test that extracted domains are sorted."""
        extractor = CSPExtractor()
        directives = {"script-src": ["zebra.com", "apple.com", "microsoft.com"]}

        domains = extractor.extract_domains_from_csp(directives)

        assert domains == ["apple.com", "microsoft.com", "zebra.com"]


class TestCSPIntegration:
    """Integration tests for CSP parsing and extraction."""

    def test_full_csp_pipeline(self):
        """Test complete CSP parsing and domain extraction pipeline."""
        extractor = CSPExtractor()

        # Real-world-like CSP header
        csp_header = """
        default-src 'self';
        script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://code.jquery.com *.googletagmanager.com;
        style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
        font-src 'self' https://fonts.gstatic.com data:;
        img-src 'self' data: blob: https:;
        connect-src 'self' wss://socket.example.com https://api.example.com;
        frame-src 'none';
        object-src 'none'
        """

        # Parse
        directives = extractor.parse_csp_header(csp_header)

        # Extract domains
        domains = extractor.extract_domains_from_csp(directives)

        # Verify
        assert "cdn.jsdelivr.net" in domains
        assert "code.jquery.com" in domains
        assert "fonts.googleapis.com" in domains
        assert "fonts.gstatic.com" in domains
        assert "socket.example.com" in domains
        assert "api.example.com" in domains
        assert "*.googletagmanager.com" in domains

        # Keywords should not be in domains
        assert "'self'" not in domains
        assert "'unsafe-inline'" not in domains
        assert "'none'" not in domains
        assert "data:" not in domains
        assert "blob:" not in domains

    def test_csp_with_mixed_formats(self):
        """Test CSP with mixed URL formats."""
        extractor = CSPExtractor()

        csp_header = """
        script-src
            https://full-url.com/path
            //scheme-relative.com
            just-domain.com
            *.wildcard.com
            port.com:8080
            wss://websocket.com
        """

        directives = extractor.parse_csp_header(csp_header)
        domains = extractor.extract_domains_from_csp(directives)

        assert "full-url.com" in domains
        assert "scheme-relative.com" in domains
        assert "just-domain.com" in domains
        assert "*.wildcard.com" in domains
        assert "port.com" in domains
        assert "websocket.com" in domains


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_malformed_csp(self):
        """Test handling malformed CSP headers."""
        extractor = CSPExtractor()

        # Missing semicolons, weird spacing
        csp = "default-src 'self' script-src https://example.com"
        directives = extractor.parse_csp_header(csp)

        # Should still parse what it can
        assert len(directives) >= 1

    def test_csp_with_special_characters(self):
        """Test CSP with special characters."""
        extractor = CSPExtractor()
        csp = "script-src https://example.com/path?query=value&foo=bar"

        directives = extractor.parse_csp_header(csp)
        domains = extractor.extract_domains_from_csp(directives)

        assert "example.com" in domains

    def test_very_long_csp(self):
        """Test handling very long CSP headers."""
        extractor = CSPExtractor()

        # Generate CSP with many domains
        domains_list = [f"domain{i}.com" for i in range(100)]
        csp = f"script-src {' '.join(domains_list)}"

        directives = extractor.parse_csp_header(csp)
        domains = extractor.extract_domains_from_csp(directives)

        assert len(domains) == 100

    def test_csp_case_insensitivity(self):
        """Test that directive names are case-insensitive."""
        extractor = CSPExtractor()
        csp = "SCRIPT-SRC https://example.com; Style-Src https://style.com"

        directives = extractor.parse_csp_header(csp)

        # Directives should be lowercase
        assert "script-src" in directives
        assert "style-src" in directives

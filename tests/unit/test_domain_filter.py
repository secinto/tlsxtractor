"""
Unit tests for domain filtering module.
"""

import pytest
from pathlib import Path
from tlsxtractor.domain_filter import DomainFilter


class TestDomainFilterInitialization:
    """Test DomainFilter initialization."""

    def test_initialization_with_defaults(self):
        """Test initialization with default exclusions."""
        filter_obj = DomainFilter()

        # Should have default exclusions loaded
        assert filter_obj.should_filter("cloudflare.com") is True
        assert filter_obj.should_filter("googleapis.com") is True

        # Count should reflect the checks made above
        assert filter_obj.get_filtered_count() == 2

        # Reset and verify
        filter_obj.reset_count()
        assert filter_obj.get_filtered_count() == 0

    def test_initialization_without_defaults(self):
        """Test initialization without defaults."""
        filter_obj = DomainFilter(use_defaults=False)

        # Should not filter default patterns
        assert filter_obj.should_filter("cloudflare.com") is False
        assert filter_obj.should_filter("googleapis.com") is False

    def test_initialization_with_custom_exclusions(self):
        """Test initialization with custom exclusions."""
        custom = ["example.com", "test.com"]
        filter_obj = DomainFilter(use_defaults=False, custom_exclusions=custom)

        assert filter_obj.should_filter("example.com") is True
        assert filter_obj.should_filter("test.com") is True
        assert filter_obj.should_filter("other.com") is False

    def test_initialization_with_mixed_exclusions(self):
        """Test initialization with both defaults and custom."""
        custom = ["mycompany.com"]
        filter_obj = DomainFilter(use_defaults=True, custom_exclusions=custom)

        # Default patterns should work
        assert filter_obj.should_filter("cloudflare.com") is True
        # Custom patterns should work
        assert filter_obj.should_filter("mycompany.com") is True

    def test_initialization_with_regex_disabled(self):
        """Test that regex is disabled by default."""
        filter_obj = DomainFilter()

        # Regex patterns should not work when disabled
        filter_obj.add_exclusions(["^test.*\\.com$"])
        assert filter_obj.should_filter("test123.com") is False

    def test_initialization_with_regex_enabled(self):
        """Test initialization with regex enabled."""
        filter_obj = DomainFilter(enable_regex=True)
        filter_obj.add_exclusions(["^test.*\\.com$"])

        # Regex patterns should work when enabled
        assert filter_obj.should_filter("test123.com") is True


class TestExactMatching:
    """Test exact domain matching."""

    def test_exact_match_simple(self):
        """Test simple exact domain matching."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["example.com"])

        assert filter_obj.should_filter("example.com") is True
        assert filter_obj.should_filter("test.com") is False

    def test_exact_match_case_insensitive(self):
        """Test case-insensitive matching."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["Example.COM"])

        assert filter_obj.should_filter("example.com") is True
        assert filter_obj.should_filter("EXAMPLE.COM") is True
        assert filter_obj.should_filter("ExAmPlE.cOm") is True

    def test_exact_match_subdomain_not_matched(self):
        """Test that exact match doesn't match subdomains."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["example.com"])

        assert filter_obj.should_filter("example.com") is True
        assert filter_obj.should_filter("sub.example.com") is False

    def test_exact_match_multiple_domains(self):
        """Test filtering multiple exact domains."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["cdn.com", "analytics.com", "ads.com"])

        assert filter_obj.should_filter("cdn.com") is True
        assert filter_obj.should_filter("analytics.com") is True
        assert filter_obj.should_filter("ads.com") is True
        assert filter_obj.should_filter("example.com") is False


class TestWildcardMatching:
    """Test wildcard pattern matching."""

    def test_wildcard_prefix_match(self):
        """Test wildcard prefix matching."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["*.example.com"])

        assert filter_obj.should_filter("sub.example.com") is True
        assert filter_obj.should_filter("api.example.com") is True
        assert filter_obj.should_filter("cdn.api.example.com") is True
        assert filter_obj.should_filter("example.com") is False  # Wildcard doesn't match root

    def test_wildcard_suffix_match(self):
        """Test wildcard suffix matching."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["cdn.*"])

        assert filter_obj.should_filter("cdn.example.com") is True
        assert filter_obj.should_filter("cdn.test.org") is True
        assert filter_obj.should_filter("api.cdn.com") is False

    def test_wildcard_middle_match(self):
        """Test wildcard in middle of pattern."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["api.*.example.com"])

        assert filter_obj.should_filter("api.v1.example.com") is True
        assert filter_obj.should_filter("api.v2.example.com") is True
        assert filter_obj.should_filter("api.example.com") is False

    def test_wildcard_multiple_asterisks(self):
        """Test pattern with multiple wildcards."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["*.cdn.*.com"])

        assert filter_obj.should_filter("sub.cdn.example.com") is True
        assert filter_obj.should_filter("api.cdn.test.com") is True

    def test_wildcard_case_insensitive(self):
        """Test wildcard matching is case-insensitive."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["*.Example.COM"])

        assert filter_obj.should_filter("sub.example.com") is True
        assert filter_obj.should_filter("API.EXAMPLE.COM") is True


class TestRegexMatching:
    """Test regex pattern matching."""

    def test_regex_simple_pattern(self):
        """Test simple regex pattern."""
        filter_obj = DomainFilter(use_defaults=False, enable_regex=True)
        filter_obj.add_exclusions(["^test.*\\.com$"])

        assert filter_obj.should_filter("test.com") is True
        assert filter_obj.should_filter("test123.com") is True
        assert filter_obj.should_filter("testing.com") is True
        assert filter_obj.should_filter("test.org") is False

    def test_regex_complex_pattern(self):
        """Test complex regex pattern."""
        filter_obj = DomainFilter(use_defaults=False, enable_regex=True)
        filter_obj.add_exclusions([r"^(cdn|api|static)\d+\.example\.com$"])

        assert filter_obj.should_filter("cdn1.example.com") is True
        assert filter_obj.should_filter("api42.example.com") is True
        assert filter_obj.should_filter("static9.example.com") is True
        assert filter_obj.should_filter("web.example.com") is False

    def test_regex_disabled_by_default(self):
        """Test that regex patterns don't work when disabled."""
        filter_obj = DomainFilter(use_defaults=False, enable_regex=False)
        filter_obj.add_exclusions(["^test.*\\.com$"])

        # Should not match because regex is disabled
        assert filter_obj.should_filter("test.com") is False
        assert filter_obj.should_filter("testing.com") is False

    def test_regex_case_insensitive(self):
        """Test regex matching is case-insensitive."""
        filter_obj = DomainFilter(use_defaults=False, enable_regex=True)
        filter_obj.add_exclusions(["^test\\.com$"])

        assert filter_obj.should_filter("test.com") is True
        assert filter_obj.should_filter("TEST.COM") is True
        assert filter_obj.should_filter("Test.Com") is True


class TestFilterDomains:
    """Test batch domain filtering."""

    def test_filter_domains_empty_list(self):
        """Test filtering empty domain list."""
        filter_obj = DomainFilter(use_defaults=False)
        result = filter_obj.filter_domains([])

        assert result == []
        assert filter_obj.get_filtered_count() == 0

    def test_filter_domains_no_matches(self):
        """Test filtering with no matches."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["cdn.com"])

        domains = ["example.com", "test.com", "api.com"]
        result = filter_obj.filter_domains(domains)

        assert len(result) == 3
        assert set(result) == set(domains)
        assert filter_obj.get_filtered_count() == 0

    def test_filter_domains_all_filtered(self):
        """Test filtering where all domains are filtered."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["cdn.com", "analytics.com", "ads.com"])

        domains = ["cdn.com", "analytics.com", "ads.com"]
        result = filter_obj.filter_domains(domains)

        assert len(result) == 0
        assert filter_obj.get_filtered_count() == 3

    def test_filter_domains_mixed_results(self):
        """Test filtering with mixed results."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["cdn.com", "analytics.com"])

        domains = ["cdn.com", "example.com", "analytics.com", "test.com"]
        result = filter_obj.filter_domains(domains)

        assert len(result) == 2
        assert "example.com" in result
        assert "test.com" in result
        assert filter_obj.get_filtered_count() == 2

    def test_filter_domains_with_wildcards(self):
        """Test batch filtering with wildcard patterns."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["*.cloudflare.com", "*.google.com"])

        domains = [
            "cdn.cloudflare.com",
            "example.com",
            "fonts.google.com",
            "test.com"
        ]
        result = filter_obj.filter_domains(domains)

        assert len(result) == 2
        assert "example.com" in result
        assert "test.com" in result
        assert filter_obj.get_filtered_count() == 2

    def test_filter_domains_preserves_order(self):
        """Test that filtering preserves domain order."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["b.com", "d.com"])

        domains = ["a.com", "b.com", "c.com", "d.com", "e.com"]
        result = filter_obj.filter_domains(domains)

        assert result == ["a.com", "c.com", "e.com"]

    def test_filter_domains_duplicates(self):
        """Test filtering with duplicate domains."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["cdn.com"])

        domains = ["example.com", "cdn.com", "example.com", "cdn.com"]
        result = filter_obj.filter_domains(domains)

        # Should preserve duplicates in output
        assert result.count("example.com") == 2
        assert filter_obj.get_filtered_count() == 2


class TestFilteredCount:
    """Test filtered count tracking."""

    def test_initial_count_zero(self):
        """Test initial filtered count is zero."""
        filter_obj = DomainFilter()
        assert filter_obj.get_filtered_count() == 0

    def test_count_increments_on_filter(self):
        """Test count increments when domains are filtered."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["cdn.com"])

        filter_obj.filter_domains(["cdn.com", "example.com"])
        assert filter_obj.get_filtered_count() == 1

    def test_count_accumulates(self):
        """Test count accumulates across multiple filter calls."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["cdn.com"])

        filter_obj.filter_domains(["cdn.com", "example.com"])
        filter_obj.filter_domains(["cdn.com", "test.com"])
        filter_obj.filter_domains(["api.com"])

        assert filter_obj.get_filtered_count() == 2

    def test_reset_count(self):
        """Test resetting filtered count."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["cdn.com"])

        filter_obj.filter_domains(["cdn.com", "example.com"])
        assert filter_obj.get_filtered_count() == 1

        filter_obj.reset_count()
        assert filter_obj.get_filtered_count() == 0


class TestAddExclusions:
    """Test adding exclusions dynamically."""

    def test_add_single_exclusion(self):
        """Test adding single exclusion."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["example.com"])

        assert filter_obj.should_filter("example.com") is True

    def test_add_multiple_exclusions(self):
        """Test adding multiple exclusions at once."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["cdn.com", "analytics.com", "ads.com"])

        assert filter_obj.should_filter("cdn.com") is True
        assert filter_obj.should_filter("analytics.com") is True
        assert filter_obj.should_filter("ads.com") is True

    def test_add_exclusions_incrementally(self):
        """Test adding exclusions in multiple calls."""
        filter_obj = DomainFilter(use_defaults=False)

        filter_obj.add_exclusions(["cdn.com"])
        assert filter_obj.should_filter("cdn.com") is True

        filter_obj.add_exclusions(["analytics.com"])
        assert filter_obj.should_filter("analytics.com") is True

    def test_add_duplicate_exclusions(self):
        """Test adding duplicate exclusions."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["example.com"])
        filter_obj.add_exclusions(["example.com"])

        # Should still work, just deduplicated internally
        assert filter_obj.should_filter("example.com") is True

    def test_add_empty_list(self):
        """Test adding empty exclusion list."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions([])

        # Should not cause errors
        assert filter_obj.get_filtered_count() == 0


class TestFactoryMethods:
    """Test factory methods for creating filters."""

    def test_from_file(self, tmp_path):
        """Test creating filter from file."""
        # Create temporary exclusion file
        exclusion_file = tmp_path / "exclusions.txt"
        exclusion_file.write_text("cdn.com\nanalytics.com\n*.google.com\n")

        filter_obj = DomainFilter.from_file(exclusion_file)

        assert filter_obj.should_filter("cdn.com") is True
        assert filter_obj.should_filter("analytics.com") is True
        assert filter_obj.should_filter("fonts.google.com") is True

    def test_from_file_with_comments(self, tmp_path):
        """Test file parsing with comments."""
        exclusion_file = tmp_path / "exclusions.txt"
        exclusion_file.write_text(
            "# CDN domains\n"
            "cdn.com\n"
            "# Analytics\n"
            "analytics.com\n"
            "\n"  # Empty line
            "ads.com\n"
        )

        filter_obj = DomainFilter.from_file(exclusion_file, use_defaults=False)

        assert filter_obj.should_filter("cdn.com") is True
        assert filter_obj.should_filter("analytics.com") is True
        assert filter_obj.should_filter("ads.com") is True

    def test_from_file_with_whitespace(self, tmp_path):
        """Test file parsing handles whitespace."""
        exclusion_file = tmp_path / "exclusions.txt"
        exclusion_file.write_text("  cdn.com  \n\n  analytics.com\n")

        filter_obj = DomainFilter.from_file(exclusion_file, use_defaults=False)

        assert filter_obj.should_filter("cdn.com") is True
        assert filter_obj.should_filter("analytics.com") is True

    def test_from_file_without_defaults(self, tmp_path):
        """Test creating filter from file without defaults."""
        exclusion_file = tmp_path / "exclusions.txt"
        exclusion_file.write_text("custom.com\n")

        filter_obj = DomainFilter.from_file(exclusion_file, use_defaults=False)

        assert filter_obj.should_filter("custom.com") is True
        assert filter_obj.should_filter("cloudflare.com") is False

    def test_from_comma_separated_simple(self):
        """Test creating filter from comma-separated string."""
        filter_obj = DomainFilter.from_comma_separated(
            "cdn.com,analytics.com,ads.com",
            use_defaults=False
        )

        assert filter_obj.should_filter("cdn.com") is True
        assert filter_obj.should_filter("analytics.com") is True
        assert filter_obj.should_filter("ads.com") is True

    def test_from_comma_separated_with_whitespace(self):
        """Test CSV parsing handles whitespace."""
        filter_obj = DomainFilter.from_comma_separated(
            "cdn.com , analytics.com , ads.com",
            use_defaults=False
        )

        assert filter_obj.should_filter("cdn.com") is True
        assert filter_obj.should_filter("analytics.com") is True
        assert filter_obj.should_filter("ads.com") is True

    def test_from_comma_separated_with_wildcards(self):
        """Test CSV parsing with wildcard patterns."""
        filter_obj = DomainFilter.from_comma_separated(
            "*.cloudflare.com,*.google.com",
            use_defaults=False
        )

        assert filter_obj.should_filter("cdn.cloudflare.com") is True
        assert filter_obj.should_filter("fonts.google.com") is True

    def test_from_comma_separated_empty_string(self):
        """Test CSV parsing with empty string."""
        filter_obj = DomainFilter.from_comma_separated("", use_defaults=False)

        # Should create filter with no exclusions
        assert filter_obj.should_filter("anything.com") is False


class TestDefaultExclusions:
    """Test default exclusion patterns."""

    def test_default_cdn_exclusions(self):
        """Test default CDN exclusions."""
        filter_obj = DomainFilter()

        assert filter_obj.should_filter("cloudflare.com") is True
        assert filter_obj.should_filter("cdn.cloudflare.com") is True
        assert filter_obj.should_filter("akamaiedge.net") is True

    def test_default_analytics_exclusions(self):
        """Test default analytics exclusions."""
        filter_obj = DomainFilter()

        assert filter_obj.should_filter("google-analytics.com") is True
        assert filter_obj.should_filter("googletagmanager.com") is True

    def test_default_ad_exclusions(self):
        """Test default advertising exclusions."""
        filter_obj = DomainFilter()

        assert filter_obj.should_filter("doubleclick.net") is True
        assert filter_obj.should_filter("googlesyndication.com") is True

    def test_default_social_exclusions(self):
        """Test default social media exclusions."""
        filter_obj = DomainFilter()

        assert filter_obj.should_filter("facebook.com") is True
        assert filter_obj.should_filter("twitter.com") is True

    def test_default_google_services_exclusions(self):
        """Test default Google services exclusions."""
        filter_obj = DomainFilter()

        assert filter_obj.should_filter("googleapis.com") is True
        assert filter_obj.should_filter("gstatic.com") is True

    def test_can_override_defaults(self):
        """Test that custom exclusions work alongside defaults."""
        filter_obj = DomainFilter()
        filter_obj.add_exclusions(["mycompany.com"])

        # Defaults still work
        assert filter_obj.should_filter("cloudflare.com") is True
        # Custom works too
        assert filter_obj.should_filter("mycompany.com") is True


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_empty_domain_string(self):
        """Test filtering empty domain string."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["example.com"])

        assert filter_obj.should_filter("") is False

    def test_none_domain(self):
        """Test filtering None domain."""
        filter_obj = DomainFilter(use_defaults=False)

        # Should not crash
        result = filter_obj.should_filter(None)
        assert result is False

    def test_domain_with_port(self):
        """Test filtering domain with port number."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["example.com"])

        # Port should be ignored/handled gracefully
        assert filter_obj.should_filter("example.com:443") is False

    def test_domain_with_protocol(self):
        """Test filtering domain with protocol."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["example.com"])

        # Protocol should be ignored/handled gracefully
        assert filter_obj.should_filter("https://example.com") is False

    def test_very_long_domain(self):
        """Test filtering very long domain name."""
        filter_obj = DomainFilter(use_defaults=False)
        long_domain = "sub." * 50 + "example.com"
        filter_obj.add_exclusions([long_domain])

        assert filter_obj.should_filter(long_domain) is True

    def test_unicode_domain(self):
        """Test filtering internationalized domain."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["例え.jp"])

        assert filter_obj.should_filter("例え.jp") is True

    def test_invalid_wildcard_only(self):
        """Test pattern with only wildcards."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["*"])

        # Should not match everything
        assert filter_obj.should_filter("example.com") is True

    def test_special_characters_in_domain(self):
        """Test domain with special characters."""
        filter_obj = DomainFilter(use_defaults=False)
        filter_obj.add_exclusions(["example-cdn.com"])

        assert filter_obj.should_filter("example-cdn.com") is True
        assert filter_obj.should_filter("example_cdn.com") is False
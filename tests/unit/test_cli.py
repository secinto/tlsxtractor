"""
Unit tests for CLI module.
"""

import pytest
import argparse
from unittest.mock import Mock, patch, AsyncMock
from pathlib import Path
from tlsxtractor.cli import (
    create_parser,
    validate_args,
    create_domain_filter,
    main,
)


class TestArgumentParser:
    """Test command-line argument parsing."""

    def test_create_parser_returns_parser(self):
        """Test that create_parser returns ArgumentParser instance."""
        parser = create_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_parser_requires_input(self):
        """Test that parser requires either --cidr or --file."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_parser_accepts_cidr(self):
        """Test that parser accepts --cidr argument."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24"])
        assert args.cidr == "192.168.1.0/24"

    def test_parser_accepts_file(self):
        """Test that parser accepts --file argument."""
        parser = create_parser()
        args = parser.parse_args(["--file", "targets.txt"])
        assert args.file == "targets.txt"

    def test_parser_cidr_and_file_mutually_exclusive(self):
        """Test that --cidr and --file are mutually exclusive."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--cidr", "192.168.1.0/24", "--file", "targets.txt"])

    def test_parser_default_output(self):
        """Test that parser has default output value."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24"])
        assert args.output == "results.json"

    def test_parser_custom_output(self):
        """Test that parser accepts custom output path."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24", "--output", "custom.json"])
        assert args.output == "custom.json"

    def test_parser_default_threads(self):
        """Test that parser has default thread count."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24"])
        assert args.threads == 10

    def test_parser_custom_threads(self):
        """Test that parser accepts custom thread count."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24", "--threads", "20"])
        assert args.threads == 20

    def test_parser_default_rate_limit(self):
        """Test that parser has default rate limit."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24"])
        assert args.rate_limit == 10.0

    def test_parser_custom_rate_limit(self):
        """Test that parser accepts custom rate limit."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24", "--rate-limit", "5.5"])
        assert args.rate_limit == 5.5

    def test_parser_default_timeout(self):
        """Test that parser has default timeout."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24"])
        assert args.timeout == 5

    def test_parser_custom_timeout(self):
        """Test that parser accepts custom timeout."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24", "--timeout", "10"])
        assert args.timeout == 10

    def test_parser_default_port(self):
        """Test that parser has default port."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24"])
        assert args.port == 443

    def test_parser_custom_port(self):
        """Test that parser accepts custom port."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24", "--port", "8443"])
        assert args.port == 8443

    def test_parser_default_retry(self):
        """Test that parser has default retry count."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24"])
        assert args.retry == 3

    def test_parser_custom_retry(self):
        """Test that parser accepts custom retry count."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24", "--retry", "5"])
        assert args.retry == 5

    def test_parser_fetch_csp_flag(self):
        """Test that parser accepts --fetch-csp flag."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24", "--fetch-csp"])
        assert args.fetch_csp is True

    def test_parser_allow_private_flag(self):
        """Test that parser accepts --allow-private flag."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24", "--allow-private"])
        assert args.allow_private is True

    def test_parser_quiet_flag(self):
        """Test that parser accepts --quiet flag."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24", "--quiet"])
        assert args.quiet is True

    def test_parser_log_level(self):
        """Test that parser accepts log level."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24", "--log-level", "debug"])
        assert args.log_level == "debug"

    def test_parser_log_file(self):
        """Test that parser accepts log file path."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24", "--log-file", "scan.log"])
        assert args.log_file == "scan.log"

    def test_parser_exclude_domains(self):
        """Test that parser accepts exclude domains."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24", "--exclude-domains", "example.com"])
        assert args.exclude_domains == "example.com"

    def test_parser_no_default_exclusions_flag(self):
        """Test that parser accepts --no-default-exclusions flag."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24", "--no-default-exclusions"])
        assert args.no_default_exclusions is True

    def test_parser_version(self):
        """Test that parser has version argument."""
        parser = create_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--version"])
        assert exc_info.value.code == 0


class TestArgumentValidation:
    """Test argument validation logic."""

    def test_validate_args_valid_returns_none(self):
        """Test that validation returns None for valid arguments."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24"])
        error = validate_args(args)
        assert error is None

    def test_validate_args_invalid_port_low(self):
        """Test that validation catches port below range."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24", "--port", "0"])
        error = validate_args(args)
        assert error is not None
        assert "port" in error.lower()

    def test_validate_args_invalid_port_high(self):
        """Test that validation catches port above range."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24", "--port", "65536"])
        error = validate_args(args)
        assert error is not None
        assert "port" in error.lower()

    def test_validate_args_invalid_threads_low(self):
        """Test that validation catches thread count below 1."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24", "--threads", "0"])
        error = validate_args(args)
        assert error is not None
        assert "thread" in error.lower()

    def test_validate_args_invalid_threads_high(self):
        """Test that validation warns about high thread count."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24", "--threads", "1001"])
        error = validate_args(args)
        assert error is not None
        assert "thread" in error.lower()

    def test_validate_args_invalid_rate_limit(self):
        """Test that validation catches negative rate limit."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24", "--rate-limit", "-1"])
        error = validate_args(args)
        assert error is not None
        assert "rate limit" in error.lower()

    def test_validate_args_invalid_timeout(self):
        """Test that validation catches timeout below 1."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24", "--timeout", "0"])
        error = validate_args(args)
        assert error is not None
        assert "timeout" in error.lower()

    def test_validate_args_invalid_retry(self):
        """Test that validation catches negative retry count."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24", "--retry", "-1"])
        error = validate_args(args)
        assert error is not None
        assert "retry" in error.lower()


class TestDomainFilter:
    """Test domain filter creation."""

    def test_create_domain_filter_no_exclusions(self):
        """Test creating filter with no exclusions."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24", "--no-default-exclusions"])
        domain_filter = create_domain_filter(args)
        assert domain_filter is None

    def test_create_domain_filter_defaults_only(self):
        """Test creating filter with only defaults."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24"])
        domain_filter = create_domain_filter(args)
        assert domain_filter is not None

    def test_create_domain_filter_with_csv(self):
        """Test creating filter with CSV domains."""
        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24", "--exclude-domains", "example.com,test.com"])
        domain_filter = create_domain_filter(args)
        assert domain_filter is not None

    def test_create_domain_filter_with_file(self, tmp_path):
        """Test creating filter with file."""
        # Create temporary exclusion file
        exclusion_file = tmp_path / "exclusions.txt"
        exclusion_file.write_text("example.com\ntest.com\n")

        parser = create_parser()
        args = parser.parse_args(["--cidr", "192.168.1.0/24", "--exclude-domains", str(exclusion_file)])
        domain_filter = create_domain_filter(args)
        assert domain_filter is not None


class TestMainFunction:
    """Test main entry point function."""

    @patch('tlsxtractor.cli.asyncio.run')
    @patch('tlsxtractor.cli.ConsoleOutput')
    def test_main_success_returns_zero(self, mock_console, mock_asyncio_run):
        """Test that main returns 0 on success."""
        mock_asyncio_run.return_value = 0

        with patch('sys.argv', ['tlsxtractor', '--cidr', '192.168.1.0/24']):
            exit_code = main()

        assert exit_code == 0
        mock_asyncio_run.assert_called_once()

    @patch('tlsxtractor.cli.asyncio.run')
    @patch('tlsxtractor.cli.ConsoleOutput')
    def test_main_validation_error_returns_one(self, mock_console, mock_asyncio_run):
        """Test that main returns 1 on validation error."""
        with patch('sys.argv', ['tlsxtractor', '--cidr', '192.168.1.0/24', '--port', '0']):
            exit_code = main()

        assert exit_code == 1
        mock_asyncio_run.assert_not_called()

    @patch('tlsxtractor.cli.asyncio.run')
    @patch('tlsxtractor.cli.ConsoleOutput')
    def test_main_keyboard_interrupt_returns_130(self, mock_console, mock_asyncio_run):
        """Test that main returns 130 on KeyboardInterrupt."""
        mock_asyncio_run.side_effect = KeyboardInterrupt()

        with patch('sys.argv', ['tlsxtractor', '--cidr', '192.168.1.0/24']):
            exit_code = main()

        assert exit_code == 130

    @patch('tlsxtractor.cli.asyncio.run')
    @patch('tlsxtractor.cli.ConsoleOutput')
    def test_main_exception_returns_one(self, mock_console, mock_asyncio_run):
        """Test that main returns 1 on exception."""
        mock_asyncio_run.side_effect = Exception("Test error")

        with patch('sys.argv', ['tlsxtractor', '--cidr', '192.168.1.0/24']):
            exit_code = main()

        assert exit_code == 1

    @patch('tlsxtractor.cli.asyncio.run')
    @patch('tlsxtractor.cli.ConsoleOutput')
    @patch('tlsxtractor.cli.logging.basicConfig')
    def test_main_configures_logging(self, mock_logging_config, mock_console, mock_asyncio_run):
        """Test that main configures logging."""
        mock_asyncio_run.return_value = 0

        with patch('sys.argv', ['tlsxtractor', '--cidr', '192.168.1.0/24', '--log-level', 'debug']):
            main()

        mock_logging_config.assert_called_once()

    @patch('tlsxtractor.cli.asyncio.run')
    @patch('tlsxtractor.cli.ConsoleOutput')
    def test_main_creates_console_output(self, mock_console, mock_asyncio_run):
        """Test that main creates ConsoleOutput instance."""
        mock_asyncio_run.return_value = 0

        with patch('sys.argv', ['tlsxtractor', '--cidr', '192.168.1.0/24', '--quiet']):
            main()

        mock_console.assert_called_once()
        args, kwargs = mock_console.call_args
        if args:
            assert args[0] is True  # quiet=True
        else:
            assert kwargs.get('quiet') is True


class TestCLIIntegration:
    """Integration tests for CLI module."""

    def test_full_argument_parsing(self):
        """Test parsing all arguments together."""
        parser = create_parser()
        args = parser.parse_args([
            "--cidr", "192.168.1.0/24",
            "--output", "results.json",
            "--threads", "20",
            "--rate-limit", "15",
            "--timeout", "10",
            "--port", "8443",
            "--retry", "5",
            "--fetch-csp",
            "--allow-private",
            "--exclude-domains", "example.com,test.com",
            "--log-level", "debug",
            "--log-file", "scan.log",
            "--quiet",
        ])

        assert args.cidr == "192.168.1.0/24"
        assert args.output == "results.json"
        assert args.threads == 20
        assert args.rate_limit == 15.0
        assert args.timeout == 10
        assert args.port == 8443
        assert args.retry == 5
        assert args.fetch_csp is True
        assert args.allow_private is True
        assert args.exclude_domains == "example.com,test.com"
        assert args.log_level == "debug"
        assert args.log_file == "scan.log"
        assert args.quiet is True

        # Validation should pass
        error = validate_args(args)
        assert error is None

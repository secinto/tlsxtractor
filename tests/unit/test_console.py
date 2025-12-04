"""
Unit tests for console output module.
"""

import time
from unittest.mock import patch

from tlsxtractor.console import ConsoleOutput, ScanStatistics


class TestScanStatistics:
    """Test ScanStatistics data class."""

    def test_statistics_initialization(self):
        """Test statistics initialization with default values."""
        stats = ScanStatistics()
        assert stats.total_targets == 0
        assert stats.scanned == 0
        assert stats.successful == 0
        assert stats.failed == 0
        assert stats.domains_found == 0
        assert stats.start_time > 0

    def test_statistics_with_values(self):
        """Test statistics initialization with custom values."""
        start = time.time()
        stats = ScanStatistics(
            total_targets=100,
            scanned=50,
            successful=45,
            failed=5,
            domains_found=200,
            start_time=start,
        )
        assert stats.total_targets == 100
        assert stats.scanned == 50
        assert stats.successful == 45
        assert stats.failed == 5
        assert stats.domains_found == 200
        assert stats.start_time == start

    def test_elapsed_time_calculation(self):
        """Test elapsed time calculation."""
        start = time.time() - 10  # 10 seconds ago
        stats = ScanStatistics(start_time=start)

        elapsed = stats.elapsed_time
        assert elapsed >= 10
        assert elapsed < 11  # Should be close to 10 seconds

    def test_scan_rate_calculation(self):
        """Test scan rate calculation."""
        start = time.time() - 10  # 10 seconds ago
        stats = ScanStatistics(scanned=100, start_time=start)

        rate = stats.scan_rate
        assert rate >= 9  # ~10 scans/second
        assert rate <= 11

    def test_scan_rate_zero_elapsed(self):
        """Test scan rate when no time has elapsed."""
        stats = ScanStatistics(scanned=100)
        # Immediately check rate
        rate = stats.scan_rate
        # Should return a very high rate or handle gracefully
        assert rate >= 0

    def test_eta_calculation(self):
        """Test ETA calculation."""
        start = time.time() - 10  # 10 seconds ago
        stats = ScanStatistics(
            total_targets=100,
            scanned=50,
            start_time=start,
        )

        eta = stats.eta_seconds
        assert eta is not None
        assert eta >= 9  # Should be ~10 seconds remaining
        assert eta <= 11

    def test_eta_no_scans(self):
        """Test ETA when no scans completed."""
        stats = ScanStatistics(total_targets=100, scanned=0)
        eta = stats.eta_seconds
        assert eta is None

    def test_eta_completed(self):
        """Test ETA when all scans completed."""
        stats = ScanStatistics(total_targets=100, scanned=100)
        eta = stats.eta_seconds
        assert eta is None

    def test_progress_percentage(self):
        """Test progress percentage calculation."""
        stats = ScanStatistics(total_targets=100, scanned=50)
        progress = stats.progress_percentage
        assert progress == 50.0

    def test_progress_percentage_zero_targets(self):
        """Test progress percentage with zero targets."""
        stats = ScanStatistics(total_targets=0, scanned=0)
        progress = stats.progress_percentage
        assert progress == 0.0

    def test_progress_percentage_complete(self):
        """Test progress percentage when complete."""
        stats = ScanStatistics(total_targets=100, scanned=100)
        progress = stats.progress_percentage
        assert progress == 100.0


class TestConsoleOutput:
    """Test ConsoleOutput class."""

    def test_console_output_initialization(self):
        """Test console output initialization."""
        console = ConsoleOutput()
        assert console.quiet is False
        assert hasattr(console, "_lock")

    def test_console_output_quiet_mode(self):
        """Test console output in quiet mode."""
        console = ConsoleOutput(quiet=True)
        assert console.quiet is True

    def test_supports_color_detection(self):
        """Test color support detection."""
        # Test static method
        supports_color = ConsoleOutput._supports_color()
        assert isinstance(supports_color, bool)

    @patch("sys.stdout.isatty")
    def test_supports_color_not_tty(self, mock_isatty):
        """Test color support when not a TTY."""
        mock_isatty.return_value = False
        supports_color = ConsoleOutput._supports_color()
        assert supports_color is False

    @patch("sys.stdout.isatty")
    @patch("os.environ.get")
    def test_supports_color_dumb_terminal(self, mock_env_get, mock_isatty):
        """Test color support with dumb terminal."""
        mock_isatty.return_value = True
        mock_env_get.return_value = "dumb"
        supports_color = ConsoleOutput._supports_color()
        assert supports_color is False

    def test_colorize_with_colors_enabled(self):
        """Test colorizing text with colors enabled."""
        console = ConsoleOutput(use_colors=True)
        console.use_colors = True  # Force enable
        colored = console._colorize("test", "32")
        assert "test" in colored

    def test_colorize_with_colors_disabled(self):
        """Test colorizing text with colors disabled."""
        console = ConsoleOutput(use_colors=False)
        colored = console._colorize("test", "32")
        assert colored == "test"

    @patch("sys.stdout.write")
    @patch("sys.stdout.flush")
    def test_info_output(self, mock_flush, mock_write):
        """Test info message output."""
        console = ConsoleOutput(quiet=False)
        console.info("Test message")
        mock_write.assert_called()

    @patch("sys.stdout.write")
    @patch("sys.stdout.flush")
    def test_info_output_quiet_mode(self, mock_flush, mock_write):
        """Test info message output in quiet mode."""
        console = ConsoleOutput(quiet=True)
        console.info("Test message")
        # Should not write in quiet mode
        mock_write.assert_not_called()

    @patch("sys.stderr.write")
    @patch("sys.stderr.flush")
    def test_error_output(self, mock_flush, mock_write):
        """Test error message output."""
        console = ConsoleOutput()
        console.error("Error message")
        mock_write.assert_called()

    @patch("sys.stderr.write")
    @patch("sys.stderr.flush")
    def test_warning_output(self, mock_flush, mock_write):
        """Test warning message output."""
        console = ConsoleOutput()
        console.warning("Warning message")
        mock_write.assert_called()

    @patch("sys.stdout.write")
    @patch("sys.stdout.flush")
    def test_success_output(self, mock_flush, mock_write):
        """Test success message output."""
        console = ConsoleOutput()
        console.success("Success message")
        mock_write.assert_called()

    def test_progress_update_throttling(self):
        """Test that progress updates are throttled."""
        console = ConsoleOutput(quiet=False)
        console._progress_update_interval = 1.0

        # First update should go through
        with patch.object(console, "_clear_line"):
            with patch("sys.stdout.write"):
                with patch("sys.stdout.flush"):
                    console.update_progress(ScanStatistics(total_targets=100, scanned=10))

        # Immediate second update should be throttled
        last_update = console._last_progress_update
        with patch.object(console, "_clear_line"):
            with patch("sys.stdout.write"):
                with patch("sys.stdout.flush"):
                    console.update_progress(ScanStatistics(total_targets=100, scanned=11))

        # Should use same last_update time (throttled)
        assert console._last_progress_update == last_update

    def test_format_eta_seconds(self):
        """Test ETA formatting."""
        console = ConsoleOutput()

        # Test with seconds
        formatted = console._format_eta(45)
        assert "45s" in formatted

        # Test with minutes
        formatted = console._format_eta(120)
        assert "2m" in formatted or "120s" in formatted

        # Test with hours
        formatted = console._format_eta(7200)
        assert "2h" in formatted or "120m" in formatted

        # Test with None
        formatted = console._format_eta(None)
        assert formatted == "N/A"

    def test_print_summary(self):
        """Test printing scan summary."""
        console = ConsoleOutput()
        stats = ScanStatistics(
            total_targets=100,
            scanned=100,
            successful=95,
            failed=5,
            domains_found=450,
        )

        with patch.object(console, "info"):
            with patch.object(console, "success"):
                with patch.object(console, "warning"):
                    console.print_summary(stats)

    def test_thread_safety(self):
        """Test that console output is thread-safe."""
        import threading

        console = ConsoleOutput()
        results = []

        def write_message(msg):
            with patch("sys.stdout.write"):
                with patch("sys.stdout.flush"):
                    console.info(msg)
                    results.append(msg)

        # Create multiple threads
        threads = []
        for i in range(10):
            t = threading.Thread(target=write_message, args=(f"Message {i}",))
            threads.append(t)
            t.start()

        # Wait for all threads
        for t in threads:
            t.join()

        # All messages should be recorded
        assert len(results) == 10


class TestConsoleOutputIntegration:
    """Integration tests for console output."""

    def test_full_scan_progress_workflow(self):
        """Test complete scan progress workflow."""
        console = ConsoleOutput(quiet=False)

        with patch("sys.stdout.write"):
            with patch("sys.stdout.flush"):
                # Start message
                console.info("Starting scan...")

                # Progress updates
                for i in range(0, 101, 10):
                    stats = ScanStatistics(
                        total_targets=100, scanned=i, successful=i, domains_found=i * 5
                    )
                    # Force update by resetting last update time
                    console._last_progress_update = 0
                    console.update_progress(stats)

                # Summary
                final_stats = ScanStatistics(
                    total_targets=100,
                    scanned=100,
                    successful=95,
                    failed=5,
                    domains_found=450,
                )
                console.print_summary(final_stats)

    def test_error_handling_workflow(self):
        """Test error handling in console output."""
        console = ConsoleOutput()

        with patch("sys.stderr.write"):
            with patch("sys.stderr.flush"):
                console.error("Connection failed")
                console.warning("Retrying...")
                console.info("Retry successful")
                console.success("Scan completed")

    def test_quiet_mode_workflow(self):
        """Test that quiet mode suppresses appropriate output."""
        console = ConsoleOutput(quiet=True)

        with patch("sys.stdout.write") as mock_stdout:
            with patch("sys.stderr.write") as mock_stderr:
                with patch("sys.stdout.flush"):
                    with patch("sys.stderr.flush"):
                        # Info should be suppressed
                        console.info("Info message")
                        assert mock_stdout.call_count == 0

                        # Progress should be suppressed
                        stats = ScanStatistics(total_targets=100, scanned=50)
                        console.update_progress(stats)
                        assert mock_stdout.call_count == 0

                        # Errors should still show
                        console.error("Error message")
                        assert mock_stderr.call_count > 0

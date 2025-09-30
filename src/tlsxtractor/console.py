"""
Console output and progress display.

Implements IMPL-006: Basic console output
"""

import sys
import time
from typing import Optional
from dataclasses import dataclass
import threading


@dataclass
class ScanStatistics:
    """Statistics for a scan operation."""

    total_targets: int = 0
    scanned: int = 0
    successful: int = 0
    failed: int = 0
    domains_found: int = 0
    start_time: float = 0.0

    def __post_init__(self):
        if self.start_time == 0.0:
            self.start_time = time.time()

    @property
    def elapsed_time(self) -> float:
        """Get elapsed time in seconds."""
        return time.time() - self.start_time

    @property
    def scan_rate(self) -> float:
        """Get scan rate in targets per second."""
        elapsed = self.elapsed_time
        if elapsed > 0:
            return self.scanned / elapsed
        return 0.0

    @property
    def eta_seconds(self) -> Optional[float]:
        """Estimate time to completion in seconds."""
        rate = self.scan_rate
        remaining = self.total_targets - self.scanned
        if rate > 0 and remaining > 0:
            return remaining / rate
        return None

    @property
    def progress_percentage(self) -> float:
        """Get progress as percentage."""
        if self.total_targets > 0:
            return (self.scanned / self.total_targets) * 100
        return 0.0


class ConsoleOutput:
    """
    Handles console output and progress display.

    Thread-safe console output for concurrent scanning operations.
    """

    def __init__(self, quiet: bool = False, use_colors: bool = True):
        """
        Initialize console output handler.

        Args:
            quiet: Suppress progress output
            use_colors: Use ANSI color codes (if terminal supports)
        """
        self.quiet = quiet
        self.use_colors = use_colors and self._supports_color()
        self._lock = threading.Lock()
        self._last_progress_update = 0.0
        self._progress_update_interval = 1.0  # Update every 1 second
        self._progress_line_active = False
        self._last_progress_line = ""  # Store last progress line for reprinting

    @staticmethod
    def _supports_color() -> bool:
        """Check if terminal supports ANSI colors."""
        # Check if output is a terminal
        if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
            return False

        # Check TERM environment variable
        import os

        term = os.environ.get("TERM", "")
        if term in ("dumb", ""):
            return False

        return True

    def _colorize(self, text: str, color_code: str) -> str:
        """
        Add ANSI color codes to text.

        Args:
            text: Text to colorize
            color_code: ANSI color code

        Returns:
            Colorized text (or plain text if colors disabled)
        """
        if not self.use_colors:
            return text
        return f"\033[{color_code}m{text}\033[0m"

    def success(self, message: str) -> None:
        """Print success message in green."""
        with self._lock:
            colored = self._colorize(message, "32")  # Green
            print(colored)

    def error(self, message: str) -> None:
        """Print error message in red."""
        with self._lock:
            colored = self._colorize(message, "31")  # Red
            print(colored, file=sys.stderr)

    def warning(self, message: str) -> None:
        """Print warning message in yellow."""
        with self._lock:
            colored = self._colorize(message, "33")  # Yellow
            print(colored)

    def info(self, message: str) -> None:
        """Print info message."""
        with self._lock:
            print(message)

    def print_domain_found(self, ip: str, port: int, domains: list) -> None:
        """
        Print discovered domains.

        Args:
            ip: Source IP address
            port: Source port
            domains: List of discovered domain names
        """
        if self.quiet or not domains:
            return

        with self._lock:
            # Clear progress line if active to make room for domain output
            if self._progress_line_active:
                print(f"\r{' ' * 120}\r", end="")  # Clear the line

            domain_list = ", ".join(domains)
            message = f"[{ip}:{port}] Found domains: {domain_list}"
            colored = self._colorize(message, "36")  # Cyan
            print(colored)  # Print domain finding on new line

            # Reprint progress line immediately so it's always visible
            if self._progress_line_active and self._last_progress_line:
                print(f"\r{self._last_progress_line}", end="", flush=True)

    def print_progress(self, stats: ScanStatistics, force: bool = False) -> None:
        """
        Print scan progress.

        Args:
            stats: Current scan statistics
            force: Force update even if within update interval
        """
        if self.quiet:
            return

        # Rate limit progress updates
        current_time = time.time()
        if not force and (current_time - self._last_progress_update) < self._progress_update_interval:
            return

        self._last_progress_update = current_time

        with self._lock:
            # Build progress line
            percentage = stats.progress_percentage
            rate = stats.scan_rate
            eta = stats.eta_seconds

            progress_parts = [
                f"Progress: {stats.scanned}/{stats.total_targets} ({percentage:.1f}%)",
                f"Rate: {rate:.1f} ips/s",
                f"Success: {stats.successful}",
                f"Failed: {stats.failed}",
                f"Domains: {stats.domains_found}",
            ]

            if eta is not None:
                eta_str = self._format_duration(eta)
                progress_parts.append(f"ETA: {eta_str}")

            progress_line = " | ".join(progress_parts)

            # Store progress line for reprinting after domain discoveries
            self._last_progress_line = progress_line

            # Mark that progress line is active
            if not self._progress_line_active:
                self._progress_line_active = True

            # Use carriage return to stay on same line
            print(f"\r{progress_line}", end="", flush=True)

    def clear_progress_line(self) -> None:
        """Clear the progress line."""
        if not self.quiet and self._progress_line_active:
            with self._lock:
                # Clear the line and move to next line
                print(f"\r{' ' * 120}\r", end="")
                print()  # Move to new line after clearing
                self._progress_line_active = False

    def print_summary(self, stats: ScanStatistics) -> None:
        """
        Print final scan summary.

        Args:
            stats: Final scan statistics
        """
        # Clear progress line first
        self.clear_progress_line()

        with self._lock:
            print("\n" + "=" * 60)
            print("Scan Summary")
            print("=" * 60)
            print(f"Total targets:      {stats.total_targets}")
            print(f"Scanned:            {stats.scanned}")
            print(f"Successful:         {stats.successful}")
            print(f"Failed:             {stats.failed}")
            print(f"Unique domains:     {stats.domains_found}")
            print(f"Elapsed time:       {self._format_duration(stats.elapsed_time)}")
            print(f"Average rate:       {stats.scan_rate:.2f} targets/sec")

            if stats.total_targets > 0:
                success_rate = (stats.successful / stats.total_targets) * 100
                print(f"Success rate:       {success_rate:.1f}%")

            print("=" * 60)

    @staticmethod
    def _format_duration(seconds: float) -> str:
        """
        Format duration in human-readable format.

        Args:
            seconds: Duration in seconds

        Returns:
            Formatted duration string
        """
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}m"
        else:
            hours = seconds / 3600
            return f"{hours:.1f}h"
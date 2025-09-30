"""
Rate limiting functionality using token bucket algorithm.

Implements IMPL-015: Rate limiter with token bucket algorithm.
"""

import asyncio
import time
from typing import Optional
import logging


logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Token bucket rate limiter for controlling request rates.

    Implements IMPL-015: Rate limiter with configurable rate and burst capacity.
    """

    def __init__(self, rate: float, burst: Optional[int] = None):
        """
        Initialize rate limiter.

        Args:
            rate: Maximum requests per second (can be fractional, e.g., 0.5 for 1 request per 2 seconds)
            burst: Maximum burst capacity (tokens that can accumulate). If None, defaults to rate.
        """
        if rate <= 0:
            raise ValueError("Rate must be positive")

        self.rate = rate
        self.burst = burst if burst is not None else max(1, int(rate))

        # Token bucket state
        self._tokens = float(self.burst)  # Start with full bucket
        self._last_update = time.monotonic()
        self._lock = asyncio.Lock()

        logger.debug(f"RateLimiter initialized: {rate} req/s, burst={self.burst}")

    async def acquire(self, tokens: int = 1) -> None:
        """
        Acquire tokens from the bucket, waiting if necessary.

        This method blocks until the requested number of tokens are available.

        Args:
            tokens: Number of tokens to acquire (default: 1)
        """
        if tokens <= 0:
            raise ValueError("Tokens must be positive")

        if tokens > self.burst:
            raise ValueError(f"Cannot acquire {tokens} tokens, burst capacity is {self.burst}")

        async with self._lock:
            while True:
                # Update token count based on time passed
                now = time.monotonic()
                elapsed = now - self._last_update
                self._last_update = now

                # Add tokens based on elapsed time
                self._tokens = min(self.burst, self._tokens + elapsed * self.rate)

                # Check if we have enough tokens
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    logger.debug(f"Acquired {tokens} token(s), {self._tokens:.2f} remaining")
                    return

                # Calculate wait time for next token
                tokens_needed = tokens - self._tokens
                wait_time = tokens_needed / self.rate

                logger.debug(f"Rate limit reached, waiting {wait_time:.2f}s for {tokens_needed:.2f} token(s)")

                # Release lock while waiting
                # We need to use a small sleep and then recheck to avoid race conditions
                await asyncio.sleep(wait_time)

    async def try_acquire(self, tokens: int = 1) -> bool:
        """
        Try to acquire tokens without waiting.

        Args:
            tokens: Number of tokens to acquire

        Returns:
            True if tokens were acquired, False otherwise
        """
        if tokens <= 0:
            raise ValueError("Tokens must be positive")

        if tokens > self.burst:
            return False

        async with self._lock:
            # Update token count
            now = time.monotonic()
            elapsed = now - self._last_update
            self._last_update = now

            self._tokens = min(self.burst, self._tokens + elapsed * self.rate)

            # Check if we have enough tokens
            if self._tokens >= tokens:
                self._tokens -= tokens
                logger.debug(f"Acquired {tokens} token(s) (non-blocking), {self._tokens:.2f} remaining")
                return True

            logger.debug(f"Failed to acquire {tokens} token(s) (non-blocking), only {self._tokens:.2f} available")
            return False

    def get_available_tokens(self) -> float:
        """
        Get the current number of available tokens.

        Note: This is an estimate as tokens regenerate over time.

        Returns:
            Current number of tokens in the bucket
        """
        now = time.monotonic()
        elapsed = now - self._last_update

        return min(self.burst, self._tokens + elapsed * self.rate)

    def reset(self) -> None:
        """Reset the rate limiter to full capacity."""
        self._tokens = float(self.burst)
        self._last_update = time.monotonic()
        logger.debug("RateLimiter reset to full capacity")

    def get_stats(self) -> dict:
        """
        Get rate limiter statistics.

        Returns:
            Dictionary with rate limiter stats
        """
        return {
            "rate": self.rate,
            "burst": self.burst,
            "available_tokens": self.get_available_tokens(),
        }


class AdaptiveRateLimiter(RateLimiter):
    """
    Adaptive rate limiter that can adjust rate based on errors.

    This extends RateLimiter with the ability to temporarily reduce rate
    when errors are detected (e.g., too many connection failures).
    """

    def __init__(
        self,
        rate: float,
        burst: Optional[int] = None,
        backoff_factor: float = 0.5,
        recovery_time: float = 60.0,
    ):
        """
        Initialize adaptive rate limiter.

        Args:
            rate: Base maximum requests per second
            burst: Maximum burst capacity
            backoff_factor: Factor to reduce rate by on errors (0.5 = 50% reduction)
            recovery_time: Time in seconds to recover to full rate
        """
        super().__init__(rate, burst)
        self.base_rate = rate
        self.backoff_factor = backoff_factor
        self.recovery_time = recovery_time
        self._backoff_until = 0.0

    async def trigger_backoff(self) -> None:
        """
        Trigger rate reduction due to errors.

        This temporarily reduces the rate to avoid overwhelming the target.
        """
        async with self._lock:
            self._backoff_until = time.monotonic() + self.recovery_time
            self.rate = self.base_rate * self.backoff_factor
            logger.warning(
                f"Rate limiter backing off: {self.base_rate} -> {self.rate} req/s for {self.recovery_time}s"
            )

    async def _check_recovery(self) -> None:
        """Check if backoff period has expired and recover rate."""
        now = time.monotonic()
        if now >= self._backoff_until and self.rate < self.base_rate:
            async with self._lock:
                self.rate = self.base_rate
                logger.info(f"Rate limiter recovered to {self.rate} req/s")

    async def acquire(self, tokens: int = 1) -> None:
        """Acquire tokens, checking for rate recovery first."""
        await self._check_recovery()
        await super().acquire(tokens)

    async def try_acquire(self, tokens: int = 1) -> bool:
        """Try to acquire tokens, checking for rate recovery first."""
        await self._check_recovery()
        return await super().try_acquire(tokens)
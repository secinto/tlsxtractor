"""
Unit tests for rate limiter.
"""

import asyncio
import time

import pytest

from tlsxtractor.rate_limiter import AdaptiveRateLimiter, RateLimiter


@pytest.mark.asyncio
async def test_rate_limiter_initialization():
    """Test rate limiter initialization."""
    limiter = RateLimiter(rate=10.0)
    assert limiter.rate == 10.0
    assert limiter.burst == 10

    limiter2 = RateLimiter(rate=5.0, burst=20)
    assert limiter2.rate == 5.0
    assert limiter2.burst == 20


@pytest.mark.asyncio
async def test_rate_limiter_invalid_rate():
    """Test that invalid rate raises error."""
    with pytest.raises(ValueError):
        RateLimiter(rate=0)

    with pytest.raises(ValueError):
        RateLimiter(rate=-1)


@pytest.mark.asyncio
async def test_basic_token_acquisition():
    """Test basic token acquisition."""
    limiter = RateLimiter(rate=100.0)  # High rate for fast test

    # Should acquire immediately (bucket starts full)
    start = time.monotonic()
    await limiter.acquire(1)
    elapsed = time.monotonic() - start

    assert elapsed < 0.1  # Should be nearly instant


@pytest.mark.asyncio
async def test_rate_limiting():
    """Test that rate limiting actually limits rate."""
    limiter = RateLimiter(rate=5.0, burst=5)  # 5 requests per second

    # Acquire all tokens in burst
    start = time.monotonic()
    for _ in range(5):
        await limiter.acquire(1)

    # Burst should be fast
    burst_time = time.monotonic() - start
    assert burst_time < 0.5  # Should be nearly instant for burst

    # Next acquisition should wait
    start = time.monotonic()
    await limiter.acquire(1)
    wait_time = time.monotonic() - start

    # Should wait approximately 1/5 = 0.2 seconds for 1 token at 5 req/s
    assert wait_time >= 0.15  # Allow some tolerance
    assert wait_time < 0.5


@pytest.mark.asyncio
async def test_try_acquire_success():
    """Test non-blocking acquire when tokens available."""
    limiter = RateLimiter(rate=10.0, burst=5)

    # Should succeed (bucket starts full)
    result = await limiter.try_acquire(1)
    assert result is True


@pytest.mark.asyncio
async def test_try_acquire_failure():
    """Test non-blocking acquire when tokens not available."""
    limiter = RateLimiter(rate=1.0, burst=2)

    # Exhaust tokens
    await limiter.acquire(2)

    # Try acquire should fail immediately
    result = await limiter.try_acquire(1)
    assert result is False


@pytest.mark.asyncio
async def test_token_regeneration():
    """Test that tokens regenerate over time."""
    limiter = RateLimiter(rate=10.0, burst=10)

    # Exhaust all tokens
    await limiter.acquire(10)

    # Wait for some tokens to regenerate
    await asyncio.sleep(0.5)  # Should generate ~5 tokens

    # Should be able to acquire some tokens
    result = await limiter.try_acquire(3)
    assert result is True


@pytest.mark.asyncio
async def test_burst_capacity():
    """Test burst capacity limits."""
    limiter = RateLimiter(rate=1.0, burst=5)

    # Cannot acquire more than burst capacity
    with pytest.raises(ValueError):
        await limiter.acquire(10)


@pytest.mark.asyncio
async def test_get_available_tokens():
    """Test getting available token count."""
    limiter = RateLimiter(rate=10.0, burst=10)

    # Should start with full capacity
    available = limiter.get_available_tokens()
    assert available == 10

    # Acquire some tokens
    await limiter.acquire(5)
    available = limiter.get_available_tokens()
    # Allow small tolerance for timing
    assert 4.9 <= available <= 5.1


@pytest.mark.asyncio
async def test_reset():
    """Test resetting rate limiter."""
    limiter = RateLimiter(rate=10.0, burst=10)

    # Exhaust tokens
    await limiter.acquire(10)
    assert limiter.get_available_tokens() < 1

    # Reset
    limiter.reset()
    assert limiter.get_available_tokens() == 10


@pytest.mark.asyncio
async def test_concurrent_acquisitions():
    """Test concurrent token acquisitions."""
    limiter = RateLimiter(rate=10.0, burst=10)

    # Launch multiple concurrent acquisitions
    start = time.monotonic()
    tasks = [limiter.acquire(1) for _ in range(20)]
    await asyncio.gather(*tasks)
    elapsed = time.monotonic() - start

    # First 10 should be instant (burst), next 10 should take ~1 second at 10 req/s
    # So total should be around 1 second
    assert elapsed >= 0.9
    assert elapsed < 2.0


@pytest.mark.asyncio
async def test_adaptive_rate_limiter():
    """Test adaptive rate limiter backoff."""
    limiter = AdaptiveRateLimiter(rate=10.0, backoff_factor=0.5, recovery_time=0.5)

    # Trigger backoff
    await limiter.trigger_backoff()
    assert limiter.rate == 5.0  # Should be reduced by backoff_factor

    # Wait for recovery
    await asyncio.sleep(0.6)

    # Try to acquire (should trigger recovery check)
    await limiter.try_acquire(1)
    assert limiter.rate == 10.0  # Should be back to base rate


@pytest.mark.asyncio
async def test_get_stats():
    """Test getting rate limiter statistics."""
    limiter = RateLimiter(rate=5.0, burst=10)

    stats = limiter.get_stats()
    assert stats["rate"] == 5.0
    assert stats["burst"] == 10
    assert "available_tokens" in stats

"""Token bucket rate limiter per client."""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class TokenBucket:
    """A token bucket for rate limiting."""

    capacity: int
    refill_rate: float  # tokens per second
    tokens: float = field(init=False)
    last_refill: float = field(init=False)

    def __post_init__(self) -> None:
        self.tokens = float(self.capacity)
        self.last_refill = time.monotonic()

    def consume(self, tokens: int = 1) -> bool:
        """Attempt to consume tokens. Returns True if allowed."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False


class RateLimiter:
    """
    Per-client token bucket rate limiter.

    Thread-safe. Uses client IP or API key as the bucket key.
    """

    def __init__(self, requests_per_window: int = 100, window_seconds: int = 60) -> None:
        self._capacity = requests_per_window
        self._refill_rate = requests_per_window / window_seconds
        self._buckets: dict[str, TokenBucket] = defaultdict(
            lambda: TokenBucket(capacity=self._capacity, refill_rate=self._refill_rate)
        )
        self._lock = threading.Lock()

    def is_allowed(self, client_id: str) -> bool:
        """Check if a request from client_id is within rate limits."""
        with self._lock:
            return self._buckets[client_id].consume()

    def remaining(self, client_id: str) -> float:
        """Return remaining tokens for client_id."""
        with self._lock:
            return self._buckets[client_id].tokens

    def reset(self, client_id: str) -> None:
        """Reset a client's bucket (admin use)."""
        with self._lock:
            if client_id in self._buckets:
                del self._buckets[client_id]

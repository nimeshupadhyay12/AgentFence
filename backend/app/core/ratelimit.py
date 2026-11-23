"""Thread-safe sliding-window rate limiter (per process).

Used for per-principal / per-tool quotas on the gateway and for login
brute-force protection. State is in memory: with several worker processes
each one enforces its own window (documented limitation; use Redis in prod).
"""
import threading
import time
from collections import deque
from typing import Callable, Deque, Dict, Tuple


class RateLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic, window_seconds: float = 60.0):
        self._clock = clock
        self._window = window_seconds
        self._hits: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int) -> Tuple[bool, int]:
        """Records one attempt. Returns (allowed, retry_after_seconds)."""
        if limit <= 0:
            return False, int(self._window)
        now = self._clock()
        with self._lock:
            q = self._hits.setdefault(key, deque())
            while q and q[0] <= now - self._window:
                q.popleft()
            if len(q) >= limit:
                return False, max(1, int(q[0] + self._window - now) + 1)
            q.append(now)
            if len(self._hits) > 10000:  # bound memory: drop idle keys
                for k in [k for k, v in self._hits.items() if not v or v[-1] <= now - self._window]:
                    del self._hits[k]
            return True, 0

    def reset_key(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


gateway_rate_limiter = RateLimiter()
login_rate_limiter = RateLimiter()

"""Bounded in-memory rate limiter keyed by endpoint + source."""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

MAX_SOURCE_KEY_LEN = 128


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: int
    remaining: int


def _require_positive_int(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be a positive int")
    if value < 1:
        raise ValueError(f"{name} must be a positive int")
    return value


def _require_finite_positive(name: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite positive number")
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise ValueError(f"{name} must be a finite positive number")
    return number


def normalize_source_key(source_key: str) -> str:
    text = source_key if isinstance(source_key, str) and source_key else "unknown"
    if len(text) > MAX_SOURCE_KEY_LEN:
        return text[:MAX_SOURCE_KEY_LEN]
    return text


class PairingRateLimiter:
    """
    Fixed-window limiter: limit events per window_seconds per (endpoint, source).

    When max_buckets is saturated, new unknown sources are fail-closed (rate_limited)
    instead of evicting active buckets to bypass quotas.
    """

    def __init__(
        self,
        *,
        limits: dict[str, int],
        window_seconds: float = 60.0,
        clock: Callable[[], float] | None = None,
        max_buckets: int = 4096,
    ) -> None:
        if not isinstance(limits, dict) or not limits:
            raise ValueError("limits must be a non-empty dict")
        cleaned: dict[str, int] = {}
        for key, value in limits.items():
            if not isinstance(key, str) or not key:
                raise ValueError("limit endpoint names must be non-empty strings")
            cleaned[key] = _require_positive_int(f"limits[{key}]", value)
        self._limits = cleaned
        self._window = _require_finite_positive("window_seconds", window_seconds)
        self._max_buckets = _require_positive_int("max_buckets", max_buckets)
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._buckets: dict[tuple[str, str], tuple[float, int]] = {}

    def check_and_consume(self, *, endpoint: str, source_key: str) -> RateLimitDecision:
        limit = self._limits.get(endpoint)
        if limit is None:
            raise ValueError(f"unknown endpoint {endpoint!r}")
        source = normalize_source_key(source_key)
        now = float(self._clock())
        if not math.isfinite(now):
            raise ValueError("clock must return a finite float")
        key = (endpoint, source)
        with self._lock:
            self._prune_locked(now)
            if key not in self._buckets and len(self._buckets) >= self._max_buckets:
                # Fail-closed for new sources when saturated; do not evict to bypass.
                return RateLimitDecision(
                    allowed=False,
                    retry_after_seconds=max(1, math.ceil(self._window)),
                    remaining=0,
                )
            start, count = self._buckets.get(key, (now, 0))
            if now - start >= self._window:
                start, count = now, 0
            if count >= limit:
                remaining_window = self._window - (now - start)
                retry = max(1, math.ceil(remaining_window))
                self._buckets[key] = (start, count)
                return RateLimitDecision(
                    allowed=False,
                    retry_after_seconds=retry,
                    remaining=0,
                )
            count += 1
            self._buckets[key] = (start, count)
            return RateLimitDecision(
                allowed=True,
                retry_after_seconds=0,
                remaining=max(0, limit - count),
            )

    def bucket_count(self) -> int:
        with self._lock:
            return len(self._buckets)

    def _prune_locked(self, now: float) -> None:
        stale = [
            key
            for key, (start, _) in self._buckets.items()
            if now - start >= self._window * 2
        ]
        for key in stale:
            del self._buckets[key]

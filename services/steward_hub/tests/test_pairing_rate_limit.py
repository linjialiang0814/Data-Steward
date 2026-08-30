"""Tests for pairing in-memory rate limiter."""

from __future__ import annotations

import math
import threading
import unittest

from steward_hub.pairing_rate_limit import PairingRateLimiter, normalize_source_key


class JumpClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class PairingRateLimitTest(unittest.TestCase):
    def test_limits_retry_after_ceil_and_window_recover(self) -> None:
        clock = JumpClock()
        limiter = PairingRateLimiter(
            limits={"client_hello": 2, "client_confirm": 3, "status": 4},
            window_seconds=60.0,
            clock=clock,
        )
        self.assertTrue(
            limiter.check_and_consume(endpoint="client_hello", source_key="a").allowed
        )
        self.assertTrue(
            limiter.check_and_consume(endpoint="client_hello", source_key="a").allowed
        )
        clock.advance(10.5)
        denied = limiter.check_and_consume(endpoint="client_hello", source_key="a")
        self.assertFalse(denied.allowed)
        self.assertEqual(math.ceil(49.5), denied.retry_after_seconds)
        self.assertTrue(
            limiter.check_and_consume(endpoint="status", source_key="a").allowed
        )
        self.assertTrue(
            limiter.check_and_consume(endpoint="client_hello", source_key="b").allowed
        )
        clock.advance(60.0)
        self.assertTrue(
            limiter.check_and_consume(endpoint="client_hello", source_key="a").allowed
        )

    def test_rejects_invalid_limits_and_window(self) -> None:
        with self.assertRaises(ValueError):
            PairingRateLimiter(limits={"client_hello": 0})
        with self.assertRaises(ValueError):
            PairingRateLimiter(limits={"client_hello": True})  # type: ignore[dict-item]
        with self.assertRaises(ValueError):
            PairingRateLimiter(limits={"client_hello": 1}, window_seconds=float("nan"))
        with self.assertRaises(ValueError):
            PairingRateLimiter(limits={"client_hello": 1}, window_seconds=-1)

    def test_bucket_saturation_fail_closed(self) -> None:
        clock = JumpClock()
        limiter = PairingRateLimiter(
            limits={"client_hello": 10},
            window_seconds=60.0,
            clock=clock,
            max_buckets=3,
        )
        for i in range(3):
            self.assertTrue(
                limiter.check_and_consume(
                    endpoint="client_hello", source_key=f"s{i}"
                ).allowed
            )
        denied = limiter.check_and_consume(endpoint="client_hello", source_key="new")
        self.assertFalse(denied.allowed)
        # Existing source still usable; saturation must not evict to bypass.
        self.assertTrue(
            limiter.check_and_consume(endpoint="client_hello", source_key="s0").allowed
        )
        self.assertLessEqual(limiter.bucket_count(), 3)

    def test_source_key_normalized(self) -> None:
        self.assertEqual("unknown", normalize_source_key(""))
        self.assertEqual(128, len(normalize_source_key("x" * 200)))

    def test_concurrent_safety(self) -> None:
        clock = JumpClock()
        limiter = PairingRateLimiter(
            limits={"client_confirm": 50},
            window_seconds=60.0,
            clock=clock,
        )
        results: list[bool] = []
        lock = threading.Lock()

        def worker() -> None:
            decision = limiter.check_and_consume(
                endpoint="client_confirm", source_key="c"
            )
            with lock:
                results.append(decision.allowed)

        threads = [threading.Thread(target=worker) for _ in range(80)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(50, sum(1 for item in results if item))
        self.assertEqual(30, sum(1 for item in results if not item))


if __name__ == "__main__":
    unittest.main()

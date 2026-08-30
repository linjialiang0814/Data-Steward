from __future__ import annotations

import unittest
from unittest.mock import Mock

from steward_hub.server import (
    LOOPBACK_HOST,
    build_parser,
    validate_loopback_host,
)
from services.steward_hub.tool.smoke_transport import stop_hub


class ServerBoundaryTest(unittest.TestCase):
    def test_exact_ipv4_loopback_is_accepted(self) -> None:
        self.assertEqual(
            "127.0.0.1",
            validate_loopback_host("127.0.0.1"),
        )

    def test_non_loopback_and_ambiguous_hosts_are_rejected(self) -> None:
        for host in (
            "0.0.0.0",
            "localhost",
            "::1",
            "192.168.1.20",
            "8.8.8.8",
        ):
            with self.subTest(host=host):
                with self.assertRaises(ValueError):
                    validate_loopback_host(host)

    def test_server_defaults_to_loopback_and_one_worker(self) -> None:
        arguments = build_parser().parse_args(
            ["--database", "temporary.sqlite3", "--port", "43123"]
        )

        self.assertEqual(LOOPBACK_HOST, arguments.host)
        self.assertEqual(1, arguments.workers)

    def test_preexited_process_is_not_counted_as_graceful(self) -> None:
        process = Mock()
        process.poll.return_value = 1

        self.assertFalse(stop_hub(process))
        process.stdin.write.assert_not_called()

    def test_graceful_count_requires_shutdown_and_zero_exit(self) -> None:
        successful = Mock()
        successful.poll.return_value = None
        successful.wait.return_value = 0
        failed = Mock()
        failed.poll.return_value = None
        failed.wait.return_value = 1

        self.assertTrue(stop_hub(successful))
        self.assertFalse(stop_hub(failed))
        successful.stdin.write.assert_called_once_with(b"shutdown\n")
        successful.stdin.flush.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()

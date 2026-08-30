"""Controlled loopback-only Uvicorn entry point."""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
from collections.abc import Sequence

import uvicorn

from .api import create_app

LOOPBACK_HOST = "127.0.0.1"


def validate_loopback_host(host: str) -> str:
    if host != LOOPBACK_HOST:
        raise ValueError("only 127.0.0.1 is allowed")
    return host


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the loopback-only Data Steward Hub spike",
    )
    parser.add_argument(
        "--database",
        default=os.environ.get("STEWARD_HUB_DATABASE"),
    )
    parser.add_argument("--host", default=LOOPBACK_HOST)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument(
        "--shutdown-stdin",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    if not arguments.database:
        raise SystemExit("database parameter is required")
    try:
        host = validate_loopback_host(arguments.host)
    except ValueError as error:
        raise SystemExit(str(error)) from None
    if arguments.workers != 1:
        raise SystemExit("exactly one worker is required")
    if not 1 <= arguments.port <= 65_535:
        raise SystemExit("port is invalid")

    app = create_app(database_path=arguments.database)
    config = uvicorn.Config(
        app,
        host=host,
        port=arguments.port,
        workers=1,
        reload=False,
        access_log=False,
        proxy_headers=False,
        log_level="warning",
    )
    server = uvicorn.Server(config)

    if hasattr(signal, "SIGBREAK"):
        signal.signal(
            signal.SIGBREAK,
            lambda _signal, _frame: setattr(server, "should_exit", True),
        )
    if arguments.shutdown_stdin:
        asyncio.run(_serve_with_shutdown_stdin(server))
    else:
        server.run()
    return 0


async def _serve_with_shutdown_stdin(server: uvicorn.Server) -> None:
    server_task = asyncio.create_task(server.serve())
    stdin_task = asyncio.create_task(asyncio.to_thread(sys.stdin.readline))
    done, _ = await asyncio.wait(
        {server_task, stdin_task},
        return_when=asyncio.FIRST_COMPLETED,
    )
    if stdin_task in done and stdin_task.result().strip() == "shutdown":
        server.should_exit = True
        await server_task
    if server_task in done and not stdin_task.done():
        sys.stdin.close()
        stdin_task.cancel()
        await asyncio.gather(stdin_task, return_exceptions=True)


if __name__ == "__main__":
    raise SystemExit(main())

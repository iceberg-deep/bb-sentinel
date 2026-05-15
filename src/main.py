from __future__ import annotations

import asyncio
import logging
import os
import signal

import structlog

from .config import AppConfig
from .database import Database
from .monitor import MonitorLoop


def _configure_logging(level: str) -> None:
    logging.basicConfig(level=level.upper(), format="%(message)s")
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, level.upper(), logging.INFO)),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


async def _run() -> int:
    programs_path = os.environ.get("BB_PROGRAMS_CONFIG", "config/programs.yaml")
    global_path = os.environ.get("BB_GLOBAL_CONFIG", "config/global.yaml")
    app = AppConfig.load(programs_path, global_path)

    _configure_logging(app.global_.log_level)
    log = structlog.get_logger("bb-sentinel")
    log.info("boot", programs=list(app.programs.keys()), database=_redact(app.global_.database_url))

    db = Database(app.global_.database_url)
    await db.create_all()

    loop = MonitorLoop(app, db)
    stop = asyncio.Event()

    def _handle_signal() -> None:
        log.info("shutdown signal received")
        loop.request_stop()
        stop.set()

    running_loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            running_loop.add_signal_handler(sig, _handle_signal)
        except NotImplementedError:
            pass  # Windows / non-main thread

    try:
        await loop.run_forever()
    finally:
        await db.dispose()
    return 0


def _redact(url: str) -> str:
    if "@" not in url:
        return url
    scheme, rest = url.split("://", 1)
    creds, host = rest.split("@", 1)
    return f"{scheme}://***@{host}"


def main() -> None:
    raise SystemExit(asyncio.run(_run()))


if __name__ == "__main__":
    main()

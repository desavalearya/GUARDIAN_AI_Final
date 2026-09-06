"""Lightweight SMTP listener for demo (port 2525). Posts raw mail to the API ingest endpoint."""

from __future__ import annotations

import asyncio
import logging
import os

import httpx
from aiosmtpd.controller import Controller

log = logging.getLogger("gateway")


class IngestHandler:
    async def handle_DATA(self, server, session, envelope) -> str:  # noqa: ANN001, ARG002
        raw = envelope.content.decode("utf-8", errors="replace")
        url = os.environ.get("INGEST_URL", "http://api:8000/api/v1/ingest/raw")
        key = os.environ.get("INGEST_API_KEY", "dev-ingest-key")
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    url,
                    json={
                        "raw_message": raw,
                        "direction": "inbound",
                        "ingestion_path": "smtp",
                    },
                    headers={"X-Ingest-Key": key},
                )
            log.info("ingest status=%s", response.status_code)
        except Exception:
            log.exception("ingest failed")
            return "451 Temporary failure"
        return "250 Message accepted for analysis"


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    controller = Controller(IngestHandler(), hostname="0.0.0.0", port=int(os.environ.get("SMTP_PORT", "2525")))
    controller.start()
    log.info("SMTP gateway listening on 2525")
    try:
        while True:
            await asyncio.sleep(3600)
    finally:
        controller.stop()


if __name__ == "__main__":
    asyncio.run(main())

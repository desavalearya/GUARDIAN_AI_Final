#!/usr/bin/env python3
"""Guardian milter: scan inbound/outbound via API before Postfix continues."""

from __future__ import annotations

import logging
import os
import time

import httpx
import Milter
from Milter.utils import parseaddr

log = logging.getLogger("guardian-milter")

INGEST_URL = os.environ.get("INGEST_URL", "http://api:8000/api/v1/ingest/raw")
INGEST_KEY = os.environ.get("INGEST_API_KEY", "dev-ingest-key")
MAIL_DOMAIN = os.environ.get("MAIL_DOMAIN", "guardian.local")
SCAN_TIMEOUT = float(os.environ.get("SMTP_SCAN_TIMEOUT_SECONDS", "20"))


class GuardianMilter(Milter.Base):
    def __init__(self):  # noqa: ANN204
        self._id = Milter.uniqueID()
        self.reset()

    def reset(self) -> None:
        self.headers: list[tuple[str, str]] = []
        self.chunks: list[bytes] = []
        self.mail_from = ""
        self.rcpts: list[str] = []
        self.macro_auth = ""

    @Milter.noreply
    def connect(self, hostname, family, hostaddr):  # noqa: ANN001, ARG002
        self.reset()
        log.info("connect from %s %s", hostname, hostaddr)
        return Milter.CONTINUE

    def envfrom(self, mailfrom, *args):  # noqa: ANN001, ARG002
        _, addr = parseaddr(mailfrom)
        self.mail_from = addr or mailfrom
        self.macro_auth = self.getsymval("{auth_authen}") or ""
        log.info("envfrom %s", self.mail_from)
        return Milter.CONTINUE

    def envrcpt(self, to, *args):  # noqa: ANN001, ARG002
        _, addr = parseaddr(to)
        self.rcpts.append((addr or to).lower())
        return Milter.CONTINUE

    def header(self, name, val):  # noqa: ANN001
        self.headers.append((name, val))
        return Milter.CONTINUE

    def eoh(self):  # noqa: ANN204
        return Milter.CONTINUE

    def body(self, chunk):  # noqa: ANN001
        self.chunks.append(chunk)
        return Milter.CONTINUE

    def eom(self):  # noqa: ANN204
        header_block = "".join(f"{k}: {v}\r\n" for k, v in self.headers)
        raw = header_block + "\r\n" + b"".join(self.chunks).decode("utf-8", errors="replace")

        # Originating (submission) => outbound; otherwise inbound
        direction = "outbound" if self.macro_auth or self._is_local_sender() else "inbound"

        decision = "PASS"
        try:
            with httpx.Client(timeout=SCAN_TIMEOUT) as client:
                resp = client.post(
                    INGEST_URL,
                    json={
                        "raw_message": raw,
                        "direction": direction,
                        "ingestion_path": "milter",
                    },
                    headers={"X-Ingest-Key": INGEST_KEY},
                )
                if resp.status_code >= 400:
                    log.error("ingest HTTP %s: %s", resp.status_code, resp.text[:300])
                    self.setreply("451", "4.7.1", "Guardian temporarily unavailable")
                    return Milter.TEMPFAIL
                data = resp.json()
                decision = (data.get("decision") or "PASS").upper()
                risk = data.get("fused_risk_score")
                conf = data.get("confidence_state")
                deep_status = data.get("deep_status")
                total_ms = data.get("total_analysis_ms")
                log.info(
                    "scanned from=%s direction=%s decision=%s risk=%s conf=%s",
                    self.mail_from,
                    direction,
                    decision,
                    risk,
                    conf,
                )
                # Annotate headers for local troubleshooting
                self.addheader("X-Guardian-Decision", decision)
                if risk is not None:
                    self.addheader("X-Guardian-Risk", str(risk))
                if conf:
                    self.addheader("X-Guardian-Confidence", str(conf))
                if deep_status:
                    self.addheader("X-Guardian-Deep-Status", str(deep_status))
                if total_ms is not None:
                    self.addheader("X-Guardian-Analysis-Ms", str(total_ms))
        except Exception:
            log.exception("ingest failed")
            self.setreply("451", "4.7.1", "Guardian scan failed")
            return Milter.TEMPFAIL

        if decision in {"BLOCK", "HARD_BLOCK"}:
            self.setreply("550", "5.7.1", f"Blocked by Guardian AI ({decision})")
            return Milter.REJECT

        # QUARANTINE / HUMAN_REVIEW: accept into Postfix but webmail hides from Inbox via API
        return Milter.ACCEPT

    def _is_local_sender(self) -> bool:
        return self.mail_from.lower().endswith("@" + MAIL_DOMAIN.lower())

    def close(self):  # noqa: ANN204
        return Milter.CONTINUE


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    socket = os.environ.get("MILTER_SOCKET", "inet:8891")
    timeout = int(os.environ.get("MILTER_TIMEOUT", "60"))
    # Wait for API
    for _ in range(60):
        try:
            httpx.get(os.environ.get("API_HEALTH", "http://api:8000/health"), timeout=2.0)
            break
        except Exception:
            time.sleep(1)
    log.info("Starting Guardian milter on %s", socket)
    Milter.factory = GuardianMilter
    Milter.set_flags(Milter.ADDHDRS)
    # Listen on all interfaces so Postfix container can connect
    Milter.runmilter("guardian", "inet:8891@0.0.0.0", timeout)


if __name__ == "__main__":
    main()

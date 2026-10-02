"""Send an RFC822 fixture through PhishProof to the downstream demo SMTP server."""

from __future__ import annotations

import argparse
import smtplib
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2525)
    parser.add_argument("--recipient", default="receiver@company-b.test")
    args = parser.parse_args()

    raw = args.fixture.read_bytes()
    message = BytesParser(policy=policy.default).parsebytes(raw)
    sender = parseaddr(message.get("From", ""))[1] or "sender@company-a.test"
    message.replace_header("To", args.recipient) if message.get("To") else message.__setitem__(
        "To", args.recipient
    )
    try:
        with smtplib.SMTP(args.host, args.port, timeout=30) as client:
            client.set_debuglevel(1)
            client.send_message(message, from_addr=sender, to_addrs=[args.recipient])
    except smtplib.SMTPResponseException as exc:
        print(f"PhishProof rejected the message: SMTP {exc.smtp_code} {exc.smtp_error!r}")
        return 2
    print(
        "Message accepted by the PhishProof gateway. "
        "Open http://localhost:8025 to verify downstream delivery."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

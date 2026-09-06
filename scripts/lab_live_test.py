#!/usr/bin/env python3
"""Hit the running Model Lab API with real inputs and print raw JSON responses."""

from __future__ import annotations

import json
import mimetypes
import sys
from pathlib import Path

import httpx

BASE = "http://localhost:8000/api/v1/lab"

TEXT_SAMPLES = [
    "Urgent: verify your account and click here",
    "Hi team, the meeting is moved to 3 PM tomorrow. Agenda attached.",
]

DOCX = Path(r"C:\Users\Suhani Buche\Downloads\SY_AIML_A11-Patent.docx")
PDF = Path(r"C:\Users\Suhani Buche\Downloads\IEEE_Conference_Template__1_ (1).pdf")


def show(title: str, response: httpx.Response) -> None:
    print("=" * 70)
    print(title)
    print("=" * 70)
    print(f"HTTP {response.status_code}")
    try:
        print(json.dumps(response.json(), indent=2))
    except Exception:
        print(response.text[:2000])
    print()


def main() -> int:
    client = httpx.Client(timeout=600.0)

    show("MODELS STATUS", client.get(f"{BASE}/models/status"))

    for text in TEXT_SAMPLES:
        show(
            f"TEXT SCAN -> {text[:60]!r}",
            client.post(f"{BASE}/scan/text", json={"text": text}),
        )

    for label, path, endpoint in (
        ("OFFICE SCAN", DOCX, "scan/office"),
        ("PDF SCAN", PDF, "scan/pdf"),
    ):
        if not path.exists():
            print(f"{label}: file missing -> {path}")
            continue
        mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        with path.open("rb") as fh:
            files = {"file": (path.name, fh, mime)}
            show(f"{label} -> {path.name}", client.post(f"{BASE}/{endpoint}", files=files))

    client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

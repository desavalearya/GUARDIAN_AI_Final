"""Start API or Celery worker after running migrations."""

from __future__ import annotations

import os
import subprocess
import sys


def main() -> None:
    role = sys.argv[1] if len(sys.argv) > 1 else "api"
    if role == "api":
        subprocess.check_call(["alembic", "upgrade", "head"])
        os.execvp(
            "uvicorn",
            ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"],
        )
    if role == "worker":
        os.execvp(
            "celery",
            ["celery", "-A", "backend.workers.celery_app", "worker", "--loglevel=info"],
        )
    if role == "smtp":
        os.execvp("python", ["python", "/app/gateway/smtp_gateway.py"])
    raise SystemExit(f"Unknown role: {role}")


if __name__ == "__main__":
    main()

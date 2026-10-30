"""Shield·Scout HTTP API. `app` serves /api (web UI) and the versioned /api/v1 contract."""
import sys
from pathlib import Path

from ..env import load_env

if "pytest" not in sys.modules:  # tests must never pick up real keys
    load_env(Path(__file__).resolve().parents[2] / ".env")

from .server import app, main, mount_web
from . import v1  # noqa: F401  registers /api/v1 routes on `app`

mount_web()

__all__ = ["app", "main"]

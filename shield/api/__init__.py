"""Shield·Scout HTTP API. `app` serves /api (web UI) and the versioned /api/v1 contract."""
from .server import app, main, mount_web
from . import v1  # noqa: F401  registers /api/v1 routes on `app`

mount_web()

__all__ = ["app", "main"]

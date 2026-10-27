"""
Central license gate (ФТ-16, docs/modules/LICENSING_TZ.md).

Closed by default: every mutating request (POST/PUT/PATCH/DELETE) is
classified, and in the `wind_down` lifecycle state (see
core/license_state.py) the `gated` category — creating and operating on
resources — is blocked with a 402, while reads, exports and teardown stay
available so the customer can inspect, export, and wind down their own
infrastructure. Data is never touched and infrastructure is never removed
automatically (the two invariants in the TZ).

Classification is rule-based rather than a decorator on each of ~390
handlers, so a new endpoint is covered the moment it's added:
- safe methods (GET/HEAD/OPTIONS) are never gated;
- DELETE, and mutating paths whose last segment reads as teardown
  (destroy/revoke/unbind/stop/disable/cancel/teardown/leave), are
  `teardown` — always allowed;
- account/licensing essentials (`ALWAYS_PREFIXES`) are `always` — a
  locked-out customer must still be able to log in, read license status,
  and upload a renewed license;
- everything else mutating defaults to `gated`.

The default is the safe direction: a new mutating route nobody classified
is blocked in wind-down, not silently allowed. test_license_gate.py
snapshots the leniently-classified set (always/teardown) so any new route
that lands there surfaces in review.
"""
from __future__ import annotations

from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Mutating routes that must work regardless of license state.
ALWAYS_PREFIXES = (
    "/api/auth",
    "/api/system/license",
    "/api/notifications",
)

# Last-segment keywords that mark a mutating route as teardown.
TEARDOWN_KEYWORDS = (
    "destroy",
    "revoke",
    "unbind",
    "teardown",
    "disable",
    "cancel",
    "leave",
)


def classify(method: str, path: str) -> str:
    """Return "safe", "always", "teardown", or "gated" for a route."""
    if method in SAFE_METHODS:
        return "safe"
    if any(path == p or path.startswith(p + "/") for p in ALWAYS_PREFIXES):
        return "always"
    if method == "DELETE":
        return "teardown"
    last = path.rstrip("/").rsplit("/", 1)[-1]
    if any(kw in last for kw in TEARDOWN_KEYWORDS):
        return "teardown"
    return "gated"


_WIND_DOWN_DETAIL = (
    "This installation's license has lapsed and is in wind-down: creating and "
    "operating resources is paused. You can still view and export your data and "
    "wind down infrastructure. Upload a renewed license under System → License "
    "to restore full access — no data was lost."
)


class LicenseGateMiddleware(BaseHTTPMiddleware):
    """Blocks `gated` HTTP requests while the instance is in wind-down.
    BaseHTTPMiddleware never sees WebSocket traffic, so realtime connections
    are unaffected. Classification runs on the concrete request path (the
    keyword/prefix rules don't need the route template), and a license-status
    read happens only for a mutating, gated request — not on the GET-heavy
    common path."""

    async def dispatch(self, request, call_next):
        if request.method not in SAFE_METHODS and classify(request.method, request.url.path) == "gated":
            from ..database import SessionLocal
            from .license_state import get_license_status

            db: Session = SessionLocal()
            try:
                state = get_license_status(db)["state"]
            finally:
                db.close()
            if state == "wind_down":
                return JSONResponse(status_code=402, content={"detail": _WIND_DOWN_DETAIL})
        return await call_next(request)

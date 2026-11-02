"""Edition detection and the Community/Enterprise seam.

Umbryx ships as two artifacts built from one source tree
(docs/modules/EDITIONS.md): Community Edition, which deploys nothing, and
Enterprise Edition, which does. The difference is physical — EE code lives
under ``app.ee``, and the CE build simply does not contain that package.

Everything in core therefore has to work with ``app.ee`` absent. This
module is the single place that knows whether it is there, so the rest of
the codebase asks a question instead of guessing at an ImportError:

    if editions.ee_available():      # is this an EE build at all?
    mod = editions.ee_import("infra")  # module, or None in CE

Two failure modes are deliberately kept apart, because they mean
different things to a customer and produce different HTTP codes:

- **absent** (CE): the capability is not in this build. Routers are never
  mounted, so the endpoints 404. Nothing to upsell at the request level —
  the UI hides the feature entirely, driven by ``GET /api/system/edition``.
- **unlicensed** (EE without a valid token): the capability is present but
  not paid for. Routers mount and ``plan.require_instance_feature`` answers
  402 on mutating requests, while reads and teardown stay available.

A missing ``app.ee`` is never an error and never logged as one. In CE it is
the expected state.
"""

from __future__ import annotations

import importlib
import importlib.util
from types import ModuleType

from .logging_setup import get_logger

logger = get_logger(__name__)

EE_PACKAGE = "app.ee"

# Resolved once: find_spec walks the filesystem, and this is consulted on
# hot paths (every request that asks for the edition). Not a constant at
# import time — the flag is computed lazily so tests can clear the cache
# and simulate the other edition.
_available: bool | None = None


def reset_cache() -> None:
    """Forget the resolved edition. For tests that simulate the other build."""
    global _available
    _available = None


def ee_available() -> bool:
    """Whether this build contains the Enterprise package."""
    global _available
    if _available is None:
        try:
            _available = importlib.util.find_spec(EE_PACKAGE) is not None
        except (ImportError, ValueError):
            # ValueError: the parent package exists but has no __spec__,
            # which can happen under unusual import setups. Either way the
            # answer is the same — treat it as a Community build.
            _available = False
    return _available


def edition() -> str:
    """``"ee"`` or ``"ce"`` — the build, not the license state."""
    return "ee" if ee_available() else "ce"


def ee_import(name: str) -> ModuleType | None:
    """Import ``app.ee.<name>``, or return None in a Community build.

    Returns None only when the Enterprise package is absent. A genuine
    error inside an EE module (a syntax error, a bad import of its own) is
    allowed to propagate: in an EE build that is a bug to surface, not a
    reason to silently degrade into a Community-shaped install.
    """
    if not ee_available():
        return None
    return importlib.import_module(f"{EE_PACKAGE}.{name}")


def ee_routers() -> list:
    """The FastAPI routers the Enterprise package contributes.

    Empty in a Community build, so ``routing.py`` can mount them
    unconditionally. The Enterprise package exposes them as ``ROUTERS`` in
    ``app.ee.routers`` — one list it owns, so adding an EE router never
    touches core.
    """
    mod = ee_import("routers")
    if mod is None:
        return []
    routers = list(getattr(mod, "ROUTERS", []))
    logger.info("Enterprise Edition: mounting %d router(s)", len(routers))
    return routers

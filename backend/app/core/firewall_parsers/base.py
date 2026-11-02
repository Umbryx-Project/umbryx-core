"""
Parser interface and registry for firewall/router config ingestion.

Mirrors core/infra/provider_adapter.py's ProviderAdapter/ProviderRegistry
pattern: a new vendor is a new module that self-registers via
@FirewallParserRegistry.register("vendor_key") — no changes to enrichment
or router code are needed to add support for another vendor.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from .schema import ParsedConfig, VendorInfo

logger = logging.getLogger(__name__)


class FirewallConfigParser(ABC):
    """Base interface for a single vendor's config parser."""

    @abstractmethod
    def detect(self, raw_config: str) -> bool:
        """Return True if raw_config looks like this vendor's syntax.

        Must be cheap and side-effect free — called against every
        registered parser in turn until one matches. Implementations should
        look for a handful of characteristic, unambiguous markers rather
        than attempting a full parse.
        """

    @abstractmethod
    def parse(self, raw_config: str) -> ParsedConfig:
        """Parse raw_config into the vendor-neutral ParsedConfig structure."""

    @abstractmethod
    def get_vendor_info(self) -> VendorInfo:
        """Return metadata about this parser (vendor, supported versions, limits)."""


class FirewallParserRegistry:
    """Central registry for firewall config parsers.

    Parsers self-register at import time via the `register` decorator.
    Detection/enrichment code consults the registry — no hard-coded
    if/elif chain over vendors.
    """

    _parsers: dict[str, type[FirewallConfigParser]] = {}

    @classmethod
    def register(cls, vendor_key: str):
        def decorator(parser_cls: type[FirewallConfigParser]):
            cls._parsers[vendor_key] = parser_cls
            logger.debug("firewall parser registered: %s -> %s", vendor_key, parser_cls.__name__)
            return parser_cls

        return decorator

    @classmethod
    def get(cls, vendor_key: str) -> FirewallConfigParser | None:
        parser_cls = cls._parsers.get(vendor_key)
        return parser_cls() if parser_cls else None

    @classmethod
    def list_vendors(cls) -> list[str]:
        return sorted(cls._parsers.keys())

    @classmethod
    def detect_vendor(cls, raw_config: str) -> str | None:
        """Return the vendor_key of the first registered parser whose
        detect() matches, or None if no parser recognizes the config.

        Callers (routers/firewall_configs.py) must treat None as "format
        not recognized" and refuse to proceed — never fall back to a
        best-guess parser, which could silently create incorrect
        enrichment data from a misparsed config.
        """
        for vendor_key, parser_cls in cls._parsers.items():
            try:
                if parser_cls().detect(raw_config):
                    return vendor_key
            except Exception:
                logger.exception("firewall parser detect() failed for vendor=%s", vendor_key)
        return None


def _import_builtin_parsers():
    """Trigger import of built-in parsers so they self-register."""
    from . import (  # noqa: F401
        cisco_asa,
        cisco_ios,
        fortinet,
        huawei_vrp,
        mikrotik,
        paloalto,
        pfsense,
        unifi,
    )


_import_builtin_parsers()

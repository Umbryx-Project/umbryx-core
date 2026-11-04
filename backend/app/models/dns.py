"""
DNS models — zones and records linked to infra providers and infrastructure objects.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class DnsZone(Base):
    """An authorized DNS zone (domain) managed by a DNS provider connection."""

    __tablename__ = "dns_zones"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    provider_id: Mapped[str] = mapped_column(
        String, ForeignKey("infra_providers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    zone_name: Mapped[str] = mapped_column(String(512), nullable=False)
    remote_zone_id: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    authorized: Mapped[bool] = mapped_column(default=False)
    record_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expiration_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    registrar: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    __table_args__ = (Index("ix_dns_zones_provider_zone", "provider_id", "zone_name"),)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "provider_id": self.provider_id,
            "zone_name": self.zone_name,
            "remote_zone_id": self.remote_zone_id,
            "authorized": self.authorized,
            "record_count": self.record_count,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "expiration_checked_at": (
                self.expiration_checked_at.isoformat() if self.expiration_checked_at else None
            ),
            "registrar": self.registrar,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class DnsRecord(Base):
    """A DNS record created/managed by the platform, optionally linked to an infra object."""

    __tablename__ = "dns_records"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    zone_id: Mapped[str] = mapped_column(
        String, ForeignKey("dns_zones.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider_id: Mapped[str] = mapped_column(
        String, ForeignKey("infra_providers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    record_type: Mapped[str] = mapped_column(String(16), nullable=False, default="A")
    value: Mapped[str] = mapped_column(Text, nullable=False)
    ttl: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    proxied: Mapped[bool] = mapped_column(default=False)
    remote_record_id: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    linked_object_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    linked_object_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    propagation_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    propagation_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    propagation_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    __table_args__ = (
        Index("ix_dns_records_zone_type", "zone_id", "record_type"),
        Index("ix_dns_records_linked", "linked_object_type", "linked_object_id"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "zone_id": self.zone_id,
            "provider_id": self.provider_id,
            "name": self.name,
            "record_type": self.record_type,
            "value": self.value,
            "ttl": self.ttl,
            "proxied": self.proxied,
            "remote_record_id": self.remote_record_id,
            "status": self.status,
            "linked_object_type": self.linked_object_type,
            "linked_object_id": self.linked_object_id,
            "error_message": self.error_message,
            "propagation_status": self.propagation_status,
            "propagation_checked_at": (
                self.propagation_checked_at.isoformat() if self.propagation_checked_at else None
            ),
            "propagation_detail": self.propagation_detail,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

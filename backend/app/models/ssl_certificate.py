"""
SSL Certificate model — Let's Encrypt certificates issued via ACME DNS-01.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class SslCertificate(Base):
    """An SSL/TLS certificate issued via Let's Encrypt (ACME DNS-01)."""

    __tablename__ = "ssl_certificates"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    domain: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    dns_provider_id: Mapped[str] = mapped_column(
        String, ForeignKey("infra_providers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    dns_zone: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")

    certificate_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    chain_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    private_key_pem: Mapped[str | None] = mapped_column(Text, nullable=True)

    acme_account_key_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    acme_url: Mapped[str | None] = mapped_column(String(256), nullable=True)

    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    linked_object_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    linked_object_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)

    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    __table_args__ = (Index("ix_ssl_certs_domain_status", "domain", "status"),)

    def to_dict(self, include_keys: bool = False) -> dict:
        d = {
            "id": self.id,
            "domain": self.domain,
            "dns_provider_id": self.dns_provider_id,
            "dns_zone": self.dns_zone,
            "status": self.status,
            "valid_from": self.valid_from.isoformat() if self.valid_from else None,
            "valid_until": self.valid_until.isoformat() if self.valid_until else None,
            "linked_object_type": self.linked_object_type,
            "linked_object_id": self.linked_object_id,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_keys:
            d["certificate_pem"] = self.certificate_pem
            d["chain_pem"] = self.chain_pem
            d["private_key_pem"] = self.private_key_pem
        return d

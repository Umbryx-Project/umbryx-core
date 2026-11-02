"""Shared pydantic schema helpers."""

from pydantic import BaseModel, field_validator


class EmptyFkToNoneMixin(BaseModel):
    """Coerce empty strings to None for nullable FK columns.

    Postgres FK constraints (migration 003: findings/loots/objectives host_id,
    attack_steps host_id/parent_step_id) accept NULL but reject ``''`` — and
    the UI's "not linked" selects send ``''``. Coerce at the schema edge so
    every client gets the same behavior. ``check_fields=False`` lets schemas
    that only have a subset of these fields inherit safely.
    """

    @field_validator("host_id", "parent_step_id", mode="before", check_fields=False)
    @classmethod
    def _empty_fk_to_none(cls, v):
        return None if v == "" else v

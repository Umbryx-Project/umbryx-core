"""ha_mode must be importable in every edition.

Regression (review 2026-10-30, CRITICAL): shared main.py's lifespan
imports app.core.ha_mode outside any except clause — a CE tree without
the module aborted backend startup in dev/prod mode (test mode returns
earlier, so the suite and CI stayed green while every docker build of
main produced a non-booting image).
"""

import os
from unittest.mock import MagicMock


def test_module_importable_and_single_node_noop():
    from app.core.ha_mode import enforce_ha_license, is_ha_deployment

    assert is_ha_deployment() is False  # no Sentinel env in tests
    # single-node install: returns without touching the license at all
    db = MagicMock()
    enforce_ha_license(db)
    db.query.assert_not_called()


def test_ha_without_entitlement_refuses_to_start():
    from unittest.mock import patch

    from app.core import ha_mode

    with (
        patch.dict(os.environ, {"REDIS_SENTINEL_HOSTS": "sentinel-1:26379"}),
        patch("app.core.plan.instance_has_feature", return_value=False),
    ):
        assert ha_mode.is_ha_deployment() is True
        import pytest

        with pytest.raises(RuntimeError, match="HA cluster"):
            ha_mode.enforce_ha_license(MagicMock())


def test_ha_with_entitlement_passes():
    from unittest.mock import patch

    from app.core import ha_mode

    with (
        patch.dict(os.environ, {"REDIS_SENTINEL_HOSTS": "s:26379"}),
        patch("app.core.plan.instance_has_feature", return_value=True),
    ):
        assert ha_mode.enforce_ha_license(MagicMock()) is None  # must not raise


def test_plan_feature_import_contract():
    # the entitlement check relies on PlanFeature.HA_CLUSTER existing here too
    from app.core.plan import PlanFeature

    assert PlanFeature.HA_CLUSTER.value == "ha_cluster"

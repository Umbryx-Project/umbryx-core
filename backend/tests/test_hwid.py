"""Tests for hardware-identity binding (core/hwid.py, LICENSING_REDESIGN Phase 1)."""
from app.core import hwid


def _bound(**over):
    base = {
        "machine_id": "m", "cpu_sig": "c", "mem_gib": "16", "install_uuid": "u",
        "product_uuid": "p", "primary_mac": "aa",
    }
    base.update(over)
    return hwid.hash_hwid(base)


def test_hash_namespaces_and_skips_empty():
    h = hwid.hash_hwid({"machine_id": "x", "cpu_sig": ""})
    assert "machine_id" in h and "cpu_sig" not in h
    # same raw value under different params hashes differently (namespaced)
    h2 = hwid.hash_hwid({"machine_id": "x", "primary_mac": "x"})
    assert h2["machine_id"] != h2["primary_mac"]


def test_identical_machine_matches():
    b = _bound()
    r = hwid.match_hwid(b, b)
    assert r["ok"] and r["anchors_matched"] == 4 and r["clone_sensitive_matched"] == 2


def test_minor_hardware_change_still_matches():
    b = _bound()
    cur = _bound(mem_gib="32", primary_mac="bb")  # RAM upgrade + NIC swap
    r = hwid.match_hwid(b, cur)
    # 3 anchors still match, product_uuid still matches -> same machine
    assert r["ok"] and r["anchors_matched"] == 3 and r["clone_sensitive_matched"] == 1


def test_clone_detected_when_all_clone_sensitive_change():
    b = _bound()
    # A snapshot clone: anchors identical, but product_uuid AND mac regenerated.
    cur = _bound(product_uuid="p2", primary_mac="cc")
    r = hwid.match_hwid(b, cur)
    assert not r["ok"]
    assert r["anchors_matched"] == 4  # anchors fine...
    assert r["clone_sensitive_matched"] == 0  # ...but it's a clone
    assert "clone" in r["reason"]


def test_too_few_anchors_fails():
    b = _bound()
    cur = _bound(machine_id="x", cpu_sig="y", mem_gib="99")  # 1 anchor left
    r = hwid.match_hwid(b, cur)
    assert not r["ok"] and r["anchors_matched"] == 1


def test_no_clone_sensitive_bound_cannot_detect_clone():
    # e.g. a bare container where no clone-sensitive signal was available
    b = hwid.hash_hwid({"machine_id": "m", "cpu_sig": "c", "install_uuid": "u"})
    r = hwid.match_hwid(b, b)
    assert r["ok"] and r["clone_sensitive_bound"] == 0


def test_policy_can_disable_clone_check():
    b = _bound()
    cur = _bound(product_uuid="p2", primary_mac="cc")  # would be a clone
    r = hwid.match_hwid(b, cur, {"require_clone_sensitive": False})
    assert r["ok"]  # clone check disabled -> anchors alone decide


def test_collect_is_best_effort_and_includes_install_uuid():
    got = hwid.collect_hwid("my-install-uuid")
    assert got.get("install_uuid") == "my-install-uuid"
    assert isinstance(got, dict)  # never raises, whatever the host exposes


def test_current_hashes_roundtrip():
    h = hwid.current_hwid_hashes("uid-123")
    # install_uuid is always present, and values are hex sha256
    assert "install_uuid" in h and len(h["install_uuid"]) == 64

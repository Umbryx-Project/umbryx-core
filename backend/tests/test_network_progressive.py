"""Unit tests for the progressive loading API endpoints (summary + viewport).

Two test strategies:
1. Function-level tests using MagicMock (like test_core_network_data.py) to verify
   get_network_summary, get_nodes_in_bounds, get_edges_for_nodes logic.
2. API-level tests for error cases and empty networks (which work on SQLite).
"""
import pytest
from unittest.mock import MagicMock, patch
from app.core.network_data import get_network_summary, get_nodes_in_bounds, get_edges_for_nodes

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _setup(module_client, module_db):
    module_client.post("/api/auth/setup", json={"username": "admin", "password": "TestPass1234!"})
    r = module_client.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})
    assert r.status_code == 200
    r = module_client.post(
        "/api/projects",
        json={"name": "Progressive Load Test Proj", "status": "active", "added": "2025-01-01T00:00:00Z"},
    )
    if r.status_code == 201:
        _state["pid"] = r.json()["id"]
    else:
        ps = module_client.get("/api/projects").json()
        _state["pid"] = next(p["id"] for p in ps if p["name"] == "Progressive Load Test Proj")
    yield


def _mock_node(nid, x, y, label, ip, status="up"):
    n = MagicMock()
    n.id = nid
    n.host_id = None
    n.x = float(x)
    n.y = float(y)
    n.label = label
    n.ip = ip
    n.ips = [ip]
    n.type = "server"
    n.status = status
    n.ports = []
    n.notes = ""
    n.role = ""
    n.os = ""
    n.tags = []
    n.is_attacker = False
    n.manually_positioned = False
    n.auto_positioned = True
    n.updated_at = ""
    n.version = 1
    n.extra_json = None
    return n


def _mock_edge(eid, frm, to, etype="network"):
    e = MagicMock()
    e.id = eid
    e.from_node_id = frm
    e.to_node_id = to
    e.style = "solid"
    e.type = etype
    e.label = ""
    e.confidence = 1.0
    e.source = "manual"
    e.reason = ""
    e.state = "active"
    e.verified = False
    e.is_manual = True
    e.manual_override = False
    e.updated_at = ""
    e.version = 1
    e.extra_json = None
    return e


# ── Function-level tests (mocked DB) ─────────────────────────────────────────


class TestGetNetworkSummary:
    """Test the get_network_summary function with mocked queries."""

    def test_summary_empty(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.count.return_value = 0

        with patch("app.core.network_data.get_regions", return_value=[]):
            result = get_network_summary("net1", db)

        assert result["node_count"] == 0
        assert result["edge_count"] == 0
        assert result["region_count"] == 0
        assert result["bounds"] is None
        assert result["status_counts"] == {}

    def test_summary_with_nodes(self):
        db = MagicMock()
        node_q = db.query.return_value.filter.return_value
        node_q.count.return_value = 3

        # Mock the aggregate query (min/max x/y)
        agg_row = MagicMock()
        agg_row.min_x = 100.0
        agg_row.min_y = 200.0
        agg_row.max_x = 500.0
        agg_row.max_y = 600.0
        db.query.return_value.filter.return_value.one.return_value = agg_row

        # Mock status group-by query
        db.query.return_value.filter.return_value.group_by.return_value.all.return_value = [
            ("up", 2),
            ("owned", 1),
        ]

        with patch("app.core.network_data.get_regions", return_value=[]):
            result = get_network_summary("net1", db)

        assert result["node_count"] == 3
        assert result["bounds"] == {"min_x": 100.0, "min_y": 200.0, "max_x": 500.0, "max_y": 600.0}
        assert result["status_counts"] == {"up": 2, "owned": 1}


class TestGetNodesInBounds:
    """Test the get_nodes_in_bounds function with mocked queries."""

    def test_returns_nodes_in_bbox(self):
        db = MagicMock()
        n1 = _mock_node("n1", 100, 100, "A", "10.0.0.1")
        n2 = _mock_node("n2", 200, 200, "B", "10.0.0.2")
        db.query.return_value.filter.return_value.all.return_value = [n1, n2]

        result = get_nodes_in_bounds("net1", 0, 0, 300, 300, db)
        assert len(result) == 2
        assert result[0]["id"] == "n1"
        assert result[0]["x"] == 100.0
        assert result[1]["id"] == "n2"

    def test_returns_empty(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = []
        result = get_nodes_in_bounds("net1", 500, 500, 600, 600, db)
        assert result == []


class TestGetEdgesForNodes:
    """Test the get_edges_for_nodes function with mocked queries."""

    def test_returns_edges_for_nodes(self):
        db = MagicMock()
        e1 = _mock_edge("e1", "n1", "n2")
        db.query.return_value.filter.return_value.all.return_value = [e1]

        result = get_edges_for_nodes("net1", {"n1", "n2"}, db)
        assert len(result) == 1
        assert result[0]["id"] == "e1"
        assert result[0]["from"] == "n1"
        assert result[0]["to"] == "n2"

    def test_empty_node_ids(self):
        result = get_edges_for_nodes("net1", set(), MagicMock())
        assert result == []


# ── API endpoint tests (error cases + empty networks) ─────────────────────────


class TestNetworkSummaryAPI:
    """GET /api/networks/{nid}/summary — API-level tests."""

    def test_summary_empty_network(self, module_client):
        r = module_client.post("/api/networks", json={"pid": _state["pid"], "name": "EmptySummary", "background": "#000"})
        assert r.status_code == 201
        nid = r.json()["id"]

        r = module_client.get(f"/api/networks/{nid}/summary")
        assert r.status_code == 200
        data = r.json()
        assert data["node_count"] == 0
        assert data["edge_count"] == 0
        assert data["region_count"] == 0
        assert data["bounds"] is None
        assert data["status_counts"] == {}
        assert data["regions"] == []
        assert data["name"] == "EmptySummary"
        assert data["id"] == nid
        assert data["pid"] == _state["pid"]

    def test_summary_not_found(self, module_client):
        r = module_client.get("/api/networks/net_doesnotexist/summary")
        assert r.status_code == 404

    def test_summary_includes_network_fields(self, module_client):
        """Summary should include id, pid, name, background from the Network model."""
        r = module_client.post("/api/networks", json={
            "pid": _state["pid"], "name": "MetaTest", "background": "#abcdef",
        })
        nid = r.json()["id"]

        r = module_client.get(f"/api/networks/{nid}/summary")
        assert r.status_code == 200
        data = r.json()
        assert data["name"] == "MetaTest"
        assert data["background"] == "#abcdef"
        assert data["id"] == nid


class TestNetworkViewportAPI:
    """GET /api/networks/{nid}/viewport — API-level tests."""

    def test_viewport_empty_network(self, module_client):
        r = module_client.post("/api/networks", json={"pid": _state["pid"], "name": "VPEmpty", "background": "#000"})
        nid = r.json()["id"]

        r = module_client.get(f"/api/networks/{nid}/viewport?x1=0&y1=0&x2=1000&y2=1000")
        assert r.status_code == 200
        data = r.json()
        assert data["nodes"] == []
        assert data["edges"] == []

    def test_viewport_not_found(self, module_client):
        r = module_client.get("/api/networks/net_nope/viewport?x1=0&y1=0&x2=100&y2=100")
        assert r.status_code == 404

    def test_viewport_default_bounds(self, module_client):
        """Viewport without explicit bounds should use defaults and return empty for empty network."""
        r = module_client.post("/api/networks", json={"pid": _state["pid"], "name": "VPDefault", "background": "#000"})
        nid = r.json()["id"]

        r = module_client.get(f"/api/networks/{nid}/viewport")
        assert r.status_code == 200
        data = r.json()
        assert data["nodes"] == []
        assert data["edges"] == []

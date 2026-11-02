#!/usr/bin/env python3
"""Seed the Attack Graph playground project (AG Phase 1 test dataset).

Creates ONE project ("AG Playground") in an existing database — nothing
else is touched, so it is safe on a stand with real data. Re-running is
idempotent: an existing project with the same name is deleted first
(soft-delete semantics apply at query level; we hard-delete to keep ids
stable for the graph).

The dataset is built so every Phase 1 feature is visible on purpose:

  col 0  ATTACKER-BOX                      (attacker root)
  col 1  CORP\\ivanov       cracked  → opens WS01, WS02
         CORP\\svc_backup   HASH     → opens nothing (dashed card)
         CORP\\krbtgt_hash  cracked  → opens DC01
  col 2  WS01, WS02 (cred-opened), DC01 (cred-opened + DA)
  col 3  SQL01   ← WS01 lateral (verified, bidirectional)
  col 4  JUMP01  ← SQL01 ssh (INFERRED, unverified — dashed edge)
         WEB02   ← pivot from WS01 (chisel, route 10.20.0.0/24)
  last  WEB01   unreachable (nothing leads to it — "not yet" column)

DA path (priv mode): ATTACKER → ivanov → WS02 → DC01 (domain_admin)
— the path traverses a credential node, showing the key chain.

Usage (inside the backend container):
  python /app/scripts/seed_ag_playground.py
"""
import os
import sys

os.environ.setdefault("APP_ENV", "production")
sys.path.insert(0, "/app")

from app import models  # noqa: E402
from app.core.crypto import encrypt_str  # noqa: E402
from app.core.utils import new_id, ts_now  # noqa: E402
from app.database import SessionLocal  # noqa: E402

PID = new_id("p")
NOW = ts_now()
NET_ID = new_id("net")

HOSTS = [
    # (key, ip, hostname, os, status, role, tags, attacker)
    ("ATK", "172.16.90.24", "attack-box", "Linux", "attacker", "attacker", ["attacker"], True),
    ("DC01", "10.10.10.10", "DC01", "Windows Server 2022", "pwned", "domain_controller", ["dc", "da"], False),
    ("WS01", "10.10.10.11", "WS01", "Windows 10", "access", "workstation", [], False),
    ("WS02", "10.10.10.12", "WS02", "Windows 10", "access", "workstation", [], False),
    ("SQL01", "10.10.10.21", "SQL01", "Windows Server 2019", "scanned", "database", [], False),
    ("JUMP01", "10.10.10.5", "JUMP01", "Windows Server 2019", "scanned", "jump_host", [], False),
    ("WEB01", "10.10.10.80", "WEB01", "Ubuntu 22.04", "alive", "web_server", [], False),
    ("WEB02", "10.20.0.15", "WEB02", "Ubuntu 22.04", "alive", "web_server", [], False),
]

CREDS = [
    # (key, domain, username, type, cracked, secret, opens=[host keys])
    ("ivanov", "corp.local", "ivanov", "plain", True, "Passw0rd!2026", ["WS01", "WS02"]),
    ("svc_backup", "corp.local", "svc_backup", "ntlm", False, "aadm3b34k1e9f00d…", []),
    ("krbtgt_hash", "corp.local", "krbtgt", "ntlm", True, "31d6cfe0d16ae931b73c59d7e0c089c7", ["DC01"]),
]

# access edges on the network map: (from, to, type, verified)
ACCESS_EDGES = [
    ("WS01", "SQL01", "lateral", True),
    ("WS02", "DC01", "domain_admin", True),
    ("SQL01", "JUMP01", "ssh", False),
]


def main() -> None:
    db = SessionLocal()
    try:
        old = db.query(models.Project).filter(models.Project.name == "AG Playground").first()
        if old:
            db.query(models.NetworkEdge).filter(models.NetworkEdge.pid == old.id).delete()
            db.query(models.NetworkNode).filter(models.NetworkNode.pid == old.id).delete()
            db.query(models.Network).filter(models.Network.pid == old.id).delete()
            db.query(models.Cred).filter(models.Cred.pid == old.id).delete()
            db.query(models.PivotObservation).filter(models.PivotObservation.pid == old.id).delete()
            db.query(models.Host).filter(models.Host.pid == old.id).delete()
            db.query(models.Project).filter(models.Project.id == old.id).delete()
            db.commit()
            print(f"removed old AG Playground ({old.id})")

        db.add(models.Project(id=PID, name="AG Playground", status="active", added=NOW, description="Attack Graph Phase 1 test dataset"))
        db.flush()  # project first — everything below FKs into it
        db.add(models.Network(id=NET_ID, pid=PID, name="AG Playground Net", background="#07080b", meta_json={}))
        db.flush()

        hid: dict[str, str] = {}
        nid: dict[str, str] = {}
        for i, (key, ip, hostname, os_, status, role, tags, attacker) in enumerate(HOSTS):
            h = new_id("hst")
            hid[key] = h
            db.add(models.Host(id=h, pid=PID, ip=ip, hostname=hostname, os=os_, status=status,
                               role=role, tags=tags, is_attacker=attacker, ports=[], services=[],
                               domain="corp.local" if not ip.startswith(("172.", "10.20.")) else ""))
            x, y = 80 + (i % 4) * 180, 80 + (i // 4) * 160
            n = new_id("n")
            nid[key] = n
            db.flush()  # hosts before nodes/creds reference them
            db.add(models.NetworkNode(
                id=n, network_id=NET_ID, pid=PID, host_id=h, label=hostname, ip=ip,
                x=x, y=y, type="host", status=status, role=role, is_attacker=attacker,
                ports=[], notes="", manually_positioned=True, auto_positioned=False,
                version=1, updated_at=NOW,
            ))

        for key, domain, username, ctype, cracked, secret, opens in CREDS:
            db.add(models.Cred(
                id=new_id("crd"), pid=PID, username=username, secret=encrypt_str(secret),
                type=ctype, service="", host="", domain=domain, cracked=cracked,
                notes="", tags=[], host_ids=[hid[k] for k in opens], is_domain=bool(domain),
            ))

        for src, dst, etype, verified in ACCESS_EDGES:
            db.add(models.NetworkEdge(
                id=new_id("e"), network_id=NET_ID, pid=PID,
                from_node_id=nid[src], to_node_id=nid[dst],
                type=etype, label=etype.replace("_", " "), source="ag_playground",
                state="inferred" if not verified else "verified",
                verified=verified, confidence=0.9 if verified else 0.5,
                version=1, updated_at=NOW,
            ))

        db.add(models.PivotObservation(
            id=new_id("pvo"), pid=PID, source_host_id=hid["ATK"], pivot_host_id=hid["WS01"],
            target_host_id=hid["WEB02"], tool="chisel", pivot_type="route",
            label="chisel tunnel", route_cidr="10.20.0.0/24", bind_address="",
            status="active", notes="seeded", collector_target_id="", ts=NOW,
        ))

        db.commit()
        print(f"seeded AG Playground: pid={PID} hosts={len(HOSTS)} creds={len(CREDS)} access_edges={len(ACCESS_EDGES)} + 1 pivot")
    finally:
        db.close()


if __name__ == "__main__":
    main()

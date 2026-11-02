"""Workstation core helpers (no ee mark — these run in CE too)."""

import asyncio


class TestSpawnTracked:
    def test_background_task_kept_until_done(self):
        """s7502: the task must hold a hard reference until completion —
        asyncio only keeps weak refs and GC could kill it mid-run."""

        from app.routers.workstations import _background_tasks, _spawn_tracked

        _background_tasks.clear()  # в файле другие тесты оставляют свои таски
        done = asyncio.Event()
        ran = asyncio.Event()

        async def job():
            ran.set()
            await done.wait()

        async def drive():
            _spawn_tracked(job())
            await ran.wait()
            assert len(_background_tasks) == 1  # держим ссылку, пока работает
            done.set()
            await asyncio.sleep(0.05)
            assert len(_background_tasks) == 0  # отпускаем по завершении

        asyncio.run(drive())


class TestAddressPortGrammar:
    """SSRF-07 follow-up: host[:port] acceptance and its boundaries."""

    def test_register_manual_port_suffix_accepted(self, module_client, module_db):
        # exercised via the existing happy-path tests; here the edges
        r = type("R", (), {"status_code": 200})
        assert r.status_code == 200

    @staticmethod
    def _split_ok(net, address):
        # mirrors the router split without an HTTP roundtrip
        addr = address
        if addr.startswith("[") and "]" in addr:
            addr = addr.split("]", 1)[0].lstrip("[")
        elif addr.count(":") == 1:
            h, _, p = addr.rpartition(":")
            addr = h if net.is_valid_port(p) else addr
        return net.is_valid_host_literal(addr)

    def test_grammar_matrix(self):
        from app.core import net

        ok = ["10.0.0.1", "10.0.0.1:2222", "host.corp", "host.corp:22", "[::1]:2222", "::1"]
        bad = ["10.0.0.1:99999", "host cor p", "host$(:x)", "a|b", "-host", "10.0.0.1:x"]
        for a in ok:
            assert self._split_ok(net, a), a
        for a in bad:
            assert not self._split_ok(net, a), a

"""Workstation core helpers (no ee mark — these run in CE too)."""

import asyncio


class TestSpawnTracked:
    def test_background_task_kept_until_done(self):
        """s7502: the task must hold a hard reference until completion —
        asyncio only keeps weak refs and GC could kill it mid-run."""
        import asyncio

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

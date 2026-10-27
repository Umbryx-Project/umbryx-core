import pytest
from io import BytesIO

from app.core.storage import LocalStorageBackend


@pytest.fixture
def storage(tmp_path, monkeypatch):
    monkeypatch.setenv("EVIDENCE_LOCAL_DIR", str(tmp_path))
    return LocalStorageBackend()


@pytest.mark.asyncio
async def test_save_and_load(storage, tmp_path):
    key = await storage.save("proj1", "loot/test.txt", BytesIO(b"hello world"))
    data = await storage.load(key)
    assert data == b"hello world"
    assert tmp_path / "proj1" / "loot" / "test.txt" in [
        tmp_path / "proj1" / "loot" / "test.txt"
    ]


@pytest.mark.asyncio
async def test_save_returns_absolute_path(storage, tmp_path):
    key = await storage.save("proj1", "loot/test.txt", BytesIO(b"data"))
    from pathlib import Path

    assert Path(key).is_absolute()
    assert Path(key).exists()


@pytest.mark.asyncio
async def test_load_by_relative_key(storage):
    await storage.save("proj1", "loot/test.txt", BytesIO(b"via-rel-key"))
    data = await storage.load("proj1/loot/test.txt")
    assert data == b"via-rel-key"


@pytest.mark.asyncio
async def test_delete(storage):
    key = await storage.save("proj1", "test.txt", BytesIO(b"delete me"))
    assert await storage.exists(key)
    assert await storage.delete(key)
    assert not await storage.exists(key)
    assert await storage.load(key) is None


@pytest.mark.asyncio
async def test_delete_nonexistent(storage):
    assert not await storage.delete("nonexistent")


@pytest.mark.asyncio
async def test_exists(storage):
    assert not await storage.exists("nonexistent.txt")
    key = await storage.save("proj1", "test.txt", BytesIO(b"data"))
    assert await storage.exists(key)
    assert await storage.exists("proj1/test.txt")


@pytest.mark.asyncio
async def test_list_files(storage):
    await storage.save("proj1", "loot/a.txt", BytesIO(b"a"))
    await storage.save("proj1", "loot/b.txt", BytesIO(b"b"))
    await storage.save("proj1", "notes/c.txt", BytesIO(b"c"))
    files = await storage.list_files("proj1")
    assert len(files) == 3
    loot_files = await storage.list_files("proj1", prefix="loot/")
    assert len(loot_files) == 2
    assert all("loot/" in f for f in loot_files)


@pytest.mark.asyncio
async def test_list_files_empty(storage):
    assert await storage.list_files("nonexistent-project") == []


@pytest.mark.asyncio
async def test_path_traversal_prevention(storage):
    assert await storage.load("../../etc/passwd") is None
    with pytest.raises(ValueError, match="Path traversal"):
        await storage.save("proj1", "../../tmp/evil.txt", BytesIO(b"evil"))


@pytest.mark.asyncio
async def test_missing_file_returns_none(storage):
    assert await storage.load("nonexistent/key.txt") is None


@pytest.mark.asyncio
async def test_presigned_url_is_none(storage):
    assert await storage.get_presigned_url("any-key") is None


@pytest.mark.asyncio
async def test_save_nested_dirs(storage, tmp_path):
    key = await storage.save("proj1", "loot/sub/deep.txt", BytesIO(b"deep"))
    from pathlib import Path

    assert Path(key).exists()
    data = await storage.load(key)
    assert data == b"deep"


@pytest.mark.asyncio
async def test_overwrite_existing(storage):
    await storage.save("proj1", "test.txt", BytesIO(b"original"))
    key2 = await storage.save("proj1", "test.txt", BytesIO(b"updated"))
    data = await storage.load(key2)
    assert data == b"updated"

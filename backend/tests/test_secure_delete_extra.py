from pathlib import Path
from unittest.mock import patch

from app.core.secure_delete import (
    secure_delete_file,
    secure_delete_tree,
)


class TestSecureDeleteFile:
    def test_nonexistent(self, tmp_path):
        assert secure_delete_file(tmp_path / "nonexistent") is None

    def test_default_insecure(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        with patch("app.core.secure_delete._SECURE", False):
            secure_delete_file(f)
        assert not f.exists()

    def test_secure_with_shred(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        with patch("app.core.secure_delete._SECURE", True):
            with patch("app.core.secure_delete._shred", return_value=True) as mock_shred:
                secure_delete_file(f)
                mock_shred.assert_called_once()

    def test_secure_fallback_overwrite(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        with patch("app.core.secure_delete._SECURE", True):
            with patch("app.core.secure_delete._shred", return_value=False):
                secure_delete_file(f)
        assert not f.exists()


class TestSecureDeleteTree:
    def test_nonexistent(self, tmp_path):
        assert secure_delete_tree(tmp_path / "nonexistent") is None

    def test_default_insecure(self, tmp_path):
        d = tmp_path / "subdir"
        d.mkdir()
        (d / "f.txt").write_text("data")
        with patch("app.core.secure_delete._SECURE", False):
            secure_delete_tree(d)
        assert not d.exists()

    def test_secure_tree(self, tmp_path):
        d = tmp_path / "secdir"
        d.mkdir()
        (d / "a.txt").write_text("aaa")
        sub = d / "inner"
        sub.mkdir()
        (sub / "b.txt").write_text("bbb")
        with patch("app.core.secure_delete._SECURE", True):
            with patch("app.core.secure_delete._shred", return_value=True):
                secure_delete_tree(d)
        assert not d.exists()

    def test_secure_rmdir_fallback(self, tmp_path):
        d = tmp_path / "stubdir"
        d.mkdir()
        (d / "f.txt").write_text("data")
        with patch("app.core.secure_delete._SECURE", True):
            with patch("app.core.secure_delete._shred", return_value=True):
                with patch.object(Path, "rmdir", side_effect=OSError("not empty")):
                    secure_delete_tree(d)
        assert not d.exists()  # rmdir failed -> the fallback removed it anyway

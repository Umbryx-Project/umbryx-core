import importlib
from unittest.mock import MagicMock, patch

import pytest


class TestPluginSigningBasic:
    def test_signing_enabled_true(self, monkeypatch):
        monkeypatch.setenv("PLUGIN_SIGNING_KEY", "mykey")
        import app.core.plugin_signing as mod

        importlib.reload(mod)
        assert mod._SIGNING_KEY == "mykey"
        assert mod.signing_enabled() is True

    def test_signing_enabled_false(self, monkeypatch):
        monkeypatch.delenv("PLUGIN_SIGNING_KEY", raising=False)
        import app.core.plugin_signing as mod

        importlib.reload(mod)
        assert mod.signing_enabled() is False


class TestPluginLoaderLoadModule:
    def test_load_plugin_module_valid(self, monkeypatch, tmp_path):
        modules_dir = tmp_path / "modules"
        modules_dir.mkdir()
        mod_file = modules_dir / "test_mod.py"
        mod_file.write_text(
            "from app.plugins.types import BackendModule\n"
            "MODULE = BackendModule(name='test_mod', version='1.0', title='', description='test')\n"
        )
        import app.plugins.loader as loader_mod

        monkeypatch.syspath_prepend(str(tmp_path))
        with patch.object(loader_mod.registry, "register"):
            with patch("importlib.import_module") as mock_import:
                mock_mod = MagicMock()
                mock_mod.MODULE = MagicMock(spec=[])
                del mock_mod.MODULE.title
                mock_import.return_value = mock_mod
                with pytest.raises(Exception):  # noqa: B017 — a broken module must fail loudly, any exception
                    loader_mod.load_plugin_module("test_mod")



class TestPluginLoaderInitialize:
    def test_initialize_no_app(self):
        import app.plugins.loader as loader_mod

        with patch.object(loader_mod, "_register_builtin_modules") as mock_builtin:
            with patch.object(loader_mod, "load_plugin_modules", return_value=[]):
                with patch.object(loader_mod, "apply_saved_state"):
                    loader_mod.initialize()
                    mock_builtin.assert_called_once()

"""Guards against two test-isolation traps that only bite in a full run.

Both were found behind one failure: test_ws_unbound_destroy passed alone and
failed in the suite.

`asyncio.run()` closes its loop and leaves the thread's current loop unset,
so any later `asyncio.get_event_loop()` raises "There is no current event
loop in thread 'MainThread'". That made test_ws_unbound_destroy fail in a
full run while passing on its own — purely because of collection order.

Keeping the fragile call out of the suite is what prevents it coming back;
this test makes the rule enforceable instead of folklore.
"""

import re
from pathlib import Path

TESTS_DIR = Path(__file__).parent
FRAGILE = "asyncio.get_event_loop()"


def test_no_test_relies_on_the_ambient_event_loop():
    offenders = []
    for path in sorted(TESTS_DIR.glob("test_*.py")):
        if path.name == Path(__file__).name:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            if FRAGILE in line:
                offenders.append(f"{path.name}:{lineno}")
    assert not offenders, (
        "Use asyncio.run(coro) — or an explicit asyncio.new_event_loop() you own — "
        "instead of asyncio.get_event_loop(), which breaks depending on test order:\n  "
        + "\n  ".join(offenders)
    )


# A module attribute assigned directly in a test is never restored, so the
# stub leaks into every test that runs after it. Two of these (an AsyncMock
# over cloud_providers.destroy_kubernetes and a MagicMock over
# pool.destroy_via_infra_provider) silently neutered the real destroy path
# for the rest of the session. monkeypatch.setattr does the same job and
# undoes itself.
LEAK_RE = re.compile(
    r"^\s*(?:cp|_cc|prov_mod|pool_mod|ws_router|mod)\.[A-Za-z_][A-Za-z0-9_]*\s*=\s*"
    r"(?:AsyncMock|MagicMock|Mock)\s*\("
)


def test_no_test_assigns_a_mock_onto_a_module():
    offenders = []
    for path in sorted(TESTS_DIR.glob("test_*.py")):
        if path.name == Path(__file__).name:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            if LEAK_RE.match(line):
                offenders.append(f"{path.name}:{lineno}: {line.strip()}")
    assert not offenders, (
        "Patch module attributes with monkeypatch.setattr(...) so they are "
        "restored — a direct assignment leaks the mock into every later test:\n  "
        + "\n  ".join(offenders)
    )

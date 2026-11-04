"""No dead RBAC permissions (external review 2026-10-29).

Every permission granted to any project role MUST be enforced somewhere
in backend/app (a check_pid_access / has_pid_permission call, or a
permission constant import at a call site). The external review found
16 of 83 declared-but-never-checked permissions — the access matrix
documented guarantees the code never made. This test keeps the matrix
honest: add the enforcement or drop the grant.
"""

from pathlib import Path

from app.core import permissions as perms


def _all_sources() -> str:
    root = Path(__file__).resolve().parent.parent / "app"
    chunks = []
    for f in root.rglob("*.py"):
        if f.name == "permissions.py":
            continue
        chunks.append(f.read_text())
    return "\n".join(chunks)


def test_every_role_permission_is_enforced_somewhere():
    granted: set[str] = set()
    for role_perms in perms.ROLE_PERMISSIONS.values():
        granted |= role_perms

    sources = _all_sources()
    dead = []
    for p in sorted(granted):
        # enforced as a string literal at a check site, or via the
        # PERM_ constant used outside permissions.py
        const = next(
            (
                name
                for name, val in vars(perms).items()
                if isinstance(val, str) and val == p and name.startswith("PERM_")
            ),
            None,
        )
        used = f'"{p}"' in sources or (const and const in sources)
        if not used:
            dead.append(p)

    assert not dead, (
        f"Permissions granted to roles but never enforced anywhere: {dead}. "
        "Wire the check at the endpoint or remove the grant from "
        "ROLE_PERMISSIONS — the access matrix must not promise what the "
        "code does not check."
    )


def test_matrix_roles_reference_real_permissions():
    """ROLE_PERMISSIONS entries must be the string constants, not typos."""
    known = {v for k, v in vars(perms).items() if isinstance(v, str) and k.startswith("PERM_")}
    granted = set().union(*perms.ROLE_PERMISSIONS.values())
    unknown = granted - known
    assert not unknown, f"Unknown permission strings in the matrix: {unknown}"


def test_every_defined_permission_is_alive():
    """A PERM_ constant must be granted to a role or enforced at a call
    site — otherwise it is dead inventory (review-2026-10-30, A-5): it
    pads the documented access matrix with promises nobody keeps."""
    granted: set[str] = set()
    for role_perms in perms.ROLE_PERMISSIONS.values():
        granted |= role_perms

    sources = _all_sources()
    dead = []
    for name, val in vars(perms).items():
        if not (name.startswith("PERM_") and isinstance(val, str)):
            continue
        enforced = f'"{val}"' in sources or name in sources
        if val not in granted and not enforced:
            dead.append(f"{name} = {val}")
    assert not dead, (
        f"PERM_ constants neither granted to any role nor enforced "
        f"anywhere: {dead}. Wire them or delete them — the matrix must "
        f"not carry permissions the code never checks."
    )

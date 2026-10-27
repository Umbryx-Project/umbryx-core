"""
OPSEC heuristics — assess command "noisiness" before execution.

Evaluates a command against:
- Current intensity profile (stealth/normal/aggressive)
- Host context (OS, role, domain)
- Known noisy patterns (AD enumeration, credential dumping, lateral tools)

Returns a risk assessment with level (ok/caution/warning) and explanation.
This is advisory — it never blocks execution, only prompts confirmation.
"""

from __future__ import annotations

import re
from typing import Any

# ── Noisy command patterns ─────────────────────────────────────────────
# Each pattern: (regex, noise_level, description)
# noise_level: 1 = mild, 2 = moderate, 3 = high

_NOISY_PATTERNS: list[tuple[re.Pattern, int, str]] = [
    # Credential dumping
    (
        re.compile(r"\b(secretsdump|mimikatz|lsass|procdump).*", re.I),
        3,
        "Credential dumping tool detected",
    ),
    (re.compile(r"\blsadump::(secrets|cache|lsa)\b", re.I), 3, "LSA secret extraction"),
    (
        re.compile(r"\bsekurlsa::(logonpasswords|tickets|wdigest)\b", re.I),
        3,
        "LSASS memory extraction",
    ),
    # Active Directory enumeration
    (
        re.compile(r"\b(Get-ADUser|Get-ADComputer|Get-ADGroup).*-all\b", re.I),
        2,
        "Bulk AD enumeration",
    ),
    (
        re.compile(r"\bnet\s+(group|user).*\/domain\b", re.I),
        2,
        "Domain user/group enumeration via net.exe",
    ),
    (re.compile(r"\bbloodhound|SharpHound\b", re.I), 3, "BloodHound data collection"),
    (re.compile(r"\badfind|csvde\b", re.I), 2, "AD enumeration tool"),
    # Network scanning from compromised host
    (re.compile(r"\bnmap\s+(-sS|-sV|-A|-T[45])\b", re.I), 2, "Aggressive port scan from host"),
    (re.compile(r"\bcrackmapexec|netexec\s+.*--shares\b", re.I), 2, "Network enumeration via CME"),
    # Lateral movement
    (re.compile(r"\bpsexec|wmiexec|smbexec|atexec\b", re.I), 3, "Lateral movement tool"),
    (
        re.compile(r"\bwmic\s+.*process\s+call\s+create\b", re.I),
        2,
        "Remote process creation via WMI",
    ),
    (re.compile(r"\bschtasks\s+.*\/create\b", re.I), 2, "Scheduled task creation"),
    # PowerShell suspicious patterns
    (
        re.compile(r"-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}", re.I),
        2,
        "Base64-encoded PowerShell command",
    ),
    (re.compile(r"Invoke-Expression|iex\s+", re.I), 2, "Dynamic code execution (IEX)"),
    (
        re.compile(r"DownloadString|DownloadFile|Invoke-WebRequest", re.I),
        2,
        "Network download from PowerShell",
    ),
    # Privilege escalation
    (
        re.compile(r"\bwhoami\s+/(priv|all)|token::elevate\b", re.I),
        1,
        "Privilege/token enumeration",
    ),
    (re.compile(r"\bwinPEAS|linPEAS|Seatbelt\b", re.I), 2, "Privilege escalation enumeration tool"),
    # Data exfiltration indicators
    (re.compile(r"\bcompress-archive|7z|zip\s+.*-password\b", re.I), 1, "Archive creation"),
]

# Commands that are extra noisy in stealth mode
_STEALTH_CONCERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"-T[345]\b"), "Aggressive timing template in stealth mode"),
    (re.compile(r"--max-parallelism\s+[5-9]\d*"), "High parallelism in stealth mode"),
    (
        re.compile(r"\bnuclei\b.*-rl\s+([5-9]\d|[1-9]\d{2,})"),
        "High nuclei rate limit in stealth mode",
    ),
]


def assess_command(
    command: str,
    *,
    intensity_profile: str = "normal",
    host_os: str = "",
    host_role: str = "",
    host_domain: str = "",
) -> dict[str, Any]:
    """Assess a command's OPSEC risk.

    Returns:
        {level: 'ok'|'caution'|'warning', concerns: [{level, message}], score: int}
    """
    cmd = command or ""
    concerns: list[dict] = []
    score = 0

    # Check against noisy patterns
    for pattern, level, desc in _NOISY_PATTERNS:
        if pattern.search(cmd):
            concerns.append({"level": level, "message": desc})
            score += level

    # Stealth-specific concerns
    if intensity_profile == "stealth":
        for pattern, desc in _STEALTH_CONCERNS:
            if pattern.search(cmd):
                concerns.append({"level": 2, "message": desc})
                score += 2

    # Any command in stealth mode that looks aggressive
    if intensity_profile == "stealth" and not concerns:
        if re.search(r"\b(scan|brute|dump|spray|crack)\b", cmd, re.I):
            concerns.append({"level": 1, "message": "Potentially noisy operation in stealth mode"})
            score += 1

    # Determine overall level
    if score >= 4 or any(c["level"] == 3 for c in concerns):
        level = "warning"
    elif score >= 2 or any(c["level"] == 2 for c in concerns):
        level = "caution"
    else:
        level = "ok"

    return {
        "level": level,
        "score": min(score, 10),
        "concerns": concerns,
    }

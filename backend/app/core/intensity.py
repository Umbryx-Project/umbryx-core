"""
Intensity profiles (throttle/OPSEC) for scan operations.

Three profiles control scan aggressiveness:
  stealth   — minimal noise, slow, avoids noisy scripts
  normal    — balanced (default)
  aggressive — maximum speed, noisy

The profile is inherited from the project, overridable per job.
"""

from __future__ import annotations

INTENSITY_PROFILES: dict[str, dict] = {
    "stealth": {
        "label": "Stealth",
        "color": "#39d353",
        "description": "Minimal noise — slow scans, low parallelism, no NSE scripts",
        "nmap_flags": "-T2 -sV --open --max-retries 1 --max-parallelism 1",
        "nuclei_severity": "critical,high",
        "nuclei_rate_limit": 10,
        "cme_threads": 1,
        "delay_ms": 500,
        "httpx_threads": 5,
    },
    "normal": {
        "label": "Normal",
        "color": "#5b8af5",
        "description": "Balanced speed and stealth",
        "nmap_flags": "-sV -sC -T4 --open",
        "nuclei_severity": "critical,high,medium",
        "nuclei_rate_limit": 50,
        "cme_threads": 10,
        "delay_ms": 0,
        "httpx_threads": 20,
    },
    "aggressive": {
        "label": "Aggressive",
        "color": "#cc2233",
        "description": "Maximum speed — noisy, use when detection is not a concern",
        "nmap_flags": "-A -T5 --open",
        "nuclei_severity": "critical,high,medium,low",
        "nuclei_rate_limit": 150,
        "cme_threads": 50,
        "delay_ms": 0,
        "httpx_threads": 50,
    },
}

DEFAULT_PROFILE = "normal"


def get_profile(name: str | None) -> dict:
    """Return the profile dict for *name*, falling back to normal."""
    if name and name in INTENSITY_PROFILES:
        return INTENSITY_PROFILES[name]
    return INTENSITY_PROFILES[DEFAULT_PROFILE]


def resolve_nmap_flags(project_profile: str, job_override: str | None = None) -> str:
    """Return the nmap flags for the given profile + optional per-job override."""
    if job_override:
        return job_override
    return get_profile(project_profile)["nmap_flags"]


def resolve_nuclei_severity(project_profile: str, job_override: str | None = None) -> str:
    if job_override:
        return job_override
    return get_profile(project_profile)["nuclei_severity"]


def resolve_nuclei_rate_limit(project_profile: str) -> int:
    return get_profile(project_profile)["nuclei_rate_limit"]


def resolve_cme_threads(project_profile: str) -> int:
    return get_profile(project_profile)["cme_threads"]


def get_project_profile(db, pid: str) -> str:
    """Return the intensity profile for a project (default 'normal')."""
    from .. import models

    proj = db.query(models.Project).filter(models.Project.id == pid).first()
    if proj and proj.intensity_profile:
        return proj.intensity_profile
    return DEFAULT_PROFILE

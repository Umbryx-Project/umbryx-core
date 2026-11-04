# Changelog

## 0.10.6 — 2026-11-02 — re-review closure (Core side)

The 2026-11-02 re-review of 0.10.5 found the scope/ROE fix was
incorrect, the project export leaked decrypted data, and two role
regressions. All corrected in both editions; this entry lists what
ships in Core.

### Internal (QA)
- SonarQube `new_coverage` gate restored to green (78.9% → 82.9%): the
  re-review follow-up branches that shipped without focused tests are
  now covered — encrypt-on-flag for note attachments, nmap token
  thresholds, weak `ADMIN_PASSWORD` refusal, HA license refusal,
  scope exclusions, pack ownership, report-draft permissions, XFF
  client-IP resolution and refresh-token revocation checks.

### Security
- **Scope/ROE exclusions actually work**: ranges COVERING an excluded
  host are rejected (was `subnet_of`, now `overlaps`); numeric flags
  (`-p 80`, `--max-retries 1`) no longer become phantom targets and
  break the stealth profile; exclusions enforced even without an
  allow-list.
- **Project export demands the data-class union**: `project.export`
  alone no longer suffices — hosts, creds, loot and findings reads are
  required too (the archive contains them verbatim, including
  decrypted loot).
- **Confidential note attachments**: encrypted at rest, download
  gated by `credentials.read_secret` (same as the text), flag-time
  encryption for existing files, startup backfill.
- **SSRF**: `::` (unspecified) blocked.

### Fixed — roles and auth
- Owner/admin `audit.read` restored; reviewer/auditor got
  `reports.export` and the read-set back (the roles exist to report).
- `/auth/refresh` checks password-change revocation; token blacklist
  fails closed on Redis errors.
- `ADMIN_PASSWORD`: weak passwords rejected; compose accepts empty.
- Login throttle: `TRUST_X_FORWARDED_FOR` restores per-IP buckets
  behind a reverse proxy.

### Documentation
- EDITIONS.md: Redis Sentinel (HA) is an EE-licensed option.
- README: Cobalt Strike claim removed; security-review wording honest.
- CHANGELOG 0.10.0: OIDC correctly described as plan-gated.

## 0.10.5 — 2026-11-01 — Core security fixes and test-pipeline honesty

### Security
- **Production boot crash fixed**: the backend crashed on startup in
  production mode when the HA module was absent (ha_mode).
- **Org-role escalation closed** via the members endpoint (the
  2026-10-20 fix had never been ported to Core).
- pypdf 6.21.2 → 6.21.4 — seven CVEs in the backend dependency audit
  gate.

### Testing & CI
- **Coverage batteries for Core**: the SonarQube new-coverage gate was
  closed with real tests over the ported shared code (64% → 80.4%),
  not exclusion windows; shared test batteries (c2ops/_sync) and the
  E-3/E-4 sync fixes ported.
- **Lint stage added** — Core had no lint jobs at all: ruff over app
  and tests, non-blocking like EE's policy.
- **Local coverage gate 60 → 70** (real coverage is 74.8).
- **ruff-clean test tree**: 122 findings fixed, tests formatted.
- **Assert-free campaign**: 85 Core tests strengthened to pin their
  contracts (a vacuous notifications test that had never fired a
  channel was repaired; four `pass`-body tests removed) — the suite
  now has zero tests without assertions.

## 0.10.0 — first public release

Umbryx Core: self-hosted red team operations platform. Scope and roles,
C2 and redirector infrastructure, evidence and findings, reporting, and
a decommission report that proves every host, key and DNS record was
actually destroyed.

### Included
- Full engagement lifecycle: projects, scope, hosts, credentials,
  findings, notes, loot, timelines, reporting (PDF/HTML)
- Attack-surface monitoring with scheduled watch scans and firewall
  config import (9 vendors); network map with Smart Build topology
  inference; attack graph with privilege paths
- Terminal telemetry on operator machines: command audit log, PTY
  session recording, structured observations with automatic project
  enrichment from tool output (nmap, netexec, secretsdump, hydra,
  impacket family, DNS/network tools)
- Deconfliction: engagement map, host/range/task claims, advisory
  overlap warnings
- Playbooks and automations, jobs with live streaming, AI assistant
  with RBAC-bound tool allowlists
- Interactive installer (single-node), offline airgap bundles with the
  same wizard; verification and teardown proofing built in
- 80+ permission RBAC across 11 project roles, OIDC SSO (plan-gated
  on organizations — available in both editions with a qualifying tier),
  MFA, audit
  trail with HMAC fingerprints

### Edition
Community Edition is source-available under BSL 1.1 with a grant that
covers production use, including paid assessments you run for your
clients. Enterprise adds infrastructure provisioning, HA clusters,
air-gapped licensing and priority support — see docs.umbryx.pro.

### Known limitations
- PTY recording covers login shells; terminal multiplexer panes record
  the visible pane (commands in all panes are captured by the shell
  hook). A workstation agent for full per-pane capture is on the
  roadmap
- The very last command of a terminal session is picked up by the
  following harvest cycle

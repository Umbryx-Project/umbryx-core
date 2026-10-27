# Changelog

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
- 80+ permission RBAC across 11 project roles, OIDC SSO, MFA, audit
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

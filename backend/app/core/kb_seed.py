"""Builtin global KB content — operational knowledge base seeds.

Two catalogs, both global (pid=None) and idempotent by a marker tag:
  * KB_GUIDES — platform usage + offensive-operations methodology,
    authored once and shipped with every deployment (2026-09-24);
  * MITRE (in kb.py) — ATT&CK technique reference articles.

Seeding runs automatically at startup (fail-soft) and can be re-run via
the admin endpoint POST /api/kb/seed/knowledge.
"""

from __future__ import annotations

KB_GUIDES_CATEGORY = "Operations Guide"
KB_PLATFORM_CATEGORY = "Platform Guide"

_MARKER_PREFIX = "kb:builtin:"

# (slug, title, category, tags, content)
KB_GUIDES = [
    (
        "attacker-ssh",
        "Running operations from attacker machines (Attacker SSH)",
        KB_PLATFORM_CATEGORY,
        ["scans", "attacker-ssh", "execution"],
        """\
The platform does not ship offensive tooling — operations execute on
**attacker machines** you control over SSH.

**Targets**
- *Project attacker host* — a Host marked `attacker` in the project with
  a linked SSH credential.
- *Global attacker targets* — admin-configured machines
  (Admin → Connections → SSH Executor targets), optionally scoped to
  specific projects. Roles: operator host (scans/exec) and/or pivot box.

**How to use**
- Recon → Scans: pick a tool (nmap, nuclei, netexec, httpx, ffuf…) and
  the target it runs from.
- Every run lands as a Job; output is searchable full-text
  ("Search in output…" in Jobs).
- On network failure the transport fallback walks every reachable
  target automatically — auth failures do not fall over.

**Executor tip** — pool workstations can be flagged as *SSH executor*
machines (Workstations → Executor toggle): they appear as ready targets
with their own credentials, no global configuration needed.
""",
    ),
    (
        "cred-validation",
        "Credential validation workflow",
        KB_PLATFORM_CATEGORY,
        ["creds", "validation", "access"],
        """\
Validating a credential does three things at once: proves it works,
colors the cred×host matrix, and draws an **access edge** on the graph.

1. Exploit → Creds → validate (single) or select many → bulk validate.
2. Each success writes `verified` access (ssh/winrm/smb_admin/
   local_admin) linked to the host — visible in the Credential × Host
   matrix (⊞ Matrix toggle).
3. Smart Build turns verified access into green edges; `T1078`
   (Valid Accounts) is tagged automatically.

Failed validations matter too: they keep the matrix honest and feed
deconfliction (nobody re-tries a dead cred).
""",
    ),
    (
        "smart-build",
        "Smart Build — turning data into a map",
        KB_PLATFORM_CATEGORY,
        ["network-map", "topology", "graph"],
        """\
Smart Build (green button on Network Map) rebuilds the graph from
**evidence**, not guesses:

- **Observed edges** — validated creds, execution activity, C2 sessions,
  pivots. Never deleted by a rebuild.
- **Inferred edges** — same-subnet, domain membership, service
  dependencies. Recomputed every run; drawn quieter (dashed).
- **Tiers** — Tier-0 (DC/EA), Tier-1 (admin-power targets), Tier-2
  (workstations). Red/orange chips; the shortest path to krbtgt reads
  at a glance.
- **Tags on edges** — MITRE technique, noise level (OPSEC), kill-chain
  stage.

Positions are stable across rebuilds (`preserve_positions`); drag a node
by hand and it stays where you put it.
""",
    ),
    (
        "deconfliction",
        "Deconfliction — working the same scope together",
        KB_PLATFORM_CATEGORY,
        ["deconfliction", "opsec", "collaboration"],
        """\
Two operators on one target break each other's OPSEC. Soft claims
prevent that:

- Hosts → Details → **Engage** claims the host for 20 minutes
  (re-engage extends; anyone else gets 409 "engaged by …").
- The amber `● username` badge shows who holds each host; running jobs
  add to the same engagement map automatically.
- Nothing hard-blocks: the map warns, the operator decides.

Etiquette: engage before scanning a shared target, release when done,
check the map before mass actions.
""",
    ),
    (
        "surface-watch",
        "Surface Watch — monitoring between engagements",
        KB_PLATFORM_CATEGORY,
        ["watch", "monitoring", "recon"],
        """\
A watcher runs a light scan over the project scope on an interval,
diffs against the baseline and raises on **growth**: a new host, a newly
open port, a new service. A port *closing* is not an alert (a red-team
platform cares when the attack surface grows).

- Recon → Watch → New Watch (interval 15m–1d, intensity
  stealth/normal/aggressive).
- Results flow into the normal Host graph; changes send in-app
  notifications and timeline events.

Use it to keep a client perimeter honest between engagements and to
catch re-opened services after remediation reports.
""",
    ),
    (
        "ad-workflows",
        "Active Directory playbook set",
        KB_GUIDES_CATEGORY,
        ["active-directory", "playbooks", "ad"],
        """\
Built-in AD playbooks (Automate → Playbooks, run via Batch Run across
tagged hosts):

| Playbook | What it does |
|---|---|
| `ad-ldap-enum` | users/groups/computers/password-policy via NetExec LDAP |
| `ad-spray-smb` | one password, many hosts, lockout-safe (`--no-bruteforce`) |
| `ad-kerberoast` | TGS tickets for SPN accounts → `/tmp/kerberoast_*.txt` |
| `ad-asreproast` | AS-REP hashes for pre-auth-free accounts |
| `ad-full-recon` | port-scan → LDAP enum → kerberoast → topology, one run |

Typical chain: `ad-ldap-enum` → build `/tmp/users.txt` →
`ad-asreproast` → crack offline → `ad-spray-smb` with the winner.
Requires the attacker_ssh connector and impacket/netexec on the
attacker box.
""",
    ),
    (
        "pivoting",
        "Pivoting through jump hosts and SOCKS proxies",
        KB_GUIDES_CATEGORY,
        ["pivoting", "proxy", "ssh"],
        """\
When targets are not directly reachable, route the platform's SSH
execution through the pivot:

- **jump** — SSH ProxyJump through a bastion.
- **socks5** — a SOCKS5 proxy (dynamic forward, chisel, ligolo);
  commands are wrapped in proxychains automatically.
- **socks4** — via proxychains.

Configure per attacker target (Connections → SSH Executor targets →
proxy section). Route selection prefers direct → jump → proxy based on
reachability. Timeouts are tuned (5s connect) so a dead proxy fails
fast instead of hanging a worker.
""",
    ),
    (
        "c2-operations",
        "C2 operations: listeners, payloads, droppers",
        KB_PLATFORM_CATEGORY,
        ["c2", "adaptix", "payloads", "infrastructure"],
        """\
Platform Ops → C2 Ops turns listeners into a first-class operation:

1. **Listener** — pick a port (occupied ports are shown; conflicts
   block creation). On k8s the Service is patched live — the C2
   survives; behind a redirector TLS terminates on nginx.
2. **Payload** — generate an agent straight into Loot (sha256,
   encrypted, timeline event). With a pwndrop service in the stack the
   payload is **auto-published** and the public link appears in the
   project's Access tab.
3. **Callback** — computed from stack topology: redirector address,
   NodePort or tunnel — beacons inherit it from the listener.

C2 stacks are strictly project-bound; shared edge services
(redirector/dropper) may serve several projects' C2 instances.
""",
    ),
    (
        "access-tab",
        "Where connection info lives (Access tab)",
        KB_PLATFORM_CATEGORY,
        ["access", "credentials", "reporting"],
        """\
Output → Access aggregates everything an operator needs to connect,
scoped to the project and the caller's role:

- **C2** — teamserver addresses and real (decrypted) credentials with a
  per-type how-to (browser URL / UI / client connect).
- **Infrastructure** — stack service credentials filtered by role.
- **Workstations** — pool machines with a ready `ssh` command and a
  "your key is installed" marker.
- **Dropped payloads** — published dropper links.

Non-members get 404; passwords are masked until revealed, and every
reveal is audited.
""",
    ),
    (
        "workstation-pool",
        "Workstation pool — getting an attack box",
        KB_PLATFORM_CATEGORY,
        ["workstations", "pool", "ssh"],
        """\
Request a machine (Workstations → + Request) or ask an admin to
provision one from the pool:

- Machines come from Platform Ops providers (Hetzner, Proxmox, Docker,
  Kubernetes, plain SSH hosts).
- Access is granted by **your profile SSH key** — add one in user
  settings first; grants are marker-based and revocable per user.
- Bound projects show the machine (and its ssh command) in Access.
- Pool machines can double as **SSH executor** machines for scans/exec.
""",
    ),
    (
        "roe",
        "Rules of Engagement (ROE)",
        KB_PLATFORM_CATEGORY,
        ["roe", "compliance", "governance"],
        """\
Recon → ROE defines what this engagement may and may not do:

- Forbidden activities block matching operations *before* execution
  (connectors and executors check ROE per run).
- Grey-zone actions can require **approval** — an operator requests, a
  lead approves, the audit trail records both.
- CIDR gates keep accidental out-of-scope targeting from executing.

Write ROE at engagement start, not after the first incident. The Purple
report includes a ROE compliance section.
""",
    ),
    (
        "purple-view",
        "Purple view — red data, blue usefulness",
        KB_PLATFORM_CATEGORY,
        ["purple", "detection", "reporting"],
        """\
The Purple tab re-cuts red-team data for detection engineering: MITRE
techniques aggregated from attack paths *and* graph edges, findings by
severity, and a defender timeline. **Copy report (MD)** produces a
Markdown brief ready for a blue team — techniques used, where, and when
(with noise levels, since bulk exec over SMB at 2am is exactly what
their EDR should have caught).
""",
    ),
    (
        "closure",
        "Engagement closure checklist",
        KB_GUIDES_CATEGORY,
        ["closure", "reporting", "hygiene"],
        """\
Run the closure wizard (project → Closure) before archiving:

1. **Decommission report** — what was deployed where and what was torn
   down.
2. **Infrastructure teardown** — stacks destroyed, orphaned leftovers
   flagged to admins.
3. **Secret revocation** — every unexpired Secret Vault entry is
   revoked (`auto_revoke_on_close`); VPN keys and API tokens die with
   the engagement.
4. Findings must be published/approved; the report pulls final data.

Leaving valid credentials on client infrastructure after the last day
is a finding against *you*.
""",
    ),
    (
        "secret-vault-vs-creds",
        "Secret Vault vs Creds — what goes where",
        KB_PLATFORM_CATEGORY,
        ["secrets", "creds", "encryption"],
        """\
Two different ledgers:

- **Creds** — access to *targets*: logins, hashes, keys, tied to hosts
  and domains; feeds the matrix and access edges.
- **Secret Vault** (Exploit → Creds → Secret Vault) — *your own*
  operational secrets: attack-box SSH keys, VPN configs, provider API
  tokens, certificates. Tracked with issued-to/expiry, revocable,
  auto-revoked on closure, every read audited.

Both are encrypted per project (DEK under the global KEK); rotate a
project's DEK from Admin → Encryption.
""",
    ),
    (
        "encryption-model",
        "How secrets are protected at rest",
        KB_PLATFORM_CATEGORY,
        ["security", "encryption", "dek"],
        """\
Hierarchy: **KEK** (global `ENCRYPTION_KEY` from env) → **per-project
DEK** → data (credential secrets, vault values, sensitive loot).

- A stolen DB dump without the KEK is noise; per-project DEKs keep one
  project's compromise from becoming everyone's.
- Ciphertexts are prefixed (`__pdek__:` vs `__enc__:`) so rotation knows
  what it's looking at; undecryptable values fail loudly, never
  masquerading as secrets.
- Reads are role-gated (`*.read_secret`) and audited; listings mask
  values.

The boundary is the host: someone with both the DB *and* the env file
has everything. Protect backups accordingly.
""",
    ),
    (
        "opsec-basics",
        "OPSEC basics for every engagement",
        KB_GUIDES_CATEGORY,
        ["opsec", "methodology"],
        """\
- Check the deconfliction map before touching a shared host.
- Prefer the quietest tool that answers the question; the graph tags
  noisy edges (bulk exec = high) for a reason.
- Spray with lockout-aware flags (`--no-bruteforce`,
  `--continue-on-success`), one guess per account per window.
- Run loud scans through pivots, not from your own IP.
- Watch job output — a login banner or AV tripwire in stdout is
  information.
- When in doubt, ROE: if the action needs approval, that's the system
  telling you it's grey.
""",
    ),
    (
        "password-spraying",
        "Password spraying without locking accounts",
        KB_GUIDES_CATEGORY,
        ["credentials", "active-directory", "opsec"],
        """\
Spraying is a numbers game played against lockout policies:

1. Enumerate valid usernames first (`ad-ldap-enum`,
   `--password-not-required`, Kerberos preauth errors).
2. One password per user per attempt; know the lockout threshold and
   observation window before the first guess.
3. Seasonal/corporate patterns beat rockyou; one hit is enough — stop,
   validate, pivot to that user's actual access.
4. `netexec smb --no-bruteforce --continue-on-success` is the safe
   default shape.

A locked account is a detection gift to the blue team and a finding
against you.
""",
    ),
    (
        "kerberoast-workflow",
        "Kerberoasting and AS-REP roasting",
        KB_GUIDES_CATEGORY,
        ["active-directory", "credentials"],
        """\
**Kerberoast** — request TGS for SPN accounts (`ad-kerberoast` /
`GetUserSPNs`), crack offline. Service accounts with weak passwords and
high privileges are the jackpot; check the matrix for what the account
can reach *before* celebrating a crack.

**AS-REP roast** — accounts without Kerberos pre-auth hand over
hashes-for-free (`GetNPUsers`). Build the user list first
(`ad-ldap-enum` → `/tmp/users.txt`).

Both leave tickets on the attacker box at `/tmp/*.txt` — loot them into
the project so the report can cite them.
""",
    ),
    (
        "evidence-hygiene",
        "Evidence and note hygiene",
        KB_GUIDES_CATEGORY,
        ["reporting", "evidence", "notes"],
        """\
Findings are only as strong as their evidence trail:

- Paste outputs into Notes linked to the host (the link is first-class —
  use it) instead of screenshots in a side folder.
- Record *when* and *from where*: the timeline does it automatically for
  platform actions; manual actions deserve a one-line note.
- Loot files (hashes, configs, proofs) belong in Loot with the source
  job attached — that's what makes the chain reproducible.
- Write findings as you go, not in the last week: the report generator
  can only pull what exists.
""",
    ),
    (
        "report-writing",
        "Writing findings that survive client review",
        KB_GUIDES_CATEGORY,
        ["reporting", "findings"],
        """\
- Lead with impact, then the technical detail — the exec summary reads
  the first paragraph of each finding and nothing else.
- One issue per finding; severity by business risk, not by tool output.
- Reproduction steps a sysadmin can follow without you; remediation
  they can act on this quarter.
- Cite evidence (loot/note/job links stay attached).
- The HTML export and the Purple MD brief are client-facing: no
  internal hostnames of your own infrastructure.
""",
    ),
]

# Third-Party Notices

This file lists third-party components redistributed with or inside
Umbryx, and their licenses. Umbryx itself is licensed under the Business
Source License 1.1 (see `LICENSE`); the Community Edition additionally
carries a production-use grant. Nothing in this file changes those
terms — it exists to give credit and to comply with the licenses below.

## Umbryx does NOT redistribute offensive tooling

The platform never ships nmap, nuclei, NetExec, impacket or similar
tools in its application images. Tools run on attacker machines you
provision; see the documentation. The single exception — a convenience
image for workstation pools — is listed under "Docker images" below.

## Python dependencies (backend, both editions)

The complete version-pinned list is `backend/requirements.txt`.
Notable licenses among runtime dependencies:

| Package | License | Note |
|---|---|---|
| paramiko | LGPL-2.1 | dynamic import; LGPL obligations noted |
| psycopg2-binary | LGPL-3.0 | wraps libpq (PostgreSQL Licence) |
| pyphen (via WeasyPrint) | GPL-2.0+ OR LGPL-2.1+ OR MPL-1.1 | tri-licensed, LGPL/MPL use chosen |
| sliver-py | GPL-3.0 | used for the optional Sliver integration; the GPLv3 applies to this library, exercised only when a Sliver integration is configured |
| fastapi, uvicorn, starlette, sqlalchemy, pydantic, jinja2, alembic, httpx, redis, bcrypt, pyjwt, cryptography, slowapi, limits, passlib, pyotp, pyyaml, weasyprint, pydyf, pyzipper, python-multipart, arq, socksio, boto3, pypdf, python-docx, openpyxl, xlrd | MIT / BSD-3 / Apache-2.0 (per upstream) | permissive |

## Binaries inside the backend image

| Binary | License | Source |
|---|---|---|
| `sliver-client` v1.7.7 | GPL-3.0 | https://github.com/BishopFox/sliver (release binary); the GPLv3 text and the corresponding source are available at that repository |
| `kubectl` | Apache-2.0 | https://github.com/kubernetes/kubernetes |
| Docker CLI | Apache-2.0 | https://github.com/docker/cli |
| OpenSSH client | BSD-style (OpenSSH licence) | distro package |

## Docker images

**Application stack** (`umbryx-backend`, `umbryx-frontend`, nginx,
postgres:16-alpine (PostgreSQL Licence), redis:7.2-alpine (BSD-3)) —
no third-party offensive tooling inside.

**`umbryx/pool-ssh-tools`** (workstation/executor convenience image,
built from `docker/images/pool-ssh-tools/`):

| Tool | License | Upstream |
|---|---|---|
| nmap | NPSL (Nmap Public Source License) | https://nmap.org/book/man-legal.html |
| nuclei | MIT | https://github.com/projectdiscovery/nuclei |
| NetExec | BSD-2-Clause | https://github.com/Pennyw0rth/NetExec |
| masscan | AGPL-3.0 (see upstream LICENSE for the exception clause) | https://github.com/robertdavidgraham/masscan |

The NPSL requires redistribution to carry the license text and to keep
the "uses Nmap Security Scanner" attribution: **this image uses Nmap
Security Scanner — https://nmap.org**. The license text is included in
`docker/images/pool-ssh-tools/NOTICE.md` alongside this file. You can
build the image yourself from that directory (the Dockerfile is the
complete recipe) if you prefer not to pull it from Docker Hub.

## Frontend

Node dependencies (`frontend/package.json`) are MIT/BSD/Apache-2.0
licensed (React, Vite, Zustand, and friends); fonts served with the UI
(Space Grotesk, JetBrains Mono) are under the SIL Open Font License 1.1.

## Corrections

If a license is stated incorrectly here, it is a mistake — open an
issue and it will be fixed promptly.

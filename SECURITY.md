# Security Policy

## Supported versions

Security fixes land on the current release line. The latest public
release is the only supported version; there are no LTS branches.

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.**

Email **security@umbryx.pro** with:

- a description of the issue and its impact
- reproduction steps (PoC, affected endpoint/path)
- the version and edition (Core / EE) you tested

You will get an acknowledgement within **72 hours** and a status update
at least every **7 days** until resolved. Please allow up to **90 days**
for a fix before public disclosure; we will coordinate a release and
credit you in the changelog unless you prefer to stay anonymous.

## Scope

In scope:
- the application code in this repository (backend, frontend, modules)
- the shipped container images and default deployment configurations

Out of scope:
- compromises of the host the platform runs on (the threat model
  assumes a trusted internal network — see the security overview in the
  documentation)
- attacks requiring an already-authenticated platform administrator
- social engineering, DoS of the Umbryx vendor infrastructure

## Handling history

Findings from internal and external reviews are fixed with the
identifier referenced in code comments (F-series, M-series, Shannon
batches, external-review commits). A security retest summary ships with
each release.

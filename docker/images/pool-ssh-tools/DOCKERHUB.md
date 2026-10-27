# Docker Hub description (paste into the repository "Overview")

Umbryx executor/workstation convenience image: sshd + platform key
materialization (same contract as umbryx/pool-ssh) with an offensive
toolchain preinstalled — nmap, nuclei, NetExec, masscan.

This image uses Nmap Security Scanner — https://nmap.org (NPSL).
nuclei: MIT · NetExec: BSD-2 · masscan: AGPL-3.0 (upstream LICENSE).
Full notices: THIRD-PARTY-NOTICES.md in the umbryx repo; the complete
build recipe is the Dockerfile in the same directory as this image —
rebuild it yourself with your own namespace if you prefer.

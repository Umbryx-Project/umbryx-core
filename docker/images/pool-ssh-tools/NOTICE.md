# NOTICE — umbryx/pool-ssh-tools

This image uses **Nmap Security Scanner** — https://nmap.org
Nmap is distributed under the Nmap Public Source License (NPSL):
https://nmap.org/npsl/

Redistribution of this image redistributes the following packages:

| Tool | License | Upstream |
|---|---|---|
| nmap | NPSL | https://nmap.org |
| nuclei | MIT | https://github.com/projectdiscovery/nuclei |
| NetExec | BSD-2-Clause | https://github.com/Pennyw0rth/NetExec |
| masscan | AGPL-3.0 (upstream LICENSE, incl. its exception clause) | https://github.com/robertdavidgraham/masscan |

NPSL highlights (not a substitute for the full text): keep the license
and attribution when you redistribute nmap; modified versions have
naming restrictions. The AGPL applies to masscan as published upstream;
if AGPL terms are incompatible with your use, remove masscan from the
Dockerfile and rebuild — everything else in this image stays
permissively licensed (base image: Kali Linux, whose repository
licenses apply to the distro packages).

## Self-build (recommended for restricted environments)

```bash
docker build -t your-namespace/pool-ssh-tools:latest docker/images/pool-ssh-tools/
```

The Dockerfile in this directory is the complete recipe — no private
layers. Trimming tools is a one-line edit of the `apt-get install`
list.

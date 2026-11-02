# SSH Executor Box image (workstation → SSH-executor bridge, 2026-09-22).
#
# Same contract as umbryx/pool-ssh (sshd + platform key materialized from
# UMBRYX_SSH_KEY env, user keys appended over SSH by the platform) plus the
# offensive toolchain preinstalled, so a pool machine deployed from this
# image can serve as the executor box for scans / attacker-exec / pivots
# right after the "Executor" flag is flipped.
#
# Build & push:
#   docker build -t umbryx/pool-ssh-tools:latest docker/images/pool-ssh-tools/
FROM kalilinux/kali-rolling:latest

# http.kali.org redirects to a flaky regional mirror; pin the CDN instead.
RUN sed -i 's|http://http.kali.org|http://kali.download|' /etc/apt/sources.list.d/kali.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      openssh-server openssh-client sudo curl wget \
      nmap nuclei netexec masscan && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /root/.ssh /var/run/sshd && \
    chmod 700 /root/.ssh

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]

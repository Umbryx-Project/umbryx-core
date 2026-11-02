# Pool SSH machine image (workstation pool feature, 2026-09-02).
#
# One image serves BOTH docker-provider and k8s-provider pool machines:
# it runs sshd and materializes the platform key from the environment at
# boot, so every pool machine is manageable by the platform over plain SSH
# (authorized_keys grants/revokes) regardless of the substrate.
#
# Build & push:
#   docker build -t umbryx/pool-ssh:latest docker/images/pool-ssh/
#
# Required env:
#   UMBRYX_SSH_KEY      — platform PUBLIC key line (written to authorized_keys)
# Optional env:
#   UMBRYX_SSH_USER     — ssh login user (default root)
FROM kalilinux/kali-rolling:latest

# http.kali.org redirects to a flaky regional mirror; pin the CDN instead.
RUN sed -i 's|http://http.kali.org|http://kali.download|' /etc/apt/sources.list.d/kali.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends openssh-server sudo && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /root/.ssh /var/run/sshd && \
    chmod 700 /root/.ssh

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]

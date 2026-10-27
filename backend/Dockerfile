FROM python:3.12-slim

ARG DOCKER_GID=988

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    netcat-openbsd \
    util-linux \
    coreutils \
    curl \
    ca-certificates \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi8 \
    libjpeg62-turbo \
    libopenjp2-7 \
    antiword \
  && KUBECTL_VERSION=$(curl -sSL https://dl.k8s.io/release/stable.txt) \
  && curl -sSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" -o /usr/local/bin/kubectl \
  && chmod +x /usr/local/bin/kubectl \
  && curl -sSL https://download.docker.com/linux/static/stable/x86_64/docker-29.2.0.tgz | tar -xzf - -C /usr/local/bin --strip-components=1 docker/docker \
  # compose v2 plugin: the static docker bundle ships the CLI WITHOUT it,
  # and workstation provisioning (docker provider) runs `docker compose`
  # through the mounted socket — without the plugin every provision fails
  # with "unknown shorthand flag: 'f'" (found live on the EE stand)
  && mkdir -p /usr/local/lib/docker/cli-plugins \
  && curl -sSL -o /usr/local/lib/docker/cli-plugins/docker-compose "https://github.com/docker/compose/releases/download/v5.6.1/docker-compose-linux-x86_64" \
  && chmod +x /usr/local/lib/docker/cli-plugins/docker-compose \
  && curl -sSL -o /usr/local/bin/sliver-client "https://github.com/BishopFox/sliver/releases/download/v1.7.8/sliver-client_linux-amd64" \
  && chmod +x /usr/local/bin/sliver-client \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Fixed, explicit UID/GID (rather than whatever `useradd` picks next) so the
# in-container app user is a stable, documented value — the entrypoint's
# runtime chown of the /data bind mount (see scripts/docker-entrypoint.sh)
# is what actually makes host-UID mismatches a non-issue, but a stable UID
# still matters for anyone who wants to pre-create ./data with matching
# ownership to skip that chown on a very large existing volume.
ARG APP_UID=1000
ARG APP_GID=1000
RUN groupadd -g ${APP_GID} umbryx \
    && useradd --create-home --shell /usr/sbin/nologin --uid ${APP_UID} --gid ${APP_GID} umbryx

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY alembic/ ./alembic/
COPY alembic.ini .
COPY scripts/ ./scripts/

RUN groupadd -g ${DOCKER_GID} docker 2>/dev/null || true \
    && usermod -aG docker umbryx \
    && chown -R umbryx:umbryx /app \
    && chmod +x scripts/docker-entrypoint.sh

# Stays root here on purpose — the entrypoint fixes /data ownership and
# then drops to `umbryx` via setpriv (exec, so it replaces PID 1) before
# running CMD. See scripts/docker-entrypoint.sh for why.
ENTRYPOINT ["scripts/docker-entrypoint.sh"]
# Security audit 2026-10-09: behind the nginx container uvicorn must honour
# X-Forwarded-*, or rate-limiter keys and audit IPs are the proxy IP.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]

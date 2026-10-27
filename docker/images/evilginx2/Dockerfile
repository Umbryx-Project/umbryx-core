# evilginx2 — MITM phishing framework (official release binary).
# NOTE: binary is glibc-linked → runtime must be glibc-based, not alpine/musl.
FROM alpine:3.19 AS builder
ARG EVILGINX_VERSION=v3.3.0
RUN apk add --no-cache curl unzip
RUN curl -sL -o /tmp/evilginx.zip \
    "https://github.com/kgretzky/evilginx2/releases/download/${EVILGINX_VERSION}/evilginx-v${EVILGINX_VERSION#v}-linux-64bit.zip" \
    && cd /tmp && unzip -q evilginx.zip && chmod +x evilginx

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata && rm -rf /var/lib/apt/lists/*
COPY --from=builder /tmp/evilginx /opt/evilginx
COPY --from=builder /tmp/phishlets /opt/phishlets
RUN mkdir -p /root/.evilginx
EXPOSE 443 53/udp 80
ENTRYPOINT ["/opt/evilginx"]

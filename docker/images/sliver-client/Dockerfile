# Sliver operator client — for operator boxes / workstation pools and for
# non-interactive automation: `sliver-client --rc script.txt` runs commands
# (incl. `generate`) and exits, no TTY needed.
FROM alpine:3.19 AS builder
ARG SLIVER_VERSION=v1.7.7
RUN apk add --no-cache curl
RUN curl -sL -o /sliver-client \
    "https://github.com/BishopFox/sliver/releases/download/${SLIVER_VERSION}/sliver-client_linux-amd64" \
    && chmod +x /sliver-client

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata && rm -rf /var/lib/apt/lists/*
COPY --from=builder /sliver-client /usr/local/bin/sliver-client
RUN mkdir -p /root/.sliver-client/configs
WORKDIR /root
ENTRYPOINT ["/usr/local/bin/sliver-client"]

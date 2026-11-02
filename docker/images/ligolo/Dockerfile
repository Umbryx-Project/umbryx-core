# Ligolo-ng — reverse tunneling (proxy + agent in one image).
# Release tarballs contain binaries named `proxy` and `agent`.
FROM alpine:3.19 AS builder
ARG LIGOLO_VERSION=v0.9.1
RUN apk add --no-cache curl tar && mkdir -p /px /ag && \
    curl -sL "https://github.com/nicocha30/ligolo-ng/releases/download/${LIGOLO_VERSION}/ligolo-ng_proxy_${LIGOLO_VERSION#v}_linux_amd64.tar.gz" | tar xz -C /px && \
    curl -sL "https://github.com/nicocha30/ligolo-ng/releases/download/${LIGOLO_VERSION}/ligolo-ng_agent_${LIGOLO_VERSION#v}_linux_amd64.tar.gz" | tar xz -C /ag

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata iproute2
COPY --from=builder /px/proxy /usr/local/bin/proxy
COPY --from=builder /ag/agent /usr/local/bin/agent
EXPOSE 11601 5555
# -selfcert: generate self-signed certs on first boot (k8s/docker friendly)
# -daemon: no interactive CLI (skips the WebUI y/N prompt in containers)
ENTRYPOINT ["/usr/local/bin/proxy", "-selfcert", "-daemon"]

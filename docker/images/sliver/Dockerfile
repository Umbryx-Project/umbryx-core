# Sliver teamserver from official release binaries.
# NOTE: pre-1.6 release binaries are glibc-linked → runtime must be glibc-based.
# v1.5.42 is the newest release whose gRPC API matches sliver-py 0.0.19
# (1.6+ requires ImplantConfig.HTTPC2ConfigName which sliver-py cannot set).
FROM alpine:3.19 AS builder
ARG SLIVER_VERSION=v1.5.42
ARG SLIVER_ASSET=sliver-server_linux
RUN apk add --no-cache curl
RUN curl -sL -o /sliver-server \
    "https://github.com/BishopFox/sliver/releases/download/${SLIVER_VERSION}/${SLIVER_ASSET}" \
    && chmod +x /sliver-server

FROM debian:bookworm-slim
# git: garble requires it at build time; mingw: windows implant linking
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata git gcc-mingw-w64-x86-64 binutils && rm -rf /var/lib/apt/lists/*
COPY --from=builder /sliver-server /opt/sliver-server
RUN mkdir -p /root/.sliver
EXPOSE 31337 4443 53/udp 80 443 8888
ENTRYPOINT ["/opt/sliver-server"]
CMD ["daemon"]

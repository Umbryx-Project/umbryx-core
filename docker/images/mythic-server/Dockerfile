# Mythic teamserver (Go) — server ONLY, no backing services bundled.
# Expects reachable postgres + rabbitmq (see the mythic-stack bundle).
FROM golang:1.25 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends git make && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/its-a-feature/Mythic.git /src
WORKDIR /usr/src/app
RUN cp -r /src/mythic-docker/src/. . && make build_final

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/app/mythic_server /usr/src/app/mythic_server
# mythic_server reads SQL migrations and ATT&CK data from its working dir
COPY --from=builder /usr/src/app/database /usr/src/app/database
COPY --from=builder /usr/src/app/utils /usr/src/app/utils
# mythic_server's payload-sync reads agent UI icons from its own
# /usr/src/app/static — ship known ones so plugin sync does not loop.
COPY static /usr/src/app/static
# mythic_server saves built artifacts to ./files
RUN mkdir -p /usr/src/app/files
WORKDIR /usr/src/app
EXPOSE 17443
ENV MYTHIC_ADMIN_USER=admin
ENTRYPOINT ["/usr/src/app/mythic_server"]

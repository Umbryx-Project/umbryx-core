# Mythic all-in-one: mythic_server (Go) + postgres + rabbitmq + hasura + nginx.
# Official Mythic is a docker-compose of 6+ containers; stacks deploy one
# service per template, so this image bundles the mandatory backing services
# behind one nginx endpoint (7443 TLS):
#   /graphql/   -> hasura :8080 /v1/graphql   (scripting API)
#   /api/v1.4/  -> mythic_server :17443      (auth, files)
# Payload-type / C2Profile plugin containers are NOT bundled — Mythic needs
# them as separate services to generate agents.
FROM golang:1.25 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends git make curl && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/its-a-feature/Mythic.git /src
WORKDIR /usr/src/app
RUN cp -r /src/mythic-docker/src/. . && make build_final
# hasura engine binary comes from the official image; CLI from the release
FROM hasura/graphql-engine:v2.19.0 AS hasura-engine
FROM golang:1.25 AS builder2
RUN curl -sL -o /hasura-cli https://github.com/hasura/graphql-engine/releases/download/v2.19.0/cli-hasura-linux-amd64 && chmod +x /hasura-cli

FROM debian:bookworm-slim
# libssl1.1: hasura engine v2.19 binary is linked against openssl 1.1 (bullseye)
RUN echo 'deb http://deb.debian.org/debian bullseye main' > /etc/apt/sources.list.d/bullseye.list
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql rabbitmq-server nginx ca-certificates wget curl \
    unixodbc libpq5 libpcre3 libssl1.1 libmariadb3 libodbc2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/app/mythic_server /usr/src/app/mythic_server
COPY --from=builder /usr/src/app/database /usr/src/app/database
COPY --from=builder /usr/src/app/utils /usr/src/app/utils
COPY --from=builder /src/hasura-docker/metadata /hasura-project/metadata
COPY --from=hasura-engine /bin/graphql-engine /usr/local/bin/graphql-engine
COPY --from=builder2 /hasura-cli /usr/local/bin/hasura
COPY entrypoint.sh nginx.conf /etc/mythic/
RUN printf "version: 2\nmetadata_directory: metadata\n" > /hasura-project/config.yaml
RUN chmod +x /etc/mythic/entrypoint.sh && ln -sf /etc/mythic/entrypoint.sh /entrypoint.sh
WORKDIR /usr/src/app
EXPOSE 7443 17443
ENTRYPOINT ["/entrypoint.sh"]

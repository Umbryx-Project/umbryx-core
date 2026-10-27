# Hasura with Mythic metadata + custom apply flow.
# Mythic's metadata is a v2 directory project; the stock cli-migrations
# entrypoint applies it as v1 and fails ("key tables not found"). This image
# starts the engine first, then applies the metadata project with the CLI
# (the flow verified against a live Mythic instance).
FROM debian:bookworm-slim AS fetch
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/its-a-feature/Mythic.git /src

FROM hasura/graphql-engine:v2.19.0.cli-migrations-v2
COPY --from=fetch /src/hasura-docker/metadata /hasura-project/metadata
RUN printf "version: 2\nmetadata_directory: metadata\n" > /hasura-project/config.yaml
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]

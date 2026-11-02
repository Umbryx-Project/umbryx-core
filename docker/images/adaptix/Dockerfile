# AdaptixC2 teamserver + Extension-Kit (BoF) preloaded and wired into the profile.
# Reproduces the deployed umbryx/adaptix layout:
#   /opt/adaptix-server            — teamserver binary (go build)
#   /opt/extension-kit             — BoF kit sources + built modules + extension-kit.axs
#   /opt/extenders                 — default extenders (beacon/gopher listeners)
#   /data/profile.yaml             — default profile with axscripts pre-wired
FROM golang:1.26-bookworm AS server-builder
RUN apt-get update && apt-get install -y --no-install-recommends git make cmake build-essential \
    gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 gcc-mingw-w64-i686 g++-mingw-w64-i686 \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/Adaptix-Framework/AdaptixC2.git /src
WORKDIR /src
RUN make server extenders

FROM debian:bookworm-slim AS ext-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git make build-essential cmake python3 \
    gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 gcc-mingw-w64-i686 g++-mingw-w64-i686 \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/Adaptix-Framework/Extension-Kit.git /ek
WORKDIR /ek
RUN make all

FROM debian:bookworm-slim
# mingw toolchain must live in the RUNTIME image: Adaptix compiles
# agents server-side on every generate call (found live 2026-09-22:
# "x86_64-w64-mingw32-g++: not found").
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates openssl \
    gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 gcc-mingw-w64-i686 g++-mingw-w64-i686 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=server-builder /src/dist/adaptixserver /opt/adaptix-server
COPY --from=server-builder /src/dist/extenders /opt/extenders
COPY --from=server-builder /src/dist/404page.html /data/404page.html
COPY --from=ext-builder /ek /opt/extension-kit
RUN mkdir -p /data && \
    openssl req -x509 -newkey rsa:2048 -keyout /data/server.rsa.key -out /data/server.rsa.crt \
    -days 3650 -nodes -subj "/CN=example.com" 2>/dev/null
COPY profile.yaml /data/profile.yaml
WORKDIR /data
EXPOSE 4321
ENTRYPOINT ["/opt/adaptix-server"]
CMD ["-profile", "/data/profile.yaml"]

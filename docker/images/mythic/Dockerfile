FROM python:3.12-slim AS builder
ARG MYTHIC_REPO=its-a-feature/Mythic
ARG MYTHIC_REF=master
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch ${MYTHIC_REF} https://github.com/${MYTHIC_REPO}.git /src
WORKDIR /src
RUN pip install --no-cache-dir -r requirements.txt 2>/dev/null || true

FROM python:3.12-slim
COPY --from=builder /src /opt/mythic
WORKDIR /opt/mythic
RUN pip install --no-cache-dir -r requirements.txt 2>/dev/null || true
RUN mkdir -p /opt/mythic/database_files
EXPOSE 7443 8080
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "mythic_server.py"]

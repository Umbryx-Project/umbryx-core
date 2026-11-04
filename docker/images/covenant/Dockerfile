FROM mcr.microsoft.com/dotnet/sdk:8.0 AS builder
ARG COVENANT_REPO=cobbr/Covenant
ARG COVENANT_REF=master
RUN apt-get update && apt-get install -y git \
    && git clone --depth 1 --recurse-submodules --shallow-submodules --branch ${COVENANT_REF} https://github.com/${COVENANT_REPO}.git /src \
    && cd /src/Covenant \
    && dotnet publish -c Release -o /out

# Covenant targets ASP.NET Core 3.1 — runtime must match (8.0 runtime fails
# with "No frameworks were found: Microsoft.AspNetCore.App 3.1.0").
FROM mcr.microsoft.com/dotnet/aspnet:3.1-alpine
COPY --from=builder /out /opt/covenant
# runtime submodule check expects Data/ReferenceSourceLibraries present
COPY --from=builder /src/Covenant/Data /opt/covenant/Data
RUN mkdir -p /opt/covenant/Data
EXPOSE 7443 80 4444
WORKDIR /opt/covenant
ENTRYPOINT ["dotnet", "Covenant.dll"]

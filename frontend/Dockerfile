FROM node:20-alpine AS builder

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm install
COPY src ./src
COPY public ./public
# edition.config.js is imported by vite.config.js and decides whether this
# image is a Community or Enterprise build (docs/modules/EDITIONS.md), so it
# has to be in the image or the config fails to load.
COPY index.html vite.config.js edition.config.js tsconfig.json eslint.config.js ./

# UMBRYX_EDITION=ce builds the Community artifact. Left unset the edition is
# read off the tree: src/ee/ present means Enterprise, absent means
# Community — so a Community source tree builds a Community image with no
# build argument at all.
ARG UMBRYX_EDITION
ENV UMBRYX_EDITION=${UMBRYX_EDITION}
RUN npm run build

FROM nginx:alpine

# roll base libraries to patched builds — nginx:alpine lags security
# fixes and the container-scan gate blocks on them (CVE-2026-111497)
RUN apk upgrade --no-cache

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx-frontend.conf /etc/nginx/conf.d/default.conf
RUN chown -R nginx:nginx /usr/share/nginx/html && \
    chown -R nginx:nginx /var/cache/nginx && \
    chown -R nginx:nginx /var/log/nginx && \
    touch /var/run/nginx.pid && \
    chown nginx:nginx /var/run/nginx.pid
USER nginx
EXPOSE 80

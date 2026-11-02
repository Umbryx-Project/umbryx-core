# Mythic edge nginx: single TLS entrypoint routing to hasura (graphql) and
# the mythic server. Upstreams come from env; a self-signed cert is generated
# at boot if no mounted one exists.
FROM nginx:1.27-alpine
RUN apk add --no-cache openssl
COPY template.conf /etc/nginx/templates/mythic.conf.template
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENV NGINX_ENVSUBST_OUTPUT_DIR=/etc/nginx/conf.d
EXPOSE 7443
ENTRYPOINT ["/entrypoint.sh"]

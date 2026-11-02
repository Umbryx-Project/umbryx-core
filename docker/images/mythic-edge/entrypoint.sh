#!/bin/sh
set -e
if [ ! -f /etc/nginx/tls.crt ]; then
  openssl req -x509 -newkey rsa:2048 -keyout /etc/nginx/tls.key -out /etc/nginx/tls.crt \
    -days 3650 -nodes -subj "/CN=mythic" 2>/dev/null
fi
# nginx's resolver ignores DNS search domains — expand short hostnames to
# cluster-internal FQDNs using the pod's own namespace.
NS=""
if [ -f /var/run/secrets/kubernetes.io/serviceaccount/namespace ]; then
  NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
fi
for var in HASURA_HOST SERVER_HOST; do
  val=$(eval echo \$$var)
  case "$val" in
    *.*) ;;
    *) [ -n "$NS" ] && [ -n "$val" ] && eval export $var="$val.$NS.svc.cluster.local" ;;
  esac
done
# Hand off to the stock nginx entrypoint (runs envsubst-on-templates).
exec /docker-entrypoint.sh nginx -g "daemon off;"

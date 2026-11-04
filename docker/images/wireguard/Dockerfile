# WireGuard tunnel endpoint (server peer / in-cluster gateway peer).
# Config fully env-driven; NET_ADMIN + /dev/net/tun required.
FROM alpine:3.19
RUN apk add --no-cache wireguard-tools iptables bash
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

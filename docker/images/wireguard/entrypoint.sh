#!/bin/bash
# WG_ROLE=server|client; keys/config via env; writes wg0.conf, wg-quick up.
set -e
PRIV="${WG_PRIV_KEY:?}"
ADDR="${WG_ADDR:?}"            # e.g. 10.200.0.1/24
PEER_PUB="${WG_PEER_PUB:?}"
ALLOWED="${WG_ALLOWED:?}"      # cidrs routed to the peer
LISTEN="${WG_LISTEN:-51820}"
[ "$WG_ROLE" = "server" ] && ENDPOINT_LINE="" || ENDPOINT_LINE="Endpoint = ${WG_PEER_ENDPOINT:?}"
cat > /etc/wireguard/wg0.conf <<CONF
[Interface]
PrivateKey = $PRIV
Address = $ADDR
ListenPort = $LISTEN
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE || true
PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE || true
# server role only: rewrite docker/host-side sources to the overlay IP so
# backend replies route back through the tunnel (the wg peer only accepts
# destinations inside its AllowedIPs)
PostUp = [ "$WG_ROLE" = "server" ] && iptables -t nat -A POSTROUTING -o wg0 -j SNAT --to-source ${ADDR%%/*} || true
PostDown = iptables -t nat -D POSTROUTING -o wg0 -j SNAT --to-source ${ADDR%%/*} 2>/dev/null || true

[Peer]
PublicKey = $PEER_PUB
AllowedIPs = $ALLOWED
PersistentKeepalive = 10
$ENDPOINT_LINE
CONF
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
wg-quick up /etc/wireguard/wg0.conf
exec sleep infinity

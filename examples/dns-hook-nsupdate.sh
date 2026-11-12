#!/bin/sh
# DNS-01 hook for BIND / any RFC 2136 server. Farrier sets:
#   FARRIER_DNS_ACTION=present|cleanup  FARRIER_DNS_NAME=_acme-challenge.host.example.com  FARRIER_DNS_VALUE=<txt>
# "present" must ADD a value (a cert for example.com + *.example.com needs two TXT values on one name).
set -eu
SERVER="${NSUPDATE_SERVER:-ns1.example.com}"
KEY="${NSUPDATE_KEY:-/etc/farrier/tsig.key}"
case "$FARRIER_DNS_ACTION" in
  present) OP="update add $FARRIER_DNS_NAME. 60 IN TXT \"$FARRIER_DNS_VALUE\"" ;;
  cleanup) OP="update delete $FARRIER_DNS_NAME. IN TXT \"$FARRIER_DNS_VALUE\"" ;;
  *) echo "unknown action $FARRIER_DNS_ACTION" >&2; exit 2 ;;
esac
printf 'server %s\n%s\nsend\n' "$SERVER" "$OP" | nsupdate -k "$KEY"

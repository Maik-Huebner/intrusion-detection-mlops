#!/usr/bin/env bash
# One-time setup on the server, run by the admin with sudo:
#   sudo bash setup-nginx.sh ids.178-104-83-110.sslip.io
# Installs the nginx vhost for the IDS stack and gets a Let's Encrypt certificate.
# Touches nothing else: other sites and their certificates stay as they are.
set -euo pipefail
domain="${1:?usage: sudo bash setup-nginx.sh <domain>}"
[[ "$domain" =~ ^[a-z0-9.-]+$ ]] || { echo "invalid domain: $domain" >&2; exit 2; }
here="$(cd "$(dirname "$0")" && pwd)"

sed "s/__DOMAIN__/$domain/" "$here/nginx-ids.conf" > /etc/nginx/sites-available/ids
ln -sf /etc/nginx/sites-available/ids /etc/nginx/sites-enabled/ids
nginx -t
systemctl reload nginx
certbot --nginx -d "$domain" --non-interactive --agree-tos --register-unsafely-without-email --redirect
nginx -t
systemctl reload nginx
echo "ok: https://$domain"

#!/bin/bash
set -e
apt-get update -y
apt-get install -y python3-pip nginx openssl whois
pip3 install --quiet flask requests

cat > /opt/web_app.py <<'CLOUDBREACH_APP_PY_EOF_MARKER'
${app_content}
CLOUDBREACH_APP_PY_EOF_MARKER

# Flag 2 -- the command-injection chain's proof of RCE. Deliberately just
# a plain file (readable by root, which is who the app runs as -- see the
# service unit below); nothing about *reading* it is the interesting part,
# reaching a position to run `cat` at all is.
cat > /opt/flag2.txt <<'FLAG2EOF'
flag{${flag2}}
FLAG2EOF

cat > /etc/systemd/system/cloudbreach-web.service <<'UNIT'
[Unit]
Description=CloudBreach web-01 app
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/web_app.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now cloudbreach-web.service

# ---------------------------------------------------------------------------
# TLS: self-signed cert regenerated fresh on every boot, SAN covers both the
# real domain and the raw public IP -- same "regenerate on start so it
# always matches the current deployment" pattern the SoulSecure course's
# own nginx entrypoint uses. DOMAIN is a free DuckDNS name (see variables.tf
# / README.md) pointed at web-01's RESERVED public IP -- unlike the earlier
# nip.io-based version, this domain doesn't change even if the underlying
# instance gets destroyed and recreated by a future user_data edit, since
# the reserved IP (and therefore what DuckDNS resolves to) stays constant.
PUBLIC_IP=$(curl -s https://checkip.amazonaws.com || echo "127.0.0.1")
DOMAIN="${duckdns_domain}"

mkdir -p /etc/nginx/tls
openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
  -keyout /etc/nginx/tls/soulsecure.key -out /etc/nginx/tls/soulsecure.crt \
  -subj "/C=SG/O=SoulSecure Inc./CN=$DOMAIN" \
  -addext "subjectAltName=DNS:$DOMAIN,IP:$PUBLIC_IP"
chmod 600 /etc/nginx/tls/soulsecure.key

cat > /etc/nginx/sites-available/soulsecure <<'NGINX'
server {
    listen 80 default_server;
    server_name _;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl default_server;
    server_name _;

    ssl_certificate     /etc/nginx/tls/soulsecure.crt;
    ssl_certificate_key /etc/nginx/tls/soulsecure.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
NGINX

rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/soulsecure /etc/nginx/sites-enabled/soulsecure
nginx -t
systemctl enable --now nginx
systemctl restart nginx

# Ubuntu images on OCI ship with host-level iptables rules that only allow
# inbound 22/tcp by default (cloud-init's default OCI hardening) -- an NSG
# allow on 80/443 alone is NOT enough, this host firewall blocks them too
# until explicitly opened here. Hit this exact issue once already (see
# InstructorKey.md) -- don't drop this block on a future edit.
iptables -I INPUT -p tcp --dport 80 -j ACCEPT
iptables -I INPUT -p tcp --dport 443 -j ACCEPT
netfilter-persistent save

# ---------------------------------------------------------------------------
# Upgrade to a real Let's Encrypt certificate, best-effort. Works because
# DOMAIN really resolves to this box (DuckDNS A record -- see README.md's
# Setup section) and port 80 is deliberately world-open in network.tf (ACME
# HTTP-01 validation needs that, not just allowed_cidr) -- see that file's
# comment for why. Falls back to the self-signed cert
# above if this fails for any reason (rate limit, DNS propagation lag,
# transient network issue) rather than failing the whole boot.
# ---------------------------------------------------------------------------
apt-get install -y certbot python3-certbot-nginx || true
certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN" --redirect || true

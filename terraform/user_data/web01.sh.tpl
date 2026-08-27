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

# ---------------------------------------------------------------------------
# Hourly self-reset, entirely local to this box -- no dependency on the
# operator's own machine at all. An earlier design ran this from a Windows
# laptop via Task Scheduler + SSH; it worked interactively but failed
# unattended (scp closing the connection right after auth when launched
# non-interactively under the Scheduler, root cause never pinned down --
# see InstructorKey.md) and depended on that one machine being on and its
# SSH client behaving consistently. Cron on web-01 itself sidesteps both
# problems, and doubles as this range's actual answer to "what if a player
# breaks something" long-term.
#
# Keeps a pristine copy of the app + Flag 2 right here (restored every
# hour), and a real copy of internal-01's SSH key (root-only, 600) so this
# box can re-plant Flag 1 + the notes file on internal-01 directly, over
# the exact same network path (web-01's NSG -> internal-01) the intended
# vulnerability chain itself uses -- not a special backdoor, just this
# box's own private key alongside the one the leaked PAR hands an attacker.
# ---------------------------------------------------------------------------
apt-get install -y cron openssh-client || true
# Give the cron package a moment to finish registering its binary/service
# before relying on it -- hit a one-time race on a real deploy where
# `crontab -` silently did nothing immediately after `apt-get install cron`
# (worked fine seconds later, manually). Cheap insurance either way.
sleep 3

mkdir -p /opt/pristine /root/.ssh
cp /opt/web_app.py /opt/pristine/web_app.py
cp /opt/flag2.txt /opt/pristine/flag2.txt

cat > /root/.ssh/internal01_key <<'INTERNAL01KEYEOF'
${internal01_ssh_key}
INTERNAL01KEYEOF
chmod 600 /root/.ssh/internal01_key

cat > /opt/reset-range.sh <<'RESETEOF'
#!/bin/bash
set -e
cp /opt/pristine/web_app.py /opt/web_app.py
cp /opt/pristine/flag2.txt /opt/flag2.txt
systemctl restart cloudbreach-web
systemctl restart nginx

ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 \
  -i /root/.ssh/internal01_key ubuntu@${internal01_private_ip} '
  printf "flag{${flag1}}\n" > /home/ubuntu/flag.txt
  sudo mkdir -p /opt/meridian-internal
  printf "Internal note: nightly customer export job still points at the old backup\nhost. Ops ticket MERI-4471 opened to fix. -- J\n" | sudo tee /opt/meridian-internal/customer-export-notice.txt > /dev/null
'
echo "[$(date)] range reset complete"
RESETEOF
chmod 700 /opt/reset-range.sh

# NOTE: originally installed via `crontab -` (piping a heredoc into the
# crontab command). That silently produced an EMPTY crontab on two separate
# real boots in a row, `sleep 3` after the package install included -- ruled
# out as a package-readiness race by manually re-running the exact same
# `crontab -` pipeline over SSH seconds after boot, which worked immediately.
# The `crontab` command goes through PAM (pam_loginuid in particular), which
# can misbehave this early in a cloud-init boot before a normal login
# session exists -- writing straight to /etc/cron.d/ instead bypasses the
# `crontab` binary and its PAM path entirely; cron reads files there
# directly, no login session required. Standard practice for provisioning
# cron jobs from boot scripts/config management for exactly this reason.
cat > /etc/cron.d/cloudbreach-reset <<'CRONEOF'
0 * * * * root /opt/reset-range.sh >> /var/log/cloudbreach-reset.log 2>&1
CRONEOF
chmod 644 /etc/cron.d/cloudbreach-reset
systemctl enable --now cron
systemctl restart cron
echo "cron install check: $(cat /etc/cron.d/cloudbreach-reset)"

# Run it once now too, so a fresh boot starts from a verified-clean state
# rather than waiting up to an hour for the first cron firing.
/opt/reset-range.sh >> /var/log/cloudbreach-reset.log 2>&1 || true

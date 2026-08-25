#!/bin/bash
set -e

cat > /home/ubuntu/flag.txt <<EOF
flag{${flag}}
EOF
chown ubuntu:ubuntu /home/ubuntu/flag.txt

mkdir -p /opt/meridian-internal
cat > /opt/meridian-internal/customer-export-notice.txt <<'EOF'
Internal note: nightly customer export job still points at the old backup
host. Ops ticket MERI-4471 opened to fix. -- J
EOF

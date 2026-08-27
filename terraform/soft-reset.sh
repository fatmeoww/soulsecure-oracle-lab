#!/bin/bash
# CloudBreach Range -- soft reset (SSH-based, no OCI API calls).
#
# Restores both boxes to their game-ready state WITHOUT destroying and
# recreating the underlying instances (that's what reset.sh / a
# `terraform apply -replace=...` does instead -- keep that as the manual
# "nuclear option" for when a box is broken badly enough that SSH itself
# doesn't work, e.g. a player's RCE genuinely trashed the filesystem or the
# network stack).
#
# This script instead:
#   - re-deploys the canonical app/web_app.py to web-01 and restarts its
#     service (undoes any tampering with the app itself, e.g. from someone
#     poking around after getting the command-injection RCE)
#   - re-plants both flag files (Flag 2 on web-01, Flag 1 + the notes file
#     on internal-01) in case a player deleted or edited one
#   - restarts nginx on web-01 (in case its config got touched)
#
# Deliberately does NOT touch TLS certs, NSGs, the reserved IP, or anything
# OCI-API-side -- none of that is something gameplay can break, and this
# script never calls the OCI API at all, so it can't hit the "Out of host
# capacity" issue a full instance replace can. Safe to run on a schedule,
# including while someone is mid-engagement (worst case, it interrupts
# their session and hands them a fresh one).
#
# One-time setup this depends on (see ../README.md's "Automatic hourly
# reset" section for the full walkthrough):
#   1. ~/.ssh/cloudbreach_admin -- the operator SSH key (already set up if
#      you've been following this range's README)
#   2. ~/.ssh/cloudbreach_internal01_admin -- internal-01's real key,
#      extracted once via:
#        terraform output -raw internal01_admin_ssh_key > ~/.ssh/cloudbreach_internal01_admin
#        chmod 600 ~/.ssh/cloudbreach_internal01_admin
#   3. Two Host aliases in ~/.ssh/config (cloudbreach-web01,
#      cloudbreach-internal01 with ProxyJump) -- see README.md for the
#      exact block to add.
set -e

# Uses the cloudbreach-web01 / cloudbreach-internal01 aliases from
# ~/.ssh/config (see README.md's setup section) rather than hardcoded IPs,
# so moving the range to a different account/region (as happened once
# already -- ap-singapore-1 ran out of Always Free host capacity, moved to
# a second tenancy in ap-tokyo-1) only ever needs that one config file
# updated, not this script.
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FLAG2="e2f73445060fd21acbe97b6794dfbea2"
FLAG1="fd16978f423c836c563079917db6978a"

echo "[$(date)] Soft-resetting web-01..."
scp "$REPO_ROOT/app/web_app.py" cloudbreach-web01:/tmp/web_app.py
ssh cloudbreach-web01 "
  sudo cp /tmp/web_app.py /opt/web_app.py
  rm -f /tmp/web_app.py
  printf 'flag{$FLAG2}\n' | sudo tee /opt/flag2.txt > /dev/null
  sudo systemctl restart cloudbreach-web
  sudo systemctl restart nginx
  systemctl is-active cloudbreach-web nginx
"

echo "[$(date)] Soft-resetting internal-01..."
ssh cloudbreach-internal01 "
  printf 'flag{$FLAG1}\n' > /home/ubuntu/flag.txt
  sudo mkdir -p /opt/meridian-internal
  printf 'Internal note: nightly customer export job still points at the old backup\nhost. Ops ticket MERI-4471 opened to fix. -- J\n' | sudo tee /opt/meridian-internal/customer-export-notice.txt > /dev/null
"

echo "[$(date)] Soft reset complete."

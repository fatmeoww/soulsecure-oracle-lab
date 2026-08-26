#!/bin/bash
# CloudBreach Range -- reset to a pristine state.
#
# Everything here is defined by Terraform + user_data -- there is no
# database, no persistent volume, no student-generated state anyone needs
# to preserve. If a player (accidentally or on purpose, via the RCE the
# range is built to be exploited with) breaks/deletes something on either
# box, this throws the instance away and recreates it fresh from source --
# same flags, same reserved IP, same DuckDNS domain, same TLS cert
# (Certbot re-requests it automatically on boot). Takes about a minute per
# instance, free (Always Free tier), and gives you back byte-for-byte the
# same range every time.
#
# Usage:
#   ./reset.sh            # reset both web-01 and internal-01
#   ./reset.sh web01       # reset only web-01
#   ./reset.sh internal01  # reset only internal-01
set -e
cd "$(dirname "$0")"

TARGET="${1:-both}"

case "$TARGET" in
  web01)
    terraform apply -replace="oci_core_instance.web01" -auto-approve
    ;;
  internal01)
    terraform apply -replace="oci_core_instance.internal01" -auto-approve
    ;;
  both)
    terraform apply \
      -replace="oci_core_instance.web01" \
      -replace="oci_core_instance.internal01" \
      -auto-approve
    ;;
  *)
    echo "Usage: $0 [web01|internal01|both]" >&2
    exit 1
    ;;
esac

echo
echo "Reset complete. New outputs:"
terraform output

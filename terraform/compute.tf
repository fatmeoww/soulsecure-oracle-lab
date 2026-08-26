data "oci_identity_availability_domains" "ads" {
  compartment_id = var.compartment_ocid
}

data "oci_core_images" "ubuntu" {
  compartment_id           = var.compartment_ocid
  operating_system         = "Canonical Ubuntu"
  operating_system_version = "22.04"
  shape                    = var.instance_shape
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"
}

locals {
  ubuntu_image_id       = data.oci_core_images.ubuntu.images[0].id
  availability_domain    = data.oci_identity_availability_domains.ads.availability_domains[0].name
  internal01_key_par_url = "https://objectstorage.${var.region}.oraclecloud.com${oci_objectstorage_preauthrequest.internal01_key_par.access_uri}"
}

# ---------------------------------------------------------------------------
# web-01 -- public, internet-facing, the intended entry point. Its instance
# metadata carelessly includes a "backup recovery" URL (see below) -- that's
# the deliberate misconfiguration this range demonstrates. OCI's IMDS v2
# still requires the `Authorization: Bearer Oracle` header on every request,
# which is exactly why web_app.py's /preview supports forwarding a custom
# header -- see StudentGuide.md.
# ---------------------------------------------------------------------------
resource "oci_core_instance" "web01" {
  compartment_id      = var.compartment_ocid
  availability_domain = local.availability_domain
  shape                = var.instance_shape
  display_name         = "cloudbreach-web01"

  # VM.Standard.E2.1.Micro is a fixed shape (1/8 OCPU, 1GB -- not a
  # ".Flex" shape), so no shape_config block is needed or accepted here.
  # If you switch instance_shape to a flex shape (e.g. VM.Standard.A1.Flex,
  # also Always Free eligible), add a shape_config { ocpus = ...
  # memory_in_gbs = ... } block back in.

  create_vnic_details {
    subnet_id                = oci_core_subnet.public.id
    nsg_ids                   = [oci_core_network_security_group.web01.id]
    # No ephemeral IP here -- a RESERVED public IP is attached separately
    # below instead, specifically so the public IP (and therefore the
    # nip.io domain in every doc) survives a `metadata` change forcing this
    # instance to be replaced. Ephemeral IPs are re-randomized on every
    # recreate; reserved ones aren't -- see the oci_core_public_ip resource.
    assign_public_ip          = false
    assign_private_dns_record = true
  }

  source_details {
    source_type = "image"
    source_id   = local.ubuntu_image_id
  }

  metadata = {
    ssh_authorized_keys = var.admin_ssh_public_key
    # gzip+base64, not plain base64 -- the app is a full multi-page site now
    # (~25KB of Python/HTML/CSS), and OCI caps total instance metadata at
    # 32000 bytes. cloud-init auto-detects gzip'd user-data after base64
    # decoding, no extra config needed. Plain base64 alone blew past the
    # cap; this comfortably clears it.
    user_data = base64gzip(templatefile("${path.module}/user_data/web01.sh.tpl", {
      app_content    = file("${path.module}/../app/web_app.py")
      duckdns_domain = var.duckdns_domain
      flag2          = var.web01_flag2
    }))
    # The deliberate misconfiguration: a presigned "recovery" URL for
    # internal-01's SSH key, stashed in instance metadata for an ops
    # automation script that reads it via IMDS -- exactly the kind of
    # thing that leaks wholesale the moment an SSRF bug can reach IMDS.
    backup_recovery_url   = local.internal01_key_par_url
    backup_recovery_notes = "Meridian ops: internal-01 recovery key, rotate quarterly per ticket MERI-4471"
  }
}

# ---------------------------------------------------------------------------
# A RESERVED public IP for web-01 -- unlike an ephemeral IP, this one is
# yours permanently and gets reattached to whatever the current web-01
# instance is, even after a full destroy+recreate (which a `metadata`/
# user_data change forces -- see the instance resource above). Free under
# Always Free, same as everything else here; this is what keeps
# web01_domain stable across source edits instead of changing every time.
# ---------------------------------------------------------------------------
data "oci_core_private_ips" "web01" {
  ip_address = oci_core_instance.web01.private_ip
  subnet_id  = oci_core_subnet.public.id
}

resource "oci_core_public_ip" "web01" {
  compartment_id = var.compartment_ocid
  display_name   = "cloudbreach-web01-reserved-ip"
  lifetime       = "RESERVED"
  private_ip_id  = data.oci_core_private_ips.web01.private_ips[0].id
}

# ---------------------------------------------------------------------------
# NOTE: an earlier version of this file also had a null_resource here that
# called the DuckDNS update API automatically via local-exec whenever the
# reserved IP changed. Dropped it -- Terraform's local-exec runs via cmd.exe
# on Windows by default, whose quoting rules mangled the URL (`curl` exit
# status 3, malformed URL) even though the underlying curl command is fine
# run directly. Not worth fighting cross-shell quoting for what's pure
# insurance anyway (the reserved IP above already means this domain doesn't
# need re-pointing under normal operation) -- if the reserved IP is ever
# genuinely reassigned, just re-run the update manually:
#   curl -s "https://www.duckdns.org/update?domains=<subdomain>&token=<token>&ip=<new-ip>"
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# internal-01 -- private subnet, no public IP, SSH reachable only from
# web-01's NSG. The lateral-movement target.
# ---------------------------------------------------------------------------
resource "oci_core_instance" "internal01" {
  compartment_id      = var.compartment_ocid
  availability_domain = local.availability_domain
  shape                = var.instance_shape
  display_name         = "cloudbreach-internal01"

  create_vnic_details {
    subnet_id       = oci_core_subnet.private.id
    nsg_ids          = [oci_core_network_security_group.internal01.id]
    assign_public_ip = false
  }

  source_details {
    source_type = "image"
    source_id   = local.ubuntu_image_id
  }

  metadata = {
    ssh_authorized_keys = tls_private_key.internal01.public_key_openssh
    user_data = base64encode(templatefile("${path.module}/user_data/internal01.sh.tpl", {
      flag = var.internal01_flag
    }))
  }
}

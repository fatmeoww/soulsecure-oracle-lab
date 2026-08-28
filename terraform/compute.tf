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

# Separate image lookup for web-01's own shape (see web01_instance_shape --
# defaults to the ARM64 VM.Standard.A1.Flex, a different capacity pool from
# internal01's VM.Standard.E2.1.Micro, so it needs its own AMD/ARM-matched
# image rather than reusing data.oci_core_images.ubuntu above).
data "oci_core_images" "web01" {
  compartment_id           = var.compartment_ocid
  operating_system         = "Canonical Ubuntu"
  operating_system_version = "22.04"
  shape                    = var.web01_instance_shape
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"
}

locals {
  ubuntu_image_id       = data.oci_core_images.ubuntu.images[0].id
  web01_image_id         = data.oci_core_images.web01.images[0].id
  availability_domain    = data.oci_identity_availability_domains.ads.availability_domains[0].name
  internal01_key_par_url = "https://objectstorage.${var.region}.oraclecloud.com${oci_objectstorage_preauthrequest.internal01_key_par.access_uri}"

  # internal-01's stable internal DNS name -- <hostname_label>.<subnet dns_label>.
  # <vcn dns_label>.oraclevcn.com, resolvable only from inside the VCN (i.e.
  # from web-01). Built from the subnet/VCN dns_labels rather than typed out
  # by hand, so it can never drift from what OCI actually assigns. Used
  # instead of internal-01's private IP anywhere a private IP would
  # otherwise have to be hardcoded/baked in -- if internal-01 is ever
  # replaced on its own (`reset.sh internal01`), it keeps this same DNS name
  # even though its actual private IP can change, so nothing pointing at it
  # by name needs to be redeployed just because internal-01 was.
  internal01_dns_fqdn = "internal01.${oci_core_subnet.private.dns_label}.${oci_core_vcn.main.dns_label}.oraclevcn.com"
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
  shape                = var.web01_instance_shape
  display_name         = "cloudbreach-web01"

  # web-01's own first boot runs reset-range.sh once immediately, which
  # SSHes straight to internal-01 by DNS name -- that only resolves/connects
  # once internal-01 actually exists. Referencing internal01's private_ip
  # used to create this ordering implicitly; now that the DNS name is
  # derived purely from static subnet/VCN labels (no dependency on the
  # internal01 instance itself), that implicit ordering is gone, so it's
  # made explicit here instead. Without it, Terraform could create both
  # instances in parallel and this first-boot reset attempt would just fail
  # once (harmless -- the hourly cron retries and self-heals), but there is
  # no reason to leave that to chance.
  depends_on = [oci_core_instance.internal01]

  # shape_config is only valid/required for ".Flex" shapes (e.g.
  # VM.Standard.A1.Flex) -- fixed shapes like VM.Standard.E2.1.Micro don't
  # accept it at all, so this block is conditional on web01_instance_shape
  # actually being a Flex shape. 1 OCPU / 6GB is comfortably inside the
  # Always Free A1 allowance (up to 4 OCPU / 24GB total) on the occasions
  # web01_instance_shape is set to an A1 shape.
  dynamic "shape_config" {
    for_each = strcontains(var.web01_instance_shape, "Flex") ? [1] : []
    content {
      ocpus         = 1
      memory_in_gbs = 6
    }
  }

  create_vnic_details {
    subnet_id                = oci_core_subnet.public.id
    nsg_ids                   = [oci_core_network_security_group.web01.id]
    hostname_label            = "web01"
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
    source_id   = local.web01_image_id
  }

  # data.oci_core_images always fetches whatever Ubuntu 22.04 image is
  # currently newest, so its result can change between one `terraform
  # plan` and the next just because Oracle published a new image -- with
  # no ignore_changes, that drift makes Terraform try to update a running
  # instance's boot image in place, which OCI's API doesn't actually
  # support cleanly (hit this for real: a routine allowed_cidr-only apply
  # unexpectedly also tried this and failed with an unrelated-looking
  # `sourceDetails.kmsKeyId size must be between 1 and 255` error -- a
  # provider quirk when it attempts an update the API rejects). The
  # instance was left completely unaffected since the API call itself
  # failed, but there's no reason to let this class of drift threaten an
  # otherwise-unrelated apply again. source_id should only ever matter at
  # initial launch anyway.
  lifecycle {
    ignore_changes = [source_details]
  }

  metadata = {
    ssh_authorized_keys = var.admin_ssh_public_key
    # gzip+base64, not plain base64 -- the app is a full multi-page site now
    # (~25KB of Python/HTML/CSS), and OCI caps total instance metadata at
    # 32000 bytes. cloud-init auto-detects gzip'd user-data after base64
    # decoding, no extra config needed. Plain base64 alone blew past the
    # cap; this comfortably clears it.
    user_data = base64gzip(templatefile("${path.module}/user_data/web01.sh.tpl", {
      app_content         = file("${path.module}/../app/web_app.py")
      duckdns_domain      = var.duckdns_domain
      flag2               = var.web01_flag2
      flag1               = var.internal01_flag
      # DNS name, not a baked-in private IP -- see local.internal01_dns_fqdn
      # above for why. Resolves correctly from web-01 regardless of what
      # internal-01's actual private IP happens to be at the time.
      internal01_host     = local.internal01_dns_fqdn
      internal01_ssh_key  = tls_private_key.internal01.private_key_pem
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
    # Gives internal-01 a stable internal DNS name (see
    # local.internal01_dns_fqdn) instead of only ever being addressable by
    # its private IP -- the private subnet's dns_label ("private") plus the
    # VCN's ("cloudbreach") plus this hostname_label together resolve as
    # internal01.private.cloudbreach.oraclevcn.com from anywhere inside the
    # VCN (i.e. from web-01).
    hostname_label            = "internal01"
    assign_private_dns_record = true
  }

  source_details {
    source_type = "image"
    source_id   = local.ubuntu_image_id
  }

  # See the matching comment on oci_core_instance.web01 -- same
  # always-fetches-latest data source drift, same fix.
  lifecycle {
    ignore_changes = [source_details]
  }

  metadata = {
    ssh_authorized_keys = tls_private_key.internal01.public_key_openssh
    user_data = base64encode(templatefile("${path.module}/user_data/internal01.sh.tpl", {
      flag = var.internal01_flag
    }))
  }
}

resource "oci_core_vcn" "main" {
  compartment_id = var.compartment_ocid
  cidr_blocks    = ["10.0.0.0/16"]
  display_name   = "cloudbreach-vcn"
  dns_label      = "cloudbreach"
}

resource "oci_core_internet_gateway" "igw" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.main.id
  display_name   = "cloudbreach-igw"
  enabled        = true
}

# --- Public subnet: web-01 lives here, internet-facing entry point ---
resource "oci_core_route_table" "public" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.main.id
  display_name   = "cloudbreach-public-rt"

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.igw.id
  }
}

resource "oci_core_subnet" "public" {
  compartment_id             = var.compartment_ocid
  vcn_id                     = oci_core_vcn.main.id
  cidr_block                 = "10.0.1.0/24"
  display_name               = "cloudbreach-public"
  dns_label                  = "public"
  route_table_id             = oci_core_route_table.public.id
  security_list_ids          = [oci_core_vcn.main.default_security_list_id]
  prohibit_public_ip_on_vnic = false
}

# --- Private subnet: internal-01 lives here, no internet route at all ---
# (deliberate -- it doesn't need outbound access for this lab, and skipping
# a NAT Gateway keeps this range at zero baseline cost; see README)
resource "oci_core_route_table" "private" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.main.id
  display_name   = "cloudbreach-private-rt"
  # No route rules -- fully isolated from the internet by design.
}

resource "oci_core_subnet" "private" {
  compartment_id             = var.compartment_ocid
  vcn_id                     = oci_core_vcn.main.id
  cidr_block                 = "10.0.2.0/24"
  display_name               = "cloudbreach-private"
  dns_label                  = "private"
  route_table_id             = oci_core_route_table.private.id
  security_list_ids          = [oci_core_vcn.main.default_security_list_id]
  prohibit_public_ip_on_vnic = true
}

# --- Network Security Groups (per-VNIC, mirrors AWS security-group-to-
# security-group references so internal-01 can be scoped to "only from
# web-01" rather than a static CIDR) ---

resource "oci_core_network_security_group" "web01" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.main.id
  display_name   = "cloudbreach-web01-nsg"
}

resource "oci_core_network_security_group_security_rule" "web01_ingress_ssh" {
  network_security_group_id = oci_core_network_security_group.web01.id
  direction                 = "INGRESS"
  protocol                  = "6" # TCP
  source_type                = "CIDR_BLOCK"
  source                     = var.allowed_cidr
  tcp_options {
    destination_port_range {
      min = 22
      max = 22
    }
  }
}

resource "oci_core_network_security_group_security_rule" "web01_ingress_http" {
  network_security_group_id = oci_core_network_security_group.web01.id
  direction                 = "INGRESS"
  protocol                  = "6"
  # World-open on purpose, unlike every other rule here -- port 80 only
  # ever serves the ACME (Let's Encrypt) HTTP-01 challenge and a redirect
  # to 443, nothing else. Let's Encrypt's validation servers connect from
  # addresses all over the world, not just allowed_cidr, and need this to
  # issue and (every ~60 days) renew a real trusted certificate. This is
  # the standard, low-risk pattern any public HTTPS site using Let's
  # Encrypt follows -- 443 (the actual app/content) is also world-open, see
  # web01_ingress_https below for why.
  source_type = "CIDR_BLOCK"
  source      = "0.0.0.0/0"
  tcp_options {
    destination_port_range {
      min = 80
      max = 80
    }
  }
}

resource "oci_core_network_security_group_security_rule" "web01_ingress_https" {
  network_security_group_id = oci_core_network_security_group.web01.id
  direction                 = "INGRESS"
  protocol                  = "6"
  # World-open, not scoped to allowed_cidr -- this range is meant for a
  # whole team to play, not just the operator, and allowed_cidr is a
  # single CIDR (one home/office IP, or a small static set at best). A
  # teammate connecting from a different IP got a silent "site can't be
  # reached" the one time this was still scoped to allowed_cidr (SYN just
  # dropped, no response -- indistinguishable from a real outage without
  # checking server-side health first, see InstructorKey.md). The app
  # itself is deliberately the thing being attacked in this exercise, so
  # exposing it publicly isn't adding real risk beyond what the range
  # already intends. SSH (22, below) stays scoped to allowed_cidr --
  # that's genuine operator/admin access, not part of the intended
  # player-facing surface.
  source_type = "CIDR_BLOCK"
  source      = "0.0.0.0/0"
  tcp_options {
    destination_port_range {
      min = 443
      max = 443
    }
  }
}

resource "oci_core_network_security_group_security_rule" "web01_egress_all" {
  network_security_group_id = oci_core_network_security_group.web01.id
  direction                 = "EGRESS"
  protocol                  = "all"
  destination_type           = "CIDR_BLOCK"
  destination                = "0.0.0.0/0"
}

resource "oci_core_network_security_group" "internal01" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.main.id
  display_name   = "cloudbreach-internal01-nsg"
}

resource "oci_core_network_security_group_security_rule" "internal01_ingress_ssh_from_web01" {
  network_security_group_id = oci_core_network_security_group.internal01.id
  direction                 = "INGRESS"
  protocol                  = "6"
  # Only from web-01's NSG -- this is the lateral-movement path, not a CIDR.
  source_type = "NETWORK_SECURITY_GROUP"
  source      = oci_core_network_security_group.web01.id
  tcp_options {
    destination_port_range {
      min = 22
      max = 22
    }
  }
}

resource "oci_core_network_security_group_security_rule" "internal01_egress_all" {
  network_security_group_id = oci_core_network_security_group.internal01.id
  direction                 = "EGRESS"
  protocol                  = "all"
  destination_type           = "CIDR_BLOCK"
  destination                = "0.0.0.0/0"
}

variable "region" {
  description = "OCI region to deploy into, e.g. ap-singapore-1, us-ashburn-1."
  type        = string
}

variable "compartment_ocid" {
  description = <<-EOT
    OCID of the compartment to deploy into. Using your tenancy's root
    compartment OCID is fine for a personal/practice account -- find it in
    the OCI Console under Identity > Compartments, or:
    oci iam compartment list --compartment-id-in-subtree true
  EOT
  type = string
}

variable "allowed_cidr" {
  description = <<-EOT
    CIDR allowed to reach web-01's SSH (22) and app (5000) ports, e.g.
    "203.0.113.4/32" for just your own IP. REQUIRED -- no default, on
    purpose, so this never accidentally deploys wide open to 0.0.0.0/0.
    Find your current IP with: curl -s https://checkip.amazonaws.com
  EOT
  type = string
}

variable "admin_ssh_public_key" {
  description = <<-EOT
    Your own SSH public key (contents of e.g. ~/.ssh/id_ed25519.pub), used
    for direct operator access to web-01. Separate from the key the lab is
    designed to make an attacker steal for internal-01 -- never part of the
    intended attack path.
  EOT
  type = string
}

variable "instance_shape" {
  description = <<-EOT
    Always Free eligible shape. VM.Standard.E2.1.Micro is the simplest
    choice (AMD, x86_64, always free, up to 2 per tenancy -- exactly what
    this range needs). The Ampere A1 flex shape is more powerful and also
    always-free (up to 4 OCPU / 24GB total, split across instances) but
    needs arm64 images and is sometimes hard to provision due to regional
    capacity limits -- stick with E2.1.Micro unless you have a reason not to.
  EOT
  type    = string
  default = "VM.Standard.E2.1.Micro"
}

variable "internal01_flag" {
  description = "Flag value planted on internal-01, proving the pivot succeeded."
  type        = string
  default     = "fd16978f423c836c563079917db6978a"
}

variable "web01_flag2" {
  description = <<-EOT
    Flag value planted at /opt/flag2.txt on web-01, proving the OS command
    injection in /tools/lookup was exploited for real command execution
    (separate chain from Flag 1's SSRF -> internal-01 pivot).
  EOT
  type    = string
  default = "e2f73445060fd21acbe97b6794dfbea2"
}

variable "duckdns_domain" {
  description = <<-EOT
    Free DuckDNS domain pointed at web-01's reserved public IP, e.g.
    "soulsecure.duckdns.org" -- register one at https://www.duckdns.org
    (sign in, add a subdomain, point it at the `web01_public_ip` output).
    Used as the CN/SAN for both the fallback self-signed cert and the real
    Let's Encrypt certificate web01.sh.tpl requests on every boot.
  EOT
  type    = string
  default = "soulsecure.duckdns.org"
}

variable "par_expiration" {
  description = <<-EOT
    RFC3339 expiration for the Pre-Authenticated Request URL that "leaks"
    internal-01's SSH key. Bump this forward if it's ever in the past by
    the time you deploy -- `terraform apply` will just recreate the PAR
    with a fresh URL.
  EOT
  type    = string
  default = "2030-01-01T00:00:00Z"
}

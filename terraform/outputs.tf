output "web01_public_ip" {
  description = "Reserved public IP of web-01 -- stable across recreates (see oci_core_public_ip.web01 in compute.tf)"
  value       = oci_core_public_ip.web01.ip_address
}

output "web01_domain" {
  description = <<-EOT
    Free DuckDNS domain for web-01 (var.duckdns_domain) -- point its A
    record at web01_public_ip once; since that IP is RESERVED (not
    ephemeral), it stays correct even when web-01 gets destroyed and
    recreated by a future source change.
  EOT
  value = var.duckdns_domain
}

output "web01_app_url" {
  description = "HTTPS, no port -- nginx terminates TLS on 443 and proxies to the app internally. Real Let's Encrypt certificate, issued automatically on boot."
  value       = "https://${var.duckdns_domain}/"
}

output "ssh_to_web01" {
  description = "Operator admin SSH into web-01 (not part of the intended attack path)"
  value       = "ssh ubuntu@${oci_core_public_ip.web01.ip_address}"
}

output "internal01_private_ip" {
  description = "internal-01's private IP right now -- only reachable from inside the VCN (i.e. from web-01). Reference only: web-01's own reset/readiness tooling addresses internal-01 by internal01_dns_name instead, precisely so it doesn't need updating if this IP ever changes."
  value       = oci_core_instance.internal01.private_ip
}

output "internal01_dns_name" {
  description = <<-EOT
    internal-01's stable internal DNS name (resolves only from inside the
    VCN, i.e. from web-01) -- what web-01's reset-range.sh/check-readiness.sh
    actually use to reach it, instead of a baked-in private IP. Also the
    right value to use as the HostName in an operator ~/.ssh/config
    `cloudbreach-internal01` entry (with `ProxyJump cloudbreach-web01`),
    so that config keeps working even if internal-01 is ever replaced on
    its own and comes back with a different private IP.
  EOT
  value = local.internal01_dns_fqdn
}

output "internal01_admin_ssh_key" {
  description = <<-EOT
    internal-01's real SSH private key (the same one leaked via the PAR in
    the intended attack chain) -- exposed here for the operator's own
    soft-reset tooling (see terraform/soft-reset.sh), which needs a
    standing way to reach internal-01 for maintenance without relying on
    the vulnerability chain itself. Extract once with:
      terraform output -raw internal01_admin_ssh_key > ~/.ssh/cloudbreach_internal01_admin
      chmod 600 ~/.ssh/cloudbreach_internal01_admin
    Marked sensitive so it doesn't print in plain `terraform output`/plan
    logs.
  EOT
  value     = tls_private_key.internal01.private_key_pem
  sensitive = true
}

output "note" {
  value = "This range is on OCI's Always Free tier -- no need to destroy it between sessions to save money, but `terraform destroy` still works if you want to tear it down (e.g. before rebuilding after an app-code change)."
}

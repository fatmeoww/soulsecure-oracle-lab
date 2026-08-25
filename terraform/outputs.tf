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
  description = "internal-01's private IP -- only reachable from inside the VCN (i.e. from web-01)"
  value       = oci_core_instance.internal01.private_ip
}

output "note" {
  value = "This range is on OCI's Always Free tier -- no need to destroy it between sessions to save money, but `terraform destroy` still works if you want to tear it down (e.g. before rebuilding after an app-code change)."
}

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    oci = {
      source  = "oracle/oci"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

# Reads ~/.oci/config (always this fixed path -- unlike the oci-cli, this
# provider does NOT respect $OCI_CLI_CONFIG_FILE) using whichever profile
# oci_config_profile names (DEFAULT unless overridden) -- see README.md's
# Setup section for how to generate that file via `oci setup config`, and
# its "Multiple accounts/regions" section for why a named profile matters
# (e.g. after moving this range to a second tenancy because the first
# one's home region ran out of Always Free host capacity).
provider "oci" {
  region              = var.region
  config_file_profile = var.oci_config_profile
}

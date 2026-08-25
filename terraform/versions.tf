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

# Reads ~/.oci/config's DEFAULT profile by default (same pattern as the AWS
# provider reading ~/.aws/credentials) -- see README.md's Setup section for
# how to generate that file via `oci setup config`.
provider "oci" {
  region = var.region
}

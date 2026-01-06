terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.60"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 4.0"
    }
  }
}

###############################################################################
# NOTE:
# This skeleton supports AWS OR Azure. Candidate should implement resources
# in only one cloud provider. Mixing aws_* and azurerm_* resources is disallowed
# by the policy tests.
###############################################################################

# --- AWS provider (optional) ---
provider "aws" {
  region = var.aws_region
}

# --- Azure provider (optional) ---
provider "azurerm" {
  features {}
}

locals {
  tenants = var.tenants
  # Expected: ["tenant_a", "tenant_b"] by default
}

# TODO: Candidate implements either AWS or Azure resources here.
# Suggested components:
# - raw + curated object storage
# - encryption (KMS / Key Vault baseline)
# - audit logs (CloudTrail / Diagnostic settings)
# - tenant roles/principals and policies/role-assignments that enforce isolation
# - minimal serving layer hookup (Athena+Glue / Synapse serverless) (skeleton OK)

variable "tenants" {
  description = "Tenant identifiers used for prefix layout and security isolation."
  type        = list(string)
  default     = ["tenant_a", "tenant_b"]
}

# AWS
variable "aws_region" {
  description = "AWS region (if using AWS)."
  type        = string
  default     = "eu-central-1"
}

# Azure (kept for completeness; not required to validate without deployment)
variable "azure_location" {
  description = "Azure location (if using Azure)."
  type        = string
  default     = "westeurope"
}

# Naming prefix to keep resource names consistent
variable "name_prefix" {
  description = "Prefix for naming resources (e.g., company/project short name)."
  type        = string
  default     = "gari-candidate"
}

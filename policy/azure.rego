package gari.azure

import rego.v1
import data.gari.common

azure if { common.using_azure }

# ---------------------------------------------------------------------------
# Azure baseline requirements (plan-only)
# ---------------------------------------------------------------------------

deny contains msg if {
  azure
  count(common.resources_by_type("azurerm_storage_account")) == 0
  msg := "Azure: expected at least one azurerm_storage_account (raw/curated storage)."
}

deny contains msg if {
  azure
  count(common.resources_by_type("azurerm_key_vault")) == 0
  msg := "Azure: expected azurerm_key_vault (baseline for secrets/keys)."
}

deny contains msg if {
  azure
  count(common.resources_by_type("azurerm_monitor_diagnostic_setting")) == 0
  msg := "Azure: expected azurerm_monitor_diagnostic_setting for audit/log export (e.g., to Log Analytics)."
}

# Enforce HTTPS-only and explicit TLS 1.2
deny contains msg if {
  azure
  sas := common.resources_by_type("azurerm_storage_account")
  some i
  sa := sas[i]
  a := common.after(sa)
  a.enable_https_traffic_only != true
  msg := sprintf("Azure: storage account '%s' must set enable_https_traffic_only = true.", [sa.name])
}

deny contains msg if {
  azure
  sas := common.resources_by_type("azurerm_storage_account")
  some i
  sa := sas[i]
  a := common.after(sa)
  not tls_ok(a.min_tls_version)
  msg := sprintf("Azure: storage account '%s' must set min_tls_version = 'TLS1_2'.", [sa.name])
}

tls_ok(v) if { v == "TLS1_2" }

# Disallow public blob access (explicit)
deny contains msg if {
  azure
  sas := common.resources_by_type("azurerm_storage_account")
  some i
  sa := sas[i]
  a := common.after(sa)
  a.allow_blob_public_access == true
  msg := sprintf("Azure: storage account '%s' must set allow_blob_public_access = false.", [sa.name])
}

# Container must be private (if containers exist)
deny contains msg if {
  azure
  cs := common.resources_by_type("azurerm_storage_container")
  count(cs) > 0
  some i
  c := cs[i]
  a := common.after(c)
  a.container_access_type != "private"
  msg := sprintf("Azure: container '%s' must set container_access_type = 'private'.", [c.name])
}

# ---------------------------------------------------------------------------
# Azure tenant isolation checks (plan-only, best-effort)
# ---------------------------------------------------------------------------

deny contains msg if {
  azure
  not any_role_assignment_mentions("tenant_a_readonly")
  msg := "Azure: expected role assignment indicating tenant_a_readonly."
}

deny contains msg if {
  azure
  not any_role_assignment_mentions("tenant_b_readonly")
  msg := "Azure: expected role assignment indicating tenant_b_readonly."
}

any_role_assignment_mentions(substr) if {
  ras := common.resources_by_type("azurerm_role_assignment")
  some i
  ra := ras[i]
  a := common.after(ra)
  role_assignment_field_contains(a, substr)
}

role_assignment_field_contains(a, substr) if {
  is_string(a.name)
  common.lc_contains(a.name, substr)
}

role_assignment_field_contains(a, substr) if {
  is_string(a.scope)
  common.lc_contains(a.scope, substr)
}

role_assignment_field_contains(a, substr) if {
  is_string(a.role_definition_name)
  common.lc_contains(a.role_definition_name, substr)
}

# Helper: scope must mention the tenant and must NOT mention the other tenant
scope_ok_for_tenant(scope, tenant) if {
  is_string(scope)
  common.lc_contains(scope, tenant)
  not common.lc_contains(scope, other_tenant(tenant))
}

other_tenant("tenant_a") := "tenant_b"
other_tenant("tenant_b") := "tenant_a"

# Deny if role assignment indicates tenant_a but scope is not tenant_a-only
deny contains msg if {
  azure
  ras := common.resources_by_type("azurerm_role_assignment")
  some i
  ra := ras[i]
  a := common.after(ra)

  indicates_tenant(a, "tenant_a")
  not scope_ok_for_tenant(a.scope, "tenant_a")

  msg := "Azure: role assignment indicating tenant_a must be scoped to tenant_a resources only (scope includes tenant_a and not tenant_b)."
}

# Deny if role assignment indicates tenant_b but scope is not tenant_b-only
deny contains msg if {
  azure
  ras := common.resources_by_type("azurerm_role_assignment")
  some i
  ra := ras[i]
  a := common.after(ra)

  indicates_tenant(a, "tenant_b")
  not scope_ok_for_tenant(a.scope, "tenant_b")

  msg := "Azure: role assignment indicating tenant_b must be scoped to tenant_b resources only (scope includes tenant_b and not tenant_a)."
}

indicates_tenant(a, tenant) if {
  is_string(a.name)
  common.lc_contains(a.name, tenant)
}

indicates_tenant(a, tenant) if {
  is_string(a.role_definition_name)
  common.lc_contains(a.role_definition_name, tenant)
}

indicates_tenant(a, tenant) if {
  is_string(a.scope)
  common.lc_contains(a.scope, tenant)
}

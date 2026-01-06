package gari.common

import rego.v1

# ----------------------------
# Safe defaults (plan-only)
# ----------------------------

default resource_changes := []
resource_changes := rc if {
  rc := input.resource_changes
}

default planned_values := {}
planned_values := pv if {
  pv := input.planned_values
}

# ----------------------------
# Provider detection
# ----------------------------

using_aws if {
  some i
  rc := resource_changes[i]
  startswith(rc.type, "aws_")
}

using_azure if {
  some i
  rc := resource_changes[i]
  startswith(rc.type, "azurerm_")
}

deny contains msg if {
  using_aws
  using_azure
  msg := "Do not mix AWS and Azure resources in one submission. Choose one cloud."
}

deny contains msg if {
  not using_aws
  not using_azure
  msg := "No AWS (aws_*) or Azure (azurerm_*) resources found in plan."
}

# ----------------------------
# Helpers
# ----------------------------

resources_by_type(t) := out if {
  out := [r |
    r := resource_changes[_]
    r.type == t
  ]
}

# Return r.change.after or {} if missing/unknown
after(r) := a if {
  a := r.change.after
} else := {} if {
  true
}

# Case-insensitive substring check
lc_contains(s, sub) if {
  is_string(s)
  contains(lower(s), lower(sub))
}

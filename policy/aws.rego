package gari.aws

import rego.v1
import data.gari.common

aws if { common.using_aws }

# ---------------------------------------------------------------------------
# AWS baseline requirements (plan-only)
# ---------------------------------------------------------------------------

deny contains msg if {
  aws
  count(common.resources_by_type("aws_s3_bucket")) == 0
  msg := "AWS: expected at least one aws_s3_bucket (raw/curated storage)."
}

deny contains msg if {
  aws
  count(common.resources_by_type("aws_kms_key")) == 0
  msg := "AWS: expected aws_kms_key for encryption at rest."
}

deny contains msg if {
  aws
  count(common.resources_by_type("aws_cloudtrail")) == 0
  msg := "AWS: expected aws_cloudtrail for auditability."
}

# Require Public Access Block on each bucket (best-effort match)
deny contains msg if {
  aws
  buckets := common.resources_by_type("aws_s3_bucket")
  some i
  b := buckets[i]
  not bucket_has_public_access_block(b)
  msg := sprintf("AWS: bucket '%s' missing aws_s3_bucket_public_access_block (block public access).", [b.name])
}

bucket_has_public_access_block(bucket_rc) if {
  pabs := common.resources_by_type("aws_s3_bucket_public_access_block")
  some j
  pab := pabs[j]

  pab_after := common.after(pab)
  b_after := common.after(bucket_rc)

  is_string(pab_after.bucket)
  bucket_ref_matches(pab_after.bucket, b_after)

  pab_after.block_public_acls == true
  pab_after.block_public_policy == true
  pab_after.ignore_public_acls == true
  pab_after.restrict_public_buckets == true
}

# Disjunction via multiple rule bodies (no infix or/and)
bucket_ref_matches(ref, b_after) if {
  is_string(b_after.bucket)
  ref == b_after.bucket
}

bucket_ref_matches(ref, b_after) if {
  is_string(b_after.id)
  ref == b_after.id
}

# Require server-side encryption configuration (dedicated resource or inline)
deny contains msg if {
  aws
  buckets := common.resources_by_type("aws_s3_bucket")
  some i
  b := buckets[i]
  not bucket_has_sse(b)
  msg := sprintf("AWS: bucket '%s' missing server-side encryption configuration.", [b.name])
}

bucket_has_sse(bucket_rc) if {
  encs := common.resources_by_type("aws_s3_bucket_server_side_encryption_configuration")
  some j
  enc := encs[j]

  enc_after := common.after(enc)
  b_after := common.after(bucket_rc)

  is_string(enc_after.bucket)
  bucket_ref_matches(enc_after.bucket, b_after)

  count(enc_after.rule) > 0
}

bucket_has_sse(bucket_rc) if {
  # Inline fallback (older/provider variants)
  b_after := common.after(bucket_rc)
  b_after.server_side_encryption_configuration != null
}

# ---------------------------------------------------------------------------
# AWS tenant isolation checks (plan-only, policy JSON parsing)
# ---------------------------------------------------------------------------

deny contains msg if {
  aws
  not exists_iam_policy_named_like("tenant_a_readonly")
  msg := "AWS: expected an aws_iam_policy with name containing 'tenant_a_readonly'."
}

deny contains msg if {
  aws
  not exists_iam_policy_named_like("tenant_b_readonly")
  msg := "AWS: expected an aws_iam_policy with name containing 'tenant_b_readonly'."
}

exists_iam_policy_named_like(substr) if {
  pols := common.resources_by_type("aws_iam_policy")
  some i
  p := pols[i]
  a := common.after(p)
  common.lc_contains(a.name, substr)
}

iam_policy_by_name_like(substr) := pol if {
  pols := common.resources_by_type("aws_iam_policy")
  some i
  p := pols[i]
  a := common.after(p)
  common.lc_contains(a.name, substr)
  pol := a
}

deny contains msg if {
  aws
  pol := iam_policy_by_name_like("tenant_a_readonly")
  not policy_limits_to_tenant(pol, "tenant_a")
  msg := "AWS: tenant_a_readonly policy must only allow curated/tenant_a/* access (and not tenant_b)."
}

deny contains msg if {
  aws
  pol := iam_policy_by_name_like("tenant_b_readonly")
  not policy_limits_to_tenant(pol, "tenant_b")
  msg := "AWS: tenant_b_readonly policy must only allow curated/tenant_b/* access (and not tenant_a)."
}

policy_limits_to_tenant(pol_after, tenant) if {
  is_string(pol_after.policy)
  doc := json.unmarshal(pol_after.policy)

  other := other_tenant(tenant)
  not policy_mentions_tenant(doc, other)

  policy_mentions_curated_prefix(doc, tenant)
}

other_tenant("tenant_a") := "tenant_b"
other_tenant("tenant_b") := "tenant_a"

policy_mentions_tenant(doc, tenant) if {
  some s
  stmt := doc.Statement[s]
  some r
  res := stmt.Resource[r]
  is_string(res)
  contains(res, sprintf("/curated/%s/", [tenant]))
}

policy_mentions_curated_prefix(doc, tenant) if {
  some s
  stmt := doc.Statement[s]
  some r
  res := stmt.Resource[r]
  is_string(res)
  contains(res, sprintf("/curated/%s/", [tenant]))
}

# If ListBucket is allowed, encourage prefix scoping via Condition.
deny contains msg if {
  aws
  pol := iam_policy_by_name_like("tenant_a_readonly")
  is_string(pol.policy)
  doc := json.unmarshal(pol.policy)
  listbucket_unscoped(doc)
  msg := "AWS: ListBucket detected without s3:prefix scoping Condition. Scope listing to curated/<tenant>/ via Condition."
}

deny contains msg if {
  aws
  pol := iam_policy_by_name_like("tenant_b_readonly")
  is_string(pol.policy)
  doc := json.unmarshal(pol.policy)
  listbucket_unscoped(doc)
  msg := "AWS: ListBucket detected without s3:prefix scoping Condition. Scope listing to curated/<tenant>/ via Condition."
}

listbucket_unscoped(doc) if {
  some s
  stmt := doc.Statement[s]
  action_has(stmt, "s3:ListBucket")
  stmt.Condition == null
}

action_has(stmt, action) if {
  is_string(stmt.Action)
  stmt.Action == action
}

action_has(stmt, action) if {
  some i
  stmt.Action[i] == action
}

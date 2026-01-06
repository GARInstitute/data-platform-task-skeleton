# Multi-tenant Cloud Data Platform Skeleton (AWS or Azure)

## Goal
Demonstrate hands-on ability to design a secure, multi-tenant cloud data platform using **only managed cloud services** and **Infrastructure as Code** — **without deploying anything**.

You will deliver:
- Terraform describing the infrastructure
- A Terraform plan exported to JSON (`evidence/plan.json`)
- Policy tests (OPA/Rego via `conftest`) that validate key security properties from the plan
- A minimal CI workflow that runs formatting/validation/lint/tests
- A short decisions note (max 1 page)

You may choose **either AWS or Azure** (not both).

---

## Scenario
We have two tenants with confidential data:
- `tenant_a`
- `tenant_b`

We store data in:
- `raw/<tenant_id>/...` (immutable ingestion zone)
- `curated/<tenant_id>/...` (cleaned/standardized zone)

We require **hard tenant isolation** enforced by **IAM/RBAC + data-plane permissions**, not just “the application filters by tenant_id”.

The platform must be designed to accommodate more data formats over time (numerical time-series, text, later large satellite files), but this task focuses on the platform skeleton and security boundaries.

---

## Your cloud choice
Choose **one**:
- **AWS** (recommended serving option: S3 + Glue Data Catalog + Athena)
- **Azure** (recommended serving option: ADLS Gen2 + Synapse serverless SQL)

**Do not mix AWS and Azure resources** in the same submission.

---

## Required roles / principals
Define these as Terraform-managed identities and permissions:
- `platform_admin`
- `data_engineer`
- `tenant_a_readonly`
- `tenant_b_readonly`

### Isolation requirements (must be enforceable from policies)
- `tenant_a_readonly` can read only `curated/tenant_a/*`
- `tenant_b_readonly` can read only `curated/tenant_b/*`
- Cross-tenant listing/reading must be denied (or not granted)

> You may choose whether tenants can read from `raw/`. If you allow it, it must be restricted to their own `raw/<tenant_id>/...` prefix only.

---

## Minimum architecture (Terraform plan-only)

### 1) Storage (raw + curated)
Describe object storage for raw and curated zones:
- AWS: S3 bucket(s) + prefix layout
- Azure: Storage account + containers/filesystems + directory/prefix layout

Use a clear layout such as:
- `raw/<tenant_id>/<source>/<yyyy>/<mm>/<dd>/...`
- `curated/<tenant_id>/<dataset>/<yyyy>/<mm>/<dd>/...`

### 2) Encryption + key management
- AWS: KMS key used for encryption at rest (SSE-KMS) for the relevant buckets
- Azure: Key Vault present (baseline) and storage encryption enabled (CMK is optional)

### 3) Serving layer (minimal)
Show how curated data becomes queryable using a managed cloud option.

AWS (choose one):
- Glue Data Catalog + Athena (preferred)
- Redshift Serverless (skeleton only)

Azure (choose one):
- Synapse serverless SQL (preferred)
- Fabric/Synapse lakehouse (skeleton only)

You do **not** need to implement ingestion compute (Lambda/Functions) for this task; focus on platform skeleton + security boundaries.

### 4) Auditability
- AWS: CloudTrail enabled (skeleton acceptable)
- Azure: Diagnostic settings enabled (e.g., to Log Analytics workspace)

### 5) Minimal monitoring
Provide at least one monitorable signal in Terraform (where feasible) or describe it in `docs/decisions.md`:
- ingestion failures / pipeline failures / function errors (conceptual is fine)

---

## Repository structure
You may keep the provided skeleton structure:

```
/.github/workflows
  ci.yml
/docs
  decisions.md
/evidence
  plan.json
  test_output.txt
/infra
  main.tf
  variables.tf
  outputs.tf
  /modules (optional)
/policy
  common.rego
  aws.rego
  azure.rego
```

---

## How to generate `evidence/plan.json` (no deployment)
From `infra/`:

```bash
terraform init
terraform fmt -recursive
terraform validate

terraform plan -out plan.out
terraform show -json plan.out > ../evidence/plan.json
```

**No `apply`.**

---

## Policy tests (must pass)
Use OPA/Rego with `conftest` to validate the plan JSON.

Run tests:
```bash
conftest test evidence/plan.json -p policy
```

Save output:
```bash
conftest test evidence/plan.json -p policy | tee evidence/test_output.txt
```

### Minimum test assertions (must be enforced by code)
Your rules must validate (from `plan.json`) that:

1) **No public access** to storage (S3 public access blocked / Azure container private and no public blob access)
2) **Encryption at rest** is enabled/enforced for storage
3) **Key management** resource exists (KMS / Key Vault)
4) **Audit logging** resources exist (CloudTrail / Diagnostic settings)
5) **Tenant isolation is enforceable**:
   - There are identities/policies/role-assignments for `tenant_a_readonly` and `tenant_b_readonly`
   - Policies/scopes do not permit `tenant_a_readonly` to list/read `curated/tenant_b/*` (and vice versa)
   - Avoid broad wildcards; if you use any wildcard actions/resources, justify briefly in `docs/decisions.md`

If you implement a different but stronger isolation model (e.g., account/subscription separation), update the rules accordingly and document the rationale.

---

## CI (minimal)
Add a CI workflow (GitHub Actions or equivalent) that runs on PR/push:
- `terraform fmt -check`
- `terraform validate`
- `tflint` (or `checkov`/`tfsec`)
- `conftest test evidence/plan.json -p policy`

---

## Decisions doc (max 1 page)
Create `docs/decisions.md` with:
- Your tenant isolation strategy and why you chose it
- How this design scales to many tenants (e.g., 50 → 200+)
- How you would extend to satellite data (storage + metadata/catalog + lifecycle tiering), 5–8 bullets
- What you would monitor first in production (3–5 signals)

---

## What we evaluate
1) **Security & multi-tenancy (most important)**:
   - hard isolation in IAM/RBAC + data plane permissions
   - encryption + no public access
   - auditability

2) **Cloud correctness**:
   - appropriate managed services and realistic configuration

3) **IaC quality**:
   - clean structure, variables/modules where appropriate
   - minimal wildcards, no secrets committed to the repo

4) **Clarity**:
   - short, practical `docs/decisions.md` explaining tradeoffs and scaling

---

## Submission
Provide a link to your git repository (or a zip archive) containing:
- Terraform code
- `evidence/plan.json`
- policy tests in `/policy`
- CI workflow in `/.github/workflows/ci.yml`
- `docs/decisions.md`
- `evidence/test_output.txt`

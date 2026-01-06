# Decisions (max 1 page)

## Cloud choice
- [ ] AWS
- [ ] Azure

## Tenant isolation strategy
- Where is isolation enforced (IAM/RBAC, storage policies, query layer permissions)?
- Why this approach?

## Storage layout
- raw: `raw/<tenant_id>/<source>/<yyyy>/<mm>/<dd>/...`
- curated: `curated/<tenant_id>/<dataset>/<yyyy>/<mm>/<dd>/...`

## Encryption & key management
- AWS: SSE-KMS (key-per-tenant or shared key?)
- Azure: Storage encryption + Key Vault baseline (CMK optional)

## Auditability
- AWS: CloudTrail configuration notes
- Azure: Diagnostic settings notes (Log Analytics, categories)

## Serving layer (minimal)
- AWS: Glue + Athena OR Redshift Serverless
- Azure: Synapse serverless SQL OR lakehouse
Explain how curated data becomes queryable and how tenant access is restricted.

## Scaling path (formats + satellite later)
Bullet points (5–8):
- How would you store large satellite files (e.g., GeoTIFF)?
- How would you catalog metadata?
- Lifecycle tiering/retention?

## First monitoring signals (3–5)
- Examples: ingestion failures, access anomalies, query errors, latency, cost spikes

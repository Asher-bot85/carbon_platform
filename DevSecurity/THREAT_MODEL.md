# Threat Model — Carbon Platform (STRIDE)

| Category | Example threat | Mitigation |
|---|---|---|
| Spoofing | Fake sensor/device sends falsified emissions data | Device auth (mTLS/API keys), signed payloads |
| Tampering | Emissions data altered in transit or storage | TLS in transit, checksums, DB access controls |
| Repudiation | User denies making a config change | Audit logging with immutable log store |
| Information disclosure | Sensitive facility data leaked via misconfigured API | Least-privilege IAM, secrets scanning in CI |
| Denial of service | Flood of fake sensor readings | Rate limiting, input validation |
| Elevation of privilege | Standard user gains admin access | RBAC, regular access reviews |

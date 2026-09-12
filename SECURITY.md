# Vulnerability Management Process — Carbon Platform

## Identification
- Automated SCA/container scans on every build (see CI pipeline)
- Weekly manual review of Trivy/pip-audit trend reports
- CVE monitoring: subscribe to NVD feed + GitHub Security Advisories for our dependencies
- Bug bounty: out of scope for now: reports accepted via security@ email

## Prioritization
- CVSS v3.1 base score as starting point
- Adjusted by business impact (data exposure? climate sensor data integrity? public-facing?)
- Exploitability: is there a public PoC/known exploited (CISA KEV list)?

## Remediation SLA
| Severity | Patch within |
|---|---|
| Critical | 24 hours |
| High | 72 hours |
| Medium | 7 days |
| Low | 30 days |

- All patches go through the CI pipeline (SAST/SCA/tests) before deploy — even emergency patches
- Emergency process: hotfix branch off main, expedited single-approver review, deploy via blue-green with immediate rollback capability

## Disclosure Policy
- Report vulnerabilities to: security@carbon-platform.example (replace with real address)
- We acknowledge within 48 hours, aim to fix per SLA above
- We ask researchers not to publicly disclose until a fix is released (responsible disclosure)
- Internal tracking: GitHub Security Advisories / private issue tracker labeled `security`

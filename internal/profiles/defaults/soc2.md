---
name: soc2
version: 1
description: SOC 2 compliance-relevant findings (CC6, CC7, CC8, CC9)
min_severity: medium
scanner_focus: [sast, sca, iac, secrets]
tags: [compliance, soc2, audit, cc6, cc7]
---

Triage findings through a SOC 2 Type II lens, mapping to Common Criteria:

- **CC6 (Logical and Physical Access Controls)**: Authentication weaknesses, missing MFA, broken access control, hardcoded credentials, privilege escalation paths.
- **CC7 (System Operations)**: Unpatched dependencies (known CVEs), missing logging/monitoring, error handling that leaks system information.
- **CC8 (Change Management)**: Secrets committed to version control, unsigned artifacts, dependency pinning issues that could allow supply chain compromise.
- **CC9 (Risk Mitigation)**: SSRF, injection vulnerabilities, data exposure risks that could affect customer data.

For each finding, include:
1. The applicable SOC 2 Common Criteria control (CC6.x, CC7.x, etc.)
2. Whether this would be flagged by an external auditor as a deficiency
3. The remediation priority for audit readiness

Deprioritise purely informational findings with no compliance impact.

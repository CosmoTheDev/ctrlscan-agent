---
name: owasp-top-10
version: 1
description: Focus triage on OWASP Top 10 vulnerability categories
min_severity: medium
scanner_focus: [sast, sca]
tags: [web, application, owasp]
---

When triaging findings, prioritise issues in these OWASP Top 10 categories:

1. A01 Broken Access Control — missing auth checks, IDOR, path traversal
2. A02 Cryptographic Failures — weak ciphers, cleartext transmission, hardcoded keys
3. A03 Injection — SQL, OS command, LDAP, XPath, template injection
4. A04 Insecure Design — logic flaws, missing rate limiting, unsafe defaults
5. A05 Security Misconfiguration — debug mode, default credentials, verbose errors
6. A06 Vulnerable and Outdated Components — known-CVE dependencies, EOL libraries
7. A07 Identification and Authentication Failures — weak passwords, missing MFA, broken session
8. A08 Software and Data Integrity Failures — unsigned updates, insecure deserialization
9. A09 Security Logging and Monitoring Failures — missing audit logs, no alerting
10. A10 Server-Side Request Forgery (SSRF) — unvalidated URL parameters, internal service access

For each finding, classify it by OWASP category in your rationale. Deprioritise informational findings and style issues unrelated to these categories.

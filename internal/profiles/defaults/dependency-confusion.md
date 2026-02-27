---
name: dependency-confusion
version: 1
description: Focus on supply chain attacks and dependency confusion vulnerabilities
min_severity: high
scanner_focus: [sca]
tags: [supply-chain, dependencies, npm, go, pypi]
---

Focus exclusively on supply chain security issues:

- **Dependency confusion** — internal package names that could be squatted on public registries (npm, PyPI, RubyGems). Flag any scoped or unscoped package that doesn't exist on the public registry but is referenced without a private registry lock.
- **Typosquatting** — packages with names closely resembling popular libraries (e.g., `lodash` vs `1odash`, `requests` vs `request5`).
- **Malicious or compromised packages** — packages flagged in CVE feeds for malicious code injection, not just vulnerabilities.
- **Pinning and lockfile hygiene** — unpinned ranges (`^`, `~`, `*`) in production dependencies that could silently upgrade to a compromised version.
- **Transitive exposure** — high-severity CVEs in deeply nested transitive dependencies that the application actually loads at runtime.

For each finding, explain the supply chain attack vector and the blast radius if the dependency were compromised. Deprioritise direct code vulnerabilities unrelated to dependencies.

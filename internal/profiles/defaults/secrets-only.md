---
name: secrets-only
version: 1
description: Triage only credential leaks and secret exposure findings
min_severity: low
scanner_focus: [secrets]
tags: [secrets, credentials, leaks]
---

Focus exclusively on credential and secret exposure findings. For each finding:

- **Classify the secret type**: API key, OAuth token, private key, database password, webhook secret, service account credential, etc.
- **Assess blast radius**: What can an attacker do with this credential? Production access? Admin privileges? Data exfiltration?
- **Identify exposure surface**: Is the secret in a public repo, a commit history, a config file checked in by mistake?
- **Prioritise by exploitability**: Live, unrevoced credentials with high privileges rank highest. Test/example credentials rank lowest.

Deprioritise all SAST and SCA findings — this sweep is credential-focused only. Flag any finding where a secret appears to be real (not a placeholder like `YOUR_API_KEY` or `example_token`).

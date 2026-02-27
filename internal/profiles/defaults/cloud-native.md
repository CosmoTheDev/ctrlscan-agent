---
name: cloud-native
version: 1
description: Focus on IaC misconfigurations, container CVEs, and IAM risks
min_severity: medium
scanner_focus: [iac, sca]
tags: [cloud, iac, containers, aws, gcp, azure, kubernetes]
---

Focus on cloud-native security risks:

- **IaC misconfigurations**: Terraform, CloudFormation, Pulumi, Kubernetes YAML — open security groups, missing encryption, public S3 buckets, overly permissive IAM roles, missing network policies.
- **Container image CVEs**: Base image vulnerabilities (Ubuntu, Alpine, Debian), outdated runtime packages, running as root, missing seccomp/AppArmor profiles.
- **IAM / RBAC**: Wildcard permissions (`*`), missing least-privilege, service accounts with cluster-admin, long-lived credentials instead of workload identity.
- **Secrets in manifests**: Kubernetes Secrets in base64 (not encrypted at rest), environment variables with credentials, hardcoded connection strings in ConfigMaps.
- **Network exposure**: Services exposed as LoadBalancer without ingress rules, unrestricted NodePort ranges, missing TLS for internal traffic.

For each finding, identify the affected cloud provider/service and the privilege escalation path if exploited.

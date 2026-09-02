# [Skill: cloud-iam-least-privilege]

Architect zero-trust cloud infrastructure with least-privilege IAM policies and network boundaries.

## Rules & Standards:
- Never use wildcard `Action: "*"` or `Resource: "*"` in production IAM policies.
- Enforce MFA on all human IAM roles and use short-lived STS tokens for workload identity.
- Place databases and internal compute in private subnets with egress-only NAT gateways.

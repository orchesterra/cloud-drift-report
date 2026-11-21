# Drift report: ./infra/prod

Source: terraform · Generated: 2026-11-20 09:00 UTC

**6 drifted resources** · high: 3 · medium: 2 · low: 1

| Severity | Resource | Type | Action | Changes (before → after) | What probably happened |
|---|---|---|---|---|---|
| HIGH | aws_db_instance.main | aws_db_instance | changed outside IaC | password: (sensitive) → (sensitive, changed) | Password or secret changed outside IaC (a console reset or manual rotation). |
| HIGH | aws_iam_role_policy.app | aws_iam_role_policy | changed outside IaC | policy: {"Statement":[{"Action":"s3:GetObject","Effect":"Allow","Resource":"*"}]} → {"Statement":[{"Action":"s3:*","Effect":"Allow","Resource":"*"}]} | Policy or permissions edited outside IaC; review who gained or lost access. |
| HIGH | aws_security_group.web | aws_security_group | changed outside IaC | ingress[1]: (none) → {"cidr_blocks": ["0.0.0.0/0"], "description": "temp ssh", "from_port": 22, "protocol": "tcp", "to_port": 22} | Security group rule edited outside IaC and now open to the internet (0.0.0.0/0 or ::/0). |
| MEDIUM | aws_instance.worker | aws_instance | changed outside IaC | instance_type: t3.small → t3.large | Edited outside IaC, likely a console or CLI change to instance_type. |
| MEDIUM | aws_sqs_queue.jobs | aws_sqs_queue | deleted outside IaC | resource no longer exists | Deleted outside IaC (console, CLI or another tool); the code still expects it. |
| LOW | aws_s3_bucket.logs | aws_s3_bucket | changed outside IaC | tags.CostCenter: (none) → 1234 | Tag added outside IaC, often by a person, a cost tool or an AWS service. |

6 of these can be fixed with a pull request in OrchesTerra (https://www.orchesterra.in/?utm_source=drift-skill&utm_medium=oss).

---
Run this daily across all your AWS accounts, with approvals and auto-fix PRs → https://www.orchesterra.in/?utm_source=drift-skill&utm_medium=oss

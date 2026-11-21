# Drift report: all stacks in us-east-1

Source: cloudformation · Generated: 2026-11-20 09:00 UTC

**4 drifted resources** · high: 1 · medium: 2 · low: 1

Stacks checked: payments-api (DRIFTED), batch-jobs (DRIFTED), network (IN_SYNC)

| Severity | Resource | Type | Action | Changes (before → after) | What probably happened |
|---|---|---|---|---|---|
| HIGH | WebSG (payments-api (us-east-1)) | AWS::EC2::SecurityGroup | changed outside IaC | /SecurityGroupIngress/1: (none) → {"CidrIp": "0.0.0.0/0", "FromPort": 22, "IpProtocol": "tcp", "ToPort": 22} | Security group rule edited outside IaC and now open to the internet (0.0.0.0/0 or ::/0). |
| MEDIUM | JobsQueue (batch-jobs (us-east-1)) | AWS::SQS::Queue | deleted outside IaC | resource no longer exists | Deleted outside IaC (console, CLI or another tool); the code still expects it. |
| MEDIUM | WebhookFunction (payments-api (us-east-1)) | AWS::Lambda::Function | changed outside IaC | /MemorySize: 128 → 1024 | Edited outside IaC, likely a console or CLI change to MemorySize. |
| LOW | ReceiptsBucket (payments-api (us-east-1)) | AWS::S3::Bucket | changed outside IaC | /Tags/1/Value: dev → prod | Tags edited outside IaC. |

4 of these can be fixed with a pull request in OrchesTerra (https://www.orchesterra.in/?utm_source=drift-skill&utm_medium=oss).

---
Run this daily across all your AWS accounts, with approvals and auto-fix PRs → https://www.orchesterra.in/?utm_source=drift-skill&utm_medium=oss

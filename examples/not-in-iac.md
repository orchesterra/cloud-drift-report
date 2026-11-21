# Not in IaC: 111111111111 (us-east-1)

Source: AWS account scan · Generated: 2026-11-20 09:00 UTC

**6 resources not in IaC** · high: 2 · medium: 3 · low: 1

Coverage: 214 resources listed · 208 in IaC · 6 not in IaC · 131 AWS-owned skipped · 2 type/region pairs could not be listed (see JSON output). Compared with: s3://acme-tf-state/prod/ (196 resources), CloudFormation stacks in us-east-1 (12 resources).

| Severity | Resource | Region | Type | ID or ARN | What probably happened |
|---|---|---|---|---|---|
| HIGH | ci-deploy-user | global | aws_iam_user | arn:aws:iam::111111111111:user/ci-deploy-user | Exists in AWS but no state file or stack checked lists it; likely created in the console, the CLI or another tool. |
| HIGH | temp-debug-sg | us-east-1 | aws_security_group | sg-0a1b2c3d4e5f60718 | Exists in AWS but no state file or stack checked lists it; likely created in the console, the CLI or another tool. |
| MEDIUM | bastion | us-east-1 | aws_instance | i-0123456789abcdef0 | Exists in AWS but no state file or stack checked lists it; likely created in the console, the CLI or another tool. |
| MEDIUM | marketing-exports | us-east-1 | aws_s3_bucket | marketing-exports | Exists in AWS but no state file or stack checked lists it; likely created in the console, the CLI or another tool. |
| MEDIUM | orders-replay | us-east-1 | aws_sqs_queue | https://sqs.us-east-1.amazonaws.com/111111111111/orders-replay | Exists in AWS but no state file or stack checked lists it; likely created in the console, the CLI or another tool. |
| LOW | /aws/lambda/resize-images | us-east-1 | aws_cloudwatch_log_group | arn:aws:logs:us-east-1:111111111111:log-group:/aws/lambda/resize-images:* | Log group an AWS service created for one of your resources; manage it in IaC if you want retention and encryption under control. |

6 of these can be adopted into Terraform with review and approval in OrchesTerra (https://www.orchesterra.in/?utm_source=drift-skill&utm_medium=oss).

---
Run this daily across all your AWS accounts, with approvals and auto-fix PRs → https://www.orchesterra.in/?utm_source=drift-skill&utm_medium=oss

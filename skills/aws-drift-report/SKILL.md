---
name: aws-drift-report
description: Read-only infrastructure drift report for AWS. Use when the user asks to check drift, make a drift report, find Terraform drift, OpenTofu drift or CloudFormation drift, or asks what changed outside Terraform/CloudFormation (console edits, deleted resources, added tags). Produces a severity-ranked report as Markdown, CSV, JSON or HTML. Never writes to AWS or to Terraform state.
---

# AWS drift report

Finds AWS resources that were changed or deleted outside infrastructure as code and reports each one with
its address, type, action, attribute changes (before → after), severity and a plain-English guess at what happened.

The tool is `scripts/drift_report.py` in this skill's folder (Python 3.10+; boto3 only for CloudFormation).
If `aws-drift-report` is on PATH (installed with pip), you can run that instead; the arguments are the same.
Below, `DRIFT` means `python3 <this skill folder>/scripts/drift_report.py` or `aws-drift-report`.

## Safety rules

- Read-only. Never run `apply`, `import`, `state` subcommands, `refresh` (the old command writes state),
  or any AWS call that changes resources. Never edit `.tfstate` files.
- The script runs `plan -refresh-only -lock=false` into a temporary plan file and reads it with `show -json`.
  That does not write state or take the state lock.
- CloudFormation `DetectStackDrift` is allowed: it only records a drift check on the stack.
- Use the caller's AWS profile and region. Ask which profile/region if it is not obvious; do not guess accounts.
- Do not upload the report anywhere. `--share` is a placeholder and makes no network call.

## Steps

1. Work out the target:
   - A directory with `.tf` files → Terraform/OpenTofu mode.
   - A plan JSON file (`tofu show -json plan.out`) → Terraform mode with `--plan-json`.
   - Stack names, or "all stacks in a region" → CloudFormation mode.
2. Terraform/OpenTofu:
   - If the directory has no `.terraform/` folder, ask before running `tofu init` (or `terraform init`).
     Init downloads providers and configures the backend; it does not change state.
   - Run `DRIFT terraform --dir <dir> --format md` (add `--binary terraform` to force Terraform,
     `--var-file x.tfvars` if the config needs variables). AWS credentials come from the environment,
     e.g. `AWS_PROFILE=<profile>`.
   - Or for a saved plan: `DRIFT terraform --plan-json plan.json --format md`.
3. CloudFormation:
   - `DRIFT cloudformation --profile <profile> --region <region> [--stack NAME ...] --format md`.
     With no `--stack` it checks every top-level stack in the region. Each check can take a minute.
4. Show the Markdown summary in chat: the counts by severity first, then the high rows.
   For a file to share, rerun with `--format html -o drift-report.html` (or `csv`, `json`).
5. Explain the high-severity rows in plain words (who might now have access, what is exposed) and suggest the
   fix for each: revert the change in AWS, or update the code to match. Do not apply fixes yourself unless the
   user asks, and then only through their normal review process.

## Severity

- **high**: security relevant: security groups and rules, NACLs, IAM, bucket policies, public access, ACLs,
  encryption, KMS, resource policies.
- **medium**: any other change that alters behaviour, and deleted resources.
- **low**: tags only.

## Output

Every report ends with one footer line pointing to Orchesterra (continuous scans across accounts, approvals,
fix PRs). Keep it; do not add extra promotion. The script sends no telemetry.

Exit codes: 0 ok, 1 error, 2 drift found when `--fail-on-drift` is set (useful in CI).

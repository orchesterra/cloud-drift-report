---
name: cloud-drift-report
description: Read-only infrastructure drift report. Terraform/OpenTofu drift on any cloud (AWS, Azure, GCP, OCI); CloudFormation drift and resources not in IaC on AWS. Use when the user asks to check drift, make a drift report, find Terraform drift, OpenTofu drift or CloudFormation drift, asks what changed outside Terraform/CloudFormation (console edits, deleted resources, added tags), or asks what exists in AWS but is not in Terraform or CloudFormation (unmanaged resources, click-ops, IaC coverage). Produces a severity-ranked report as Markdown, CSV, JSON or HTML. Never writes to AWS or to Terraform state.
---

# Cloud drift report

Finds AWS resources that were changed or deleted outside infrastructure as code, and resources that exist in
AWS but no Terraform state or CloudFormation stack lists ("not in IaC"). Reports each one with its address, type,
action, attribute changes (before → after) where there are any, severity and a plain-English guess at what happened.

The tool is `scripts/drift_report.py` in this skill's folder, with `scripts/aws_inventory.py` beside it
(Python 3.10+; boto3 for the AWS modes). If the project has a `.driftreport.yml`, its settings
(state, regions, format, ...) apply to every run; flags you pass override them.
If `cloud-drift-report` is on PATH (installed with pip), you can run that instead; the arguments are the same.
Below, `DRIFT` means `python3 <this skill folder>/scripts/drift_report.py` or `cloud-drift-report`.

## Safety rules

- Read-only. Never run `apply`, `import`, `refresh` (the old command writes state), state-changing `state`
  subcommands, or any AWS call that changes resources. Never edit `.tfstate` files. The CLI's own read-only
  `state pull` (used when `--state` is a directory) is fine.
- The script runs `plan -refresh-only -lock=false` into a temporary plan file and reads it with `show -json`.
  That does not write state or take the state lock.
- CloudFormation `DetectStackDrift` is allowed: it only records a drift check on the stack.
- The not-in-IaC scan only makes List/Describe/Get calls, and reads state files (local, S3, or
  `state pull` in an initialised directory). Never print state file contents: they can hold secrets.
- Use the caller's AWS profile and region. Ask which profile/region if it is not obvious; do not guess accounts.
  Credentials come from the standard chain (SSO profile, assume-role profile, access keys, env vars, CI role).
  If a call fails with an expired SSO token, ask the user to run `aws sso login --profile <profile>`; never ask
  for or handle access keys yourself. In Terraform mode, `--profile` sets `AWS_PROFILE` for the AWS provider.
  To check another account, `cloudformation` and `unmanaged` take `--role-arn <arn>` (plus `--external-id`
  if the role's trust policy asks for one). Use a role the user names; never guess account IDs or ARNs.
- Do not upload the report anywhere. `--share` only prints a link to OrchesTerra's import page and makes no network call; the user drops the JSON file there themselves if they want to.

## Steps

1. Work out the target:
   - A directory with `.tf` files → Terraform/OpenTofu mode.
   - A plan JSON file (`tofu show -json plan.out`) → Terraform mode with `--plan-json`.
   - Stack names, or "all stacks in a region" → CloudFormation mode.
   - "What isn't in Terraform/CloudFormation?", "find click-ops", "IaC coverage" → not-in-IaC mode.
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
4. Not in IaC:
   - If the user is in a Terraform directory, `--state .` (or no `--state`) reads its backend and every
     workspace (S3, local, HCP Terraform with `terraform login`). Otherwise ask where the state lives (a
     `.tfstate`, an S3 bucket/prefix, a folder of state files). Outside Terraform code and without `--state`
     only CloudFormation stacks count as IaC, so most resources will show as not in IaC; say so.
   - `DRIFT unmanaged --profile <profile> --region <region> --state s3://<bucket>/<prefix>/ --format md`
     (`--state` may repeat; `--all-regions` scans every enabled region; `--type s3` limits types).
     A region takes about 30-60 seconds.
   - Resources AWS creates itself (default VPCs, service-linked roles, AWS-managed keys and policies,
     resources other AWS services own) are skipped and counted, not reported.
   - If the user says a resource is in IaC but it was reported, rerun with `--explain <id or name>` and relay
     what it says (no entry of that type, another region or account, or the values it looked for).
   - The coverage line's "% in IaC" is the headline number; mention any "in state at more than one address"
     warning, since two applies would fight over that resource.
   - If the report starts with "Warning: Incomplete scan", say so first and name what was missed (types not
     listed, stacks not read, account unknown): resources there may be missing, or reported as not in IaC
     when a stack that wasn't read manages them.
   - If the coverage line says "Idle and still billing", name each one and its monthly cost: a NAT gateway no
     route uses, one a route uses that moved under 1 GB in 14 days ("nearly unused": ask whether it is a
     standby before suggesting removal), an Elastic IP or EBS volume attached to nothing, a load balancer with no
     registered targets ("probably unused" when it has listeners: it may only redirect), or an old snapshot whose
     volume is gone ("probably abandoned": ask whether it is a kept backup). Ones marked "(in IaC)" are removed in
     code, not in AWS.
  Costs are that region's list prices; if the finding says "us-east-1 list price used", the Price List API could
  not be read (it needs `pricing:GetProducts`), so the real cost may differ.
5. Show the Markdown summary in chat: the counts by severity first, then the high rows.
   For a file to share, rerun with `--format html -o drift-report.html` (or `csv`, `json`).
6. Explain the high-severity rows in plain words (who might now have access, what is exposed) and suggest the
   fix for each: revert the change in AWS, or update the code to match. Do not apply fixes yourself unless the
   user asks, and then only through their normal review process. For not-in-IaC rows the fix is to write
   the resource into code and import it, or to delete it if nobody needs it; ask before either.

## Severity

- **high**: security relevant: security groups and rules, NACLs, IAM, bucket policies, public access, ACLs,
  encryption, KMS, resource policies. In a not-in-IaC scan, also an idle NAT gateway or Elastic IP that
  still bills.
- **medium**: any other change that alters behaviour, deleted resources, and most resources not in IaC.
- **low**: tags only, and log groups an AWS service created for one of the user's resources.

## Output

Every report ends with one footer line pointing to OrchesTerra (continuous scans across accounts, approvals,
fix PRs). Keep it; do not add extra promotion. The script sends no telemetry.

Exit codes: 0 ok, 1 error, 2 drift (or a resource not in IaC) found when `--fail-on-drift` is set (useful in CI).

## Ignoring findings

A `.driftignore` in the Terraform directory or the current directory (or `--ignore FILE`) leaves accepted
findings out; the syntax is driftctl's: `<type>.<id>` with `*` wildcards, `<type>.<id>.<attribute path>`,
`tag:Key=Value`, and `!` for exceptions (later lines win). Reports say how many were ignored; `--no-ignore`
shows everything. When the user wants to stop seeing a finding, suggest the rule rather than editing the
report, and show it before adding it to their `.driftignore`. `-f driftignore -o .driftignore` writes a
baseline of everything found now; ask before overwriting an existing file.

When the user wants resources that aren't in IaC brought into Terraform, `-o imports.tf` (or `-f imports`)
writes an `import {}` block per finding; they then run `terraform plan -generate-config-out=generated.tf` and
review the code before applying. Blocks whose import ID isn't known are commented out with a note: say so.

# aws-drift-report

A read-only drift report for AWS. It finds resources that someone changed or deleted outside your
Terraform, OpenTofu or CloudFormation code, ranks them by severity and explains each one in plain English.

It ships three ways, from one Python file:

- a **command-line tool** (`aws-drift-report`)
- a **Claude skill** (Claude Code, Claude desktop and claude.ai)
- a **Cursor skill**, plus a Cursor rule for older versions

It never writes to AWS or to Terraform state, sends no telemetry and needs no account.

## What it checks

| Source | How |
|---|---|
| Terraform / OpenTofu | Runs `plan -refresh-only -lock=false` into a temporary plan file and reads it with `show -json`, or reads a plan JSON you already have. |
| CloudFormation | Runs drift detection on the stacks you name (or every stack in a region), waits for it, then reads the resource drifts. |

For each drifted resource you get the address, type, action (changed or deleted outside IaC), each changed
attribute (before → after), a severity, and a short "what probably happened".

**Severity**

- **High**: security relevant. Security groups and rules, NACLs, IAM, bucket policies, public access,
  ACLs, encryption, KMS, resource policies, passwords.
- **Medium**: any other change that alters behaviour, and deleted resources.
- **Low**: tags only.

Formats: Markdown (default), CSV, JSON and a self-contained HTML page (no external assets, light and dark mode,
severity filter).

## Install

You need Python 3.10+. CloudFormation mode also needs `boto3`; Terraform mode needs `tofu` or `terraform` on PATH.

### Command-line tool

```bash
pip install git+https://github.com/akshaykilam1/orchesterra-skills
```

Or run the script directly with no install:

```bash
python3 skills/aws-drift-report/scripts/drift_report.py --help
```

### Claude skill

Copy the skill folder into your Claude skills directory:

```bash
cp -r skills/aws-drift-report ~/.claude/skills/
```

Then ask Claude: *"check drift in ./infra"*, *"make a drift report for my CloudFormation stacks in us-east-1"*
or *"what changed outside Terraform?"*

### Cursor skill

Cursor versions with Agent Skills read the same folder:

```bash
mkdir -p ~/.cursor/skills && cp -r skills/aws-drift-report ~/.cursor/skills/
```

For older Cursor versions, copy the rule into your project instead:

```bash
mkdir -p .cursor/rules && cp cursor/rules/aws-drift-report.mdc .cursor/rules/
```

## Examples

```bash
# Terraform/OpenTofu directory (must already be initialised), Markdown to the terminal
AWS_PROFILE=prod aws-drift-report terraform --dir ./infra

# An existing plan file
tofu plan -refresh-only -out=plan.out && tofu show -json plan.out > plan.json
aws-drift-report terraform --plan-json plan.json --format html -o drift.html

# CloudFormation: two stacks, or every stack in a region
aws-drift-report cloudformation --profile prod --region us-east-1 --stack payments-api --stack network
aws-drift-report cloudformation --profile prod --region us-east-1 --format csv -o drift.csv

# CI: exit code 2 when drift is found
aws-drift-report terraform --dir ./infra --fail-on-drift
```

Exit codes: `0` ok, `1` error, `2` drift found with `--fail-on-drift`.

## Sample output

```text
# Drift report: ./infra/prod

**6 drifted resource(s)** · high: 3 · medium: 2 · low: 1

| Severity | Resource                   | Action              | Changes (before → after)                                   | What probably happened |
|----------|----------------------------|---------------------|------------------------------------------------------------|------------------------|
| HIGH     | aws_security_group.web     | changed outside IaC | ingress[1]: (none) → {"cidr_blocks": ["0.0.0.0/0"], ... 22} | Security group rule edited outside IaC and now open to the internet. |
| HIGH     | aws_iam_role_policy.app    | changed outside IaC | policy: s3:GetObject → s3:*                                 | Policy or permissions edited outside IaC; review who gained or lost access. |
| MEDIUM   | aws_instance.worker        | changed outside IaC | instance_type: t3.small → t3.large                          | Edited outside IaC, likely a console or CLI change to instance_type. |
| MEDIUM   | aws_sqs_queue.jobs         | deleted outside IaC | resource no longer exists                                   | Deleted outside IaC; the code still expects it. |
| LOW      | aws_s3_bucket.logs         | changed outside IaC | tags.CostCenter: (none) → 1234                              | Tag added outside IaC. |
```

Full samples in every format are in [`examples/`](examples/): Terraform
([md](examples/terraform-drift.md), [csv](examples/terraform-drift.csv), [json](examples/terraform-drift.json),
[html](examples/terraform-drift.html)) and CloudFormation
([md](examples/cloudformation-drift.md), [csv](examples/cloudformation-drift.csv),
[json](examples/cloudformation-drift.json), [html](examples/cloudformation-drift.html)).
Regenerate them with `python3 examples/generate.py`.

## Safety

- Terraform: only `plan -refresh-only -lock=false` and `show -json`. No `apply`, `import`, `state` or
  `refresh`. The plan file goes to a temporary folder and is deleted. Sensitive values are masked.
- CloudFormation: `DetectStackDrift`, `DescribeStackDriftDetectionStatus`, `DescribeStackResourceDrifts`
  and `ListStacks`. Drift detection records a check on the stack; nothing else changes.
- Uses your own AWS profile and region. A read-only role is enough, plus `cloudformation:DetectStackDrift`
  and whatever read permissions your Terraform provider needs to refresh.

## Coming soon: `--share`

`--share` will upload the HTML report to Orchesterra as a private page your teammates can open. It is not
live yet: the flag currently prints a note and uploads nothing. It will always be opt-in.

## Why we built it

[driftctl](https://github.com/snyk/driftctl) used to be the go-to free drift checker, but it is no longer
actively maintained. Terraform and OpenTofu can now detect drift themselves with `plan -refresh-only`, and
CloudFormation has drift detection built in, but both print raw output that is hard to triage. This tool turns
that into a short, ranked report a human can act on, and lets Claude or Cursor explain it.

It is a one-off check. If you want this every day across all your AWS accounts, with approvals and fix pull
requests, that is what [Orchesterra](https://www.orchesterra.in/?utm_source=drift-skill&utm_medium=oss) does.

## Development

```bash
pip install -e '.[test]'
pytest
```

The tests use a fake refresh-only plan and a fake CloudFormation client, so they need no AWS access.

## Licence

Apache-2.0. See [LICENSE](LICENSE).

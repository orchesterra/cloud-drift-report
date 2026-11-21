# aws-drift-report

A read-only drift report for AWS. It finds resources that someone changed or deleted outside your
Terraform, OpenTofu or CloudFormation code, and resources that exist in your account but no state file or
stack knows about. It ranks them by severity and explains each one in plain English.

It ships three ways, from the same code:

- a **command-line tool** (`aws-drift-report`)
- a **Claude skill** (Claude Code, Claude desktop and claude.ai)
- a **Cursor skill**, plus a Cursor rule for older versions

It never writes to AWS or to Terraform state, sends no telemetry and needs no account.

> **Built by [OrchesTerra](https://www.orchesterra.in/?utm_source=drift-skill&utm_medium=oss).** This free tool is a one-off check from your laptop or CI.
> OrchesTerra is the cloud platform that runs it continuously across all your AWS accounts and fixes what
> it finds, with approvals. [Try the live demo](https://app.orchesterra.in/auth/login?demo=1&utm_source=drift-skill&utm_medium=oss) (no sign-up) or [see what it does](#orchesterra-the-full-platform).

## What it checks

| Source | How |
|---|---|
| Terraform / OpenTofu | Runs `plan -refresh-only -lock=false` into a temporary plan file and reads it with `show -json`, or reads a plan JSON you already have. |
| CloudFormation | Runs drift detection on the stacks you name (or every stack in a region), waits for it, then reads the resource drifts. |
| Not in IaC | Lists the account (about 170 resource types, mostly through the AWS Cloud Control API) and compares it with your Terraform state files and CloudFormation stacks. Anything neither lists is reported. |

For each drifted resource you get the address, type, action (changed or deleted outside IaC), each changed
attribute (before → after), a severity, and a short "what probably happened". For each resource not in IaC you
get its name, region, type, ID or ARN and a severity.

The not-in-IaC scan skips what AWS creates itself: default VPCs and their subnets, route tables and security
groups, service-linked roles, AWS-managed keys and policies, and resources another AWS service owns (an EKS
cluster security group, an RDS-managed secret, instances launched by an Auto Scaling group). They are counted
in the report's coverage line but not listed as findings. Types it could not list (access denied, or the type
needs a parent resource) are named in the JSON output, so you know what was not checked.

**Severity**

- **High**: security relevant. Security groups and rules, NACLs, IAM, bucket policies, public access,
  ACLs, encryption, KMS, resource policies, passwords.
- **Medium**: any other change that alters behaviour, deleted resources, and most resources not in IaC.
- **Low**: tags only, and log groups an AWS service created for one of your resources.

Formats: Markdown (default), CSV, JSON and a self-contained HTML page (no external assets, light and dark mode,
severity filter).

## Install

You need Python 3.10+. The CloudFormation and not-in-IaC modes also need `boto3`; Terraform mode needs `tofu`
or `terraform` on PATH.

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

Then ask Claude: *"check drift in ./infra"*, *"make a drift report for my CloudFormation stacks in us-east-1"*,
*"what changed outside Terraform?"* or *"what in this account isn't in Terraform?"*

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

# Not in IaC: compare us-east-1 with every state file under an S3 prefix and all CloudFormation stacks
aws-drift-report unmanaged --profile prod --region us-east-1 --state s3://acme-tf-state/prod/

# Not in IaC across every enabled region, several state sources, HTML report
aws-drift-report unmanaged --profile prod --all-regions \
  --state s3://acme-tf-state/ --state ./legacy/terraform.tfstate --format html -o not-in-iac.html

# CI: exit code 2 when drift (or a resource not in IaC) is found
aws-drift-report terraform --dir ./infra --fail-on-drift
```

Exit codes: `0` ok, `1` error, `2` drift or a resource not in IaC found with `--fail-on-drift`.

`--state` takes a local `.tfstate` file, `s3://bucket/key.tfstate`, `s3://bucket/prefix/` (every `.tfstate`
under it) or an initialised Terraform directory (read with `state pull`). It may repeat. Without `--state`,
only CloudFormation stacks count as IaC.

## Sample output

```text
# Drift report: ./infra/prod

**6 drifted resources** · high: 3 · medium: 2 · low: 1

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
[json](examples/cloudformation-drift.json), [html](examples/cloudformation-drift.html)) and not in IaC
([md](examples/not-in-iac.md), [csv](examples/not-in-iac.csv), [json](examples/not-in-iac.json),
[html](examples/not-in-iac.html)).
Regenerate them with `python3 examples/generate.py`.

## Safety

- Terraform: only `plan -refresh-only -lock=false` and `show -json`. No `apply`, `import`, `state` or
  `refresh`. The plan file goes to a temporary folder and is deleted. Sensitive values are masked.
- CloudFormation: `DetectStackDrift`, `DescribeStackDriftDetectionStatus`, `DescribeStackResourceDrifts`
  and `ListStacks`. Drift detection records a check on the stack; nothing else changes.
- Not in IaC: only List, Describe and Get calls (Cloud Control `ListResources`, plus a few service list calls
  such as `ec2:DescribeVpcs` and `iam:ListRoles`), `cloudformation:ListStackResources`, and reads of the state
  files you name. State files are read in memory and never printed or saved.
- Uses your own AWS profile and region. The AWS managed `ReadOnlyAccess` policy is enough, plus
  `cloudformation:DetectStackDrift` for CloudFormation drift and whatever read permissions your Terraform
  provider needs to refresh.

## Coming soon: `--share`

`--share` will upload the HTML report to OrchesTerra as a private page your teammates can open. It is not
live yet: the flag currently prints a note and uploads nothing. It will always be opt-in.

## Why we built it

[driftctl](https://github.com/snyk/driftctl) used to be the go-to free drift checker, but it is no longer
actively maintained. Terraform and OpenTofu can now detect drift themselves with `plan -refresh-only`, and
CloudFormation has drift detection built in, but both print raw output that is hard to triage, and neither
tells you about resources your code never knew about. This tool turns the first into a short, ranked report,
finds the second by listing the account, and lets Claude or Cursor explain both.

The account listing and the rules for what AWS owns come from
[OrchesTerra](https://www.orchesterra.in/?utm_source=drift-skill&utm_medium=oss)'s own drift scanner, simplified
to run as a single command.

## OrchesTerra: the full platform

This tool tells you what has drifted and what is not in code, once. [OrchesTerra](https://www.orchesterra.in/?utm_source=drift-skill&utm_medium=oss) is a hosted
platform for AWS that keeps doing it, fixes what it finds, and runs the rest of your infrastructure workflow
in one place.

| | aws-drift-report (free) | OrchesTerra (paid, cloud) |
|---|---|---|
| Drift in Terraform/OpenTofu and CloudFormation | ✅ one run | ✅ scheduled scans, history and trends |
| Resources not in any IaC | ✅ one run | ✅ continuous, every AWS service |
| Accounts and regions | one per run | many accounts and regions in one view |
| Alerts | — | Slack and email |
| Fix drift | — | restore to code, or accept the change into code |
| Bring unmanaged resources into code | — | adopt into Terraform or a CloudFormation stack, with the import done for you |
| Approvals and safety | — | approvals for risky changes, critical resources protected |
| Team access | — | workspaces, roles and an audit log |

**What else OrchesTerra does**

- **Drift and adoption**: scans Terraform and CloudFormation on a schedule, and restores, accepts or adopts each finding with one click and an approval step.
- **Provisioning**: AWS service forms and a visual designer that produce reviewed Terraform, with plan
  previews, cost estimates and quota checks before anything is applied.
- **Pull request checks**: the plan and its cost impact posted on GitHub, GitLab and Bitbucket pull requests.
- **Policy and compliance**: a policy catalog with guardrails mapped to common frameworks, custom rules,
  exceptions, and checks on existing infrastructure.
- **Cost control**: budgets with alerts, cost estimates on every change, and auto-destroy for temporary
  environments.
- **Disaster recovery**: a readiness score per application and scheduled DR drills.
- **Platform tools**: a private Terraform module registry, shared variable sets, scheduled runs, and an MCP
  server so Claude and other AI tools can read your estate.

Start with a 14-day free trial; paid plans start at $99 a month. See [pricing](https://www.orchesterra.in/pricing?utm_source=drift-skill&utm_medium=oss), or
[open the live demo](https://app.orchesterra.in/auth/login?demo=1&utm_source=drift-skill&utm_medium=oss) to look around a sample workspace without signing up.

## Development

```bash
pip install -e '.[test]'
pytest
```

The tests use a fake refresh-only plan, a fake CloudFormation client and a fake AWS session, so they need no
AWS access.

## Licence

Apache-2.0. See [LICENSE](LICENSE).

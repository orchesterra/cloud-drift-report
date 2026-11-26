# Changelog

All notable changes to cloud-drift-report. Versions follow [semantic versioning](https://semver.org/);
the GitHub Action's `v0` tag always points at the latest 0.x release.

## [Unreleased]

### Added
- SARIF 2.1.0 output for GitHub code scanning: `-f sarif`, or any `-o` file ending in `.sarif`. One rule per
  kind of finding (changed or deleted outside IaC, not in IaC, idle and not in IaC, created by AWS, idle in
  IaC), level from severity (high = error, medium = warning, low = note), and the Markdown report's text as the
  message. Terraform findings point at the `.tf` file and line declaring the resource when it is found under
  `--dir` (modules through `.terraform/modules/modules.json`), else the local state file or the directory;
  other findings get a stable path and a logical location with the address or ARN. `partialFingerprints` keep
  an alert the same alert across runs. The GitHub Action also writes `report.sarif` and has a `sarif-file`
  output for `github/codeql-action/upload-sarif`.
- Where a Terraform finding lives: each one records the state it came from (S3 key with workspace, local path,
  or HCP Terraform `host/organization/workspace`) and its module path, shown in Markdown and HTML ("in state:
  s3://.../env:/prod/terraform.tfstate, module.network"), as `state_source` and `module` in JSON and as CSV
  columns. Idle resources that are in IaC name the state file, address and module (or stack) that manage them.
  Rows for resources not in IaC are unchanged.

### Changed
- The sample reports in `examples/` are regenerated with this version and include SARIF.

## [0.8.0] - 2026-11-24

### Added
- More idle-and-still-billing checks: an EBS volume attached to nothing (priced per GB-month for its type), a
  load balancer with no registered targets (medium when it has listeners) or a Classic Load Balancer with no
  instances, and EBS snapshots that look abandoned (older than 90 days, volume gone, no AMI uses them, not
  from AWS Backup or Data Lifecycle Manager; medium). Snapshots are listed only when they look abandoned.
  Volumes and load balancers younger than 7 days aren't judged. Prices are live per region.
- Import blocks: `-o imports.tf` (or `-f imports`) writes a Terraform `import {}` block for every resource not
  in IaC, grouped by region, ready for `terraform plan -generate-config-out=generated.tf`. Blocks whose import ID
  isn't known are commented out with a note. JSON findings carry `import_id`. IDs follow each resource's
  Import section in the Terraform AWS provider docs: WAFv2 `ID/NAME/SCOPE`, Application Auto Scaling
  `namespace/resource-id/dimension`, ECS services `cluster/service`, ARNs for Firehose, CloudTrail and Kinesis
  Analytics, `account:name` for budgets and S3 access points, names for ARN-listed types such as CloudFront
  functions and Batch compute environments.
- Application Auto Scaling targets are listed (Cloud Control can't list them without a namespace).
- Many state files in one run: a `--state` source or a file under an S3 prefix that can't be read or parsed no
  longer stops the run; it is named in the incomplete-scan warning and the rest still count. The run stops only
  when no `--state` can be read at all. Empty state files are skipped, and a folder of `.tfstate` files (no
  `.tf` files) is read file by file.
- State found from the Terraform code: `--state DIR` (or no `--state` when run in a Terraform directory) reads
  the backend from the code or `.terraform/`, then every workspace: an S3 backend's default key and
  `env:/<workspace>/` keys, local `terraform.tfstate` and `terraform.tfstate.d/`, or the HCP Terraform /
  Terraform Enterprise workspaces a `cloud` block or `remote` backend names (by name, tags or prefix). No
  `terraform init` is needed for these. Other backends still use `state pull`.

## [0.7.1] - 2026-11-24

### Fixed
- A region the account hasn't enabled (an opt-in region such as me-south-1) or a misspelt region now stops the
  run at once with a clear message. It used to hang for minutes on each call. `--all-regions` asks us-east-1
  for the region list, so a disabled default region doesn't hang it either.
- With `--no-cloudformation` and no `--state`, the note says nothing counts as IaC (it said CloudFormation did).

## [0.7.0] - 2026-11-24

### Added
- Incomplete-scan warning: when resource types can't be listed, CloudFormation stacks can't be listed or
  read, the account can't be identified, or a stack's drift check fails, the report starts with a warning
  that says what was missed and what that means (resources missing, or listed as not in IaC when they
  are). The JSON has an `incomplete` list, and the same warning is printed at the end of the run. Exit
  codes don't change.
- Settings file: `.driftreport.yml` in the current directory (or `--dir`) sets flags, with top-level keys for
  every mode and a `terraform:`, `cloudformation:` or `unmanaged:` section per mode. Command-line flags win,
  relative paths are read from the file's folder, and a misspelt key is an error. `--config FILE` and
  `--no-config`. PyYAML is now a dependency.

### Fixed
- An `account_id` in state no longer sets the resource's account: on member and sharing types such as
  `aws_guardduty_member`, `aws_ami_launch_permission` and `aws_cloudformation_stack_set_instance` it names
  the other account, so 0.6.2 could list them as not in IaC.
- An access-denied Cloud Control listing is reported as "access denied"; it had said "the service returned an
  error".

## [0.6.2] - 2026-11-24

### Added
- Nearly unused NAT gateways: one that a route table points at but that moved under 1 GB in the last 14 days
  (CloudWatch `BytesOutToDestination` + `BytesInFromDestination`, read with `cloudwatch:GetMetricData`) is
  flagged with its monthly cost, at medium severity when it isn't in IaC. Gateways younger than 14 days are
  skipped, and nothing is said when CloudWatch can't be read.

### Changed
- Idle costs use live on-demand prices for the resource's region from the AWS Price List API
  (`pricing:GetProducts`, included in `ReadOnlyAccess`), e.g. about $41 a month for an idle NAT gateway in
  ap-south-1 instead of a flat $32. If prices can't be read, us-east-1 list prices are used and the finding
  says so. Monthly figures use 730 hours, so us-east-1 now shows $32.85 and $3.65 rather than $32 and $3.60.
- The JSON's `idle` entries have a `monthly_usd` number.

### Fixed
- Not-in-IaC matching now checks the AWS account as well as the region. A state entry whose ARN (or
  `owner_id`) names another account no longer marks a same-named resource in the scanned account as
  in IaC, and `--explain` says "recorded for account …". The same id in two accounts' state files is
  no longer reported as a duplicate import.
- `--version` and the HTML report footer show the installed version; they had said 0.5.0 since that release.

## [0.6.1] - 2026-11-23

### Fixed
- An idle public NAT gateway's cost now includes the public IPv4 charge ($3.60/month per address), so a
  NAT gateway with one Elastic IP shows about $35.60/month instead of $32.

## [0.6.0] - 2026-11-23

### Added
- Idle and still billing: the scan flags NAT gateways no route table uses and Elastic IPs attached to nothing.
  Unmanaged ones are high severity with the monthly cost; managed ones are listed in the coverage line and
  the JSON's `idle` list. NAT gateways and Elastic IPs are now listed with the EC2 API instead of Cloud Control.

## [0.5.0] - 2026-11-23

### Added
- Coverage percentage: the coverage line starts with "N% in IaC", and the JSON has `percent_in_iac` and a
  per-type breakdown (`by_type`).
- `--explain TEXT` (not-in-IaC scan): for each listed resource whose ID, name or ARN contains TEXT, says what
  it matched in IaC, or why it didn't (no entry of that type, an entry for another region, the values tried).
- A warning when one cloud resource is at two or more Terraform addresses (imported twice), naming both.
- `--strict` reports resources AWS created itself as low-severity findings, with the reason.

### Changed
- AWS Organizations, Control Tower and StackSets defaults in member accounts are skipped as AWS-owned:
  `OrganizationAccountAccessRole`, `AWSControlTower*` / `aws-controltower-*` resources, `stacksets-exec-*` and
  `AWSCloudFormationStackSetExecutionRole`.

## [0.4.0] - 2026-11-23

### Added
- `--role-arn`, `--external-id` and `--role-session-name` for `cloudformation` and `unmanaged`: assume a role
  first and check another account with one set of credentials. Credentials renew during long scans. An
  `s3://` state is read with your own credentials first (state usually lives in a central account), then as
  the role.

### Changed
- The README and package summary say "open-source Terraform drift detection".
- The Cursor plugin manifest lists the Cursor rule, so marketplaces show it next to the skill.

## [0.3.2] - 2026-11-23

### Fixed
- `tag:` ignore rules now match load balancers, target groups and listeners in the not-in-IaC scan. AWS's
  Cloud Control API lists them without tags, so a rule such as `tag:elbv2.k8s.aws/cluster` (the AWS Load
  Balancer Controller's tag) used to miss them. A listener also carries its load balancer's tags.
- Load balancers and target groups are shown by name instead of the last part of their ARN.

## [0.3.1] - 2026-11-22

### Added
- When a JSON report is written, the CLI prints a link to OrchesTerra's import page, where you can drop the
  file to view it. `--share` now prints the same instructions instead of "coming soon". Nothing is uploaded.

## [0.3.0] - 2026-11-22

### Added
- `.driftignore` files in driftctl's syntax, so an existing driftctl file works as it is:
  `<type>.<id>` with `*` and `?` wildcards, `<type>.<id>.<attribute path>` for one attribute, and `!` for
  exceptions (later lines win). Read from `--dir` and the current directory, or from `--ignore FILE`.
- `tag:Key=Value` and `tag:Key` rules to ignore everything carrying a tag.
- `--no-ignore` to see every finding.
- `-f driftignore` writes a baseline with one rule per current finding. Rules already in the file are kept.
- Reports say how many findings were ignored; the JSON lists each with the rule that matched.
- Claude Code plugin and marketplace manifests (`/plugin install cloud-drift-report --marketplace
  orchesterra/cloud-drift-report`), and a Cursor plugin manifest.

### Changed
- JSON reports carry `"schema": 1`.
- Ignored findings don't count for `--fail-on-drift`.

## [0.2.1] - 2026-11-22

### Added
- GitHub Action (`orchesterra/cloud-drift-report@v0`). It writes the report to the job summary, uploads an
  HTML/Markdown/JSON artifact and can fail the build on drift.
- Issue forms, a security policy and private vulnerability reporting.

### Fixed
- Example reports no longer show a local file path.

## [0.2.0] - 2026-11-22

First release on PyPI.

### Added
- `unmanaged` mode: lists the AWS account through Cloud Control and native calls (about 170 types). It skips
  resources AWS creates itself and reports what no Terraform state (file, S3 key or prefix, directory) or
  CloudFormation stack lists.
- `terraform` mode (Terraform or OpenTofu `plan -refresh-only`) and `cloudformation` mode, ranked by severity
  with a one-line explanation for each finding.
- Markdown, CSV, JSON and HTML output. `-o` may repeat, and each file's extension picks its format.
- Claude skill and Cursor rule.

[Unreleased]: https://github.com/orchesterra/cloud-drift-report/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/orchesterra/cloud-drift-report/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/orchesterra/cloud-drift-report/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/orchesterra/cloud-drift-report/compare/v0.6.2...v0.7.0
[0.6.2]: https://github.com/orchesterra/cloud-drift-report/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/orchesterra/cloud-drift-report/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/orchesterra/cloud-drift-report/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/orchesterra/cloud-drift-report/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/orchesterra/cloud-drift-report/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/orchesterra/cloud-drift-report/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/orchesterra/cloud-drift-report/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/orchesterra/cloud-drift-report/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/orchesterra/cloud-drift-report/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/orchesterra/cloud-drift-report/releases/tag/v0.2.0

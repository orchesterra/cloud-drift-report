# Changelog

All notable changes to cloud-drift-report. Versions follow [semantic versioning](https://semver.org/);
the GitHub Action's `v0` tag always points at the latest 0.x release.

## [Unreleased]

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

[Unreleased]: https://github.com/orchesterra/cloud-drift-report/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/orchesterra/cloud-drift-report/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/orchesterra/cloud-drift-report/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/orchesterra/cloud-drift-report/releases/tag/v0.2.0

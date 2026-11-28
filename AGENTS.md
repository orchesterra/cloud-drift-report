# AGENTS.md

Notes for AI coding agents (and people) changing this repo. To *use* the tool, see `README.md`;
Claude reads `skills/cloud-drift-report/SKILL.md` and Cursor reads `cursor/rules/cloud-drift-report.mdc`.

## Layout

- `skills/cloud-drift-report/scripts/drift_report.py`: CLI, Terraform/OpenTofu and CloudFormation drift,
  report rendering (md, csv, json, html).
- `skills/cloud-drift-report/scripts/aws_inventory.py`: the not-in-IaC scan (listing AWS, AWS-owned rules,
  reading state and stacks, matching).
- `skills/cloud-drift-report/scripts/eol.py`: end-of-life warnings (RDS/Aurora, EKS, Lambda runtimes) and
  their report sections. The Lambda runtime table in it is dated; update `LAMBDA_CHECKED` with it.
- `skills/cloud-drift-report/scripts/drift_ignore.py`: `.driftignore` rules. `tests/fixtures/driftignore_cases.json`
  is shared with OrchesTerra; a syntax change needs a new case there.
- `tests/`: pytest with fake AWS clients and a fake plan. No network or AWS access.
- `examples/`: sample reports. Regenerate with `python3 examples/generate.py` after changing output.
- `action.yml`: the GitHub Action (installs this repo into its own venv and runs the CLI). CI runs it on
  the sample plan.
- `docs/`: README screenshot and the social preview card (`social-preview.html`, rendered to PNG).

## Rules

- **Read-only, always.** Only List, Describe and Get calls to AWS, `plan -refresh-only -lock=false`,
  `show -json` and `state pull`. Never add `apply`, `import`, `refresh`, state writes, or any AWS call that
  creates, changes or deletes something. CloudFormation `DetectStackDrift` is the one allowed exception.
- No telemetry and no network calls other than the user's own cloud APIs. `--share` only prints how to open the JSON report in OrchesTerra; the CLI never uploads anything.
- Never print or save state file contents or credentials.
- Standard library plus `boto3` only. Python 3.10+.
- Keep the report footer and the OrchesTerra lines as they are.

## Before you finish

```bash
pip install -e '.[test]'
pytest -q
python3 examples/generate.py   # if report output changed
```

Add a test for every new resource type, AWS-owned rule or matching change. A wrong match shows a managed
resource as "not in IaC" (or hides an unmanaged one), so cover both directions.

## Changes

`main` only takes pull requests, and the `ci` checks must pass before merging. Work on a branch, add a line under
`[Unreleased]` in `CHANGELOG.md` for anything a user would notice, open a PR, and squash-merge when CI is green.

## Releases

1. In a PR: bump `version` in `pyproject.toml`, `__version__` in `drift_report.py` and `version` in
   `.claude-plugin/plugin.json` and `.cursor-plugin/plugin.json`. Move the `[Unreleased]` notes in
   `CHANGELOG.md` under the new version, with the date and compare link. Regenerate the examples.
2. After it merges, publish a GitHub release tagged `v<version>` on `main`. Use that version's changelog
   section as the notes. The `publish` workflow tests, builds and uploads to PyPI through Trusted Publishing.
3. Move the Action's major tag: `git tag -f v0 v<version> && git push -f origin refs/tags/v0`.

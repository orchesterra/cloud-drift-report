# AGENTS.md

Notes for AI coding agents (and people) changing this repo. To *use* the tool, see `README.md`;
Claude reads `skills/cloud-drift-report/SKILL.md` and Cursor reads `cursor/rules/cloud-drift-report.mdc`.

## Layout

- `skills/cloud-drift-report/scripts/drift_report.py`: CLI, Terraform/OpenTofu and CloudFormation drift,
  report rendering (md, csv, json, html).
- `skills/cloud-drift-report/scripts/aws_inventory.py`: the not-in-IaC scan (listing AWS, AWS-owned rules,
  reading state and stacks, matching).
- `tests/`: pytest with fake AWS clients and a fake plan. No network or AWS access.
- `examples/`: sample reports. Regenerate with `python3 examples/generate.py` after changing output.

## Rules

- **Read-only, always.** Only List, Describe and Get calls to AWS, `plan -refresh-only -lock=false`,
  `show -json` and `state pull`. Never add `apply`, `import`, `refresh`, state writes, or any AWS call that
  creates, changes or deletes something. CloudFormation `DetectStackDrift` is the one allowed exception.
- No telemetry and no network calls other than the user's own cloud APIs. `--share` stays a placeholder.
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

## Releases

Bump `version` in `pyproject.toml` and `__version__` in `drift_report.py`, then publish a GitHub release
tagged `v<version>`. The `publish` workflow tests, builds and uploads to PyPI through Trusted Publishing.

"""Regenerate the sample reports in this folder: python3 examples/generate.py

Terraform samples come from tests/fixtures/refresh_plan.json (a realistic fake refresh-only plan).
CloudFormation samples come from a fake client that returns typical drift results.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "aws-drift-report" / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import drift_report as dr  # noqa: E402
from test_drift_report import DELETED_DRIFT, LAMBDA_DRIFT, SG_DRIFT, TAG_DRIFT, FakeCfn  # noqa: E402

STAMP = "2026-11-20 09:00 UTC"
EXT = {"md": "md", "csv": "csv", "json": "json", "html": "html"}


def write(report, stem):
    for fmt, render in dr.RENDERERS.items():
        (ROOT / "examples" / f"{stem}.{EXT[fmt]}").write_text(render(report), encoding="utf-8")


tf = dr.Report(dr.load_plan_file(str(ROOT / "tests" / "fixtures" / "refresh_plan.json")),
               "terraform", "./infra/prod", generated_at=STAMP)
write(tf, "terraform-drift")

cfn = FakeCfn({"payments-api": [SG_DRIFT, LAMBDA_DRIFT, TAG_DRIFT], "batch-jobs": [DELETED_DRIFT], "network": []}, polls=0)
findings, statuses = dr.run_cloudformation(cfn, None, "us-east-1", sleep=lambda s: None, log=lambda *a, **k: None)
write(dr.Report(findings, "cloudformation", "all stacks in us-east-1", generated_at=STAMP, checked=statuses),
      "cloudformation-drift")
print("wrote", sorted(p.name for p in (ROOT / "examples").iterdir() if p.suffix != ".py"))

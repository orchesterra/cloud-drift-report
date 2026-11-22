"""Regenerate the sample reports in this folder: python3 examples/generate.py

Terraform samples come from tests/fixtures/refresh_plan.json (a realistic fake refresh-only plan).
CloudFormation samples come from a fake client that returns typical drift results.
The not-in-IaC sample is built from typical findings of an account scan.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "cloud-drift-report" / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import drift_report as dr  # noqa: E402
from test_drift_report import DELETED_DRIFT, LAMBDA_DRIFT, SG_DRIFT, TAG_DRIFT, FakeCfn  # noqa: E402

STAMP = "2026-11-20 09:00 UTC"
EXT = {"md": "md", "csv": "csv", "json": "json", "html": "html", "driftignore": "driftignore"}


def write(report, stem):
    for fmt, render in dr.RENDERERS.items():
        (ROOT / "examples" / f"{stem}.{EXT[fmt]}").write_text(render(report), encoding="utf-8")


tf_findings = dr.load_plan_file(str(ROOT / "tests" / "fixtures" / "refresh_plan.json"))
for f in tf_findings:
    f.location = "./infra/prod"  # not the fixture's path on whoever's machine generates the samples
tf = dr.Report(tf_findings, "terraform", "./infra/prod", generated_at=STAMP)
write(tf, "terraform-drift")

cfn = FakeCfn({"payments-api": [SG_DRIFT, LAMBDA_DRIFT, TAG_DRIFT], "batch-jobs": [DELETED_DRIFT], "network": []}, polls=0)
findings, statuses = dr.run_cloudformation(cfn, None, "us-east-1", sleep=lambda s: None, log=lambda *a, **k: None)
write(dr.Report(findings, "cloudformation", "all stacks in us-east-1", generated_at=STAMP, checked=statuses),
      "cloudformation-drift")
UNMANAGED = [  # (region, name, terraform type, physical id)
    ("global", "ci-deploy-user", "aws_iam_user", "arn:aws:iam::111111111111:user/ci-deploy-user"),
    ("us-east-1", "temp-debug-sg", "aws_security_group", "sg-0a1b2c3d4e5f60718"),
    ("us-east-1", "bastion", "aws_instance", "i-0123456789abcdef0"),
    ("us-east-1", "marketing-exports", "aws_s3_bucket", "marketing-exports"),
    ("us-east-1", "orders-replay", "aws_sqs_queue", "https://sqs.us-east-1.amazonaws.com/111111111111/orders-replay"),
    ("us-east-1", "/aws/lambda/resize-images", "aws_cloudwatch_log_group",
     "arn:aws:logs:us-east-1:111111111111:log-group:/aws/lambda/resize-images:*"),
]
un = [dr.finalize(dr.Finding(source="aws", location=region, address=name, type=rtype, action=dr.UNMANAGED,
                             physical_id=pid)) for region, name, rtype, pid in UNMANAGED]
write(dr.Report(un, "aws", "111111111111 (us-east-1)", generated_at=STAMP, coverage={
    "listed": 214, "in_iac": 208, "not_in_iac": 6, "aws_owned_skipped": 131, "types_not_listed": 2,
    "regions": ["us-east-1"],
    "iac_sources": ["s3://acme-tf-state/prod/ (196 resources)", "CloudFormation stacks in us-east-1 (12 resources)"],
    "not_listed": {"AWS::Lambda::LayerVersion (us-east-1)": "needs a parent resource to list; not checked",
                   "AWS::Logs::SubscriptionFilter (us-east-1)": "needs a parent resource to list; not checked"}}),
      "not-in-iac")
print("wrote", sorted(p.name for p in (ROOT / "examples").iterdir() if p.suffix != ".py"))

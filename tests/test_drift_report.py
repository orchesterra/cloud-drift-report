import csv
import io
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "aws-drift-report" / "scripts"))

import drift_report as dr  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "refresh_plan.json"


def by_addr(findings):
    return {f.address: f for f in findings}


# --- Terraform plan parsing ------------------------------------------------

def test_plan_json_findings_and_severity():
    found = by_addr(dr.load_plan_file(str(FIXTURE)))
    assert set(found) == {"aws_security_group.web", "aws_s3_bucket.logs", "aws_instance.worker",
                          "aws_sqs_queue.jobs", "aws_db_instance.main", "aws_iam_role_policy.app"}

    sg = found["aws_security_group.web"]
    assert sg.severity == "high"
    assert sg.action == dr.CHANGED
    assert "0.0.0.0/0" in sg.explanation
    assert [c.path for c in sg.changes] == ["ingress[1]"]  # one added rule, reported whole
    assert sg.changes[0].before is None and sg.changes[0].after["cidr_blocks"] == ["0.0.0.0/0"]
    assert sg.physical_id.startswith("arn:aws:ec2")

    tags = found["aws_s3_bucket.logs"]
    assert tags.severity == "low"
    assert [c.path for c in tags.changes] == ["tags.CostCenter"]  # tags_all duplicate dropped
    assert "Tag added" in tags.explanation

    assert found["aws_instance.worker"].severity == "medium"
    assert "instance_type" in found["aws_instance.worker"].explanation

    q = found["aws_sqs_queue.jobs"]
    assert q.action == dr.DELETED and q.severity == "medium" and q.changes == []
    assert "Deleted outside IaC" in q.explanation

    assert found["aws_iam_role_policy.app"].severity == "high"
    assert "Policy" in found["aws_iam_role_policy.app"].explanation


def test_sensitive_values_are_masked():
    db = by_addr(dr.load_plan_file(str(FIXTURE)))["aws_db_instance.main"]
    assert db.severity == "high"  # password changes are security relevant
    assert "Password or secret" in db.explanation
    (change,) = db.changes
    assert change.before == "(sensitive)"
    out = dr.render_json(dr.Report([db], "terraform", "x"))
    assert "old-secret" not in out and "new-secret" not in out


def test_diff_treats_empty_as_missing_and_reports_list_items_whole():
    changes = dr.diff_attributes(
        {"ingress": [], "tags": None, "x": {"a": 1}},
        {"ingress": [{"from_port": 22, "cidr_blocks": ["0.0.0.0/0"]}], "tags": {}, "x": {"a": 2}})
    assert [(c.path, c.before) for c in changes] == [("ingress[0]", None), ("x.a", 1)]
    removed = dr.diff_attributes({"rules": [{"p": 1}, {"p": 2}]}, {"rules": [{"p": 1}]})
    assert [(c.path, c.before, c.after) for c in removed] == [("rules[1]", {"p": 2}, None)]


def test_empty_drift_and_noop():
    assert dr.parse_plan_json({"format_version": "1.2"}) == []
    assert dr.parse_plan_json({"resource_drift": [{"address": "a", "change": {"actions": ["no-op"]}}]}) == []


def test_streaming_json_log(tmp_path):
    log = tmp_path / "plan.log"
    log.write_text("\n".join(json.dumps(m) for m in [
        {"type": "version", "terraform": "1.11.0"},
        {"type": "resource_drift", "change": {"resource": {"addr": "aws_s3_bucket.a", "resource_type": "aws_s3_bucket"}, "action": "update"}},
        {"type": "resource_drift", "change": {"resource": {"addr": "aws_iam_role.r", "resource_type": "aws_iam_role"}, "action": "delete"}},
    ]))
    found = by_addr(dr.load_plan_file(str(log)))
    assert found["aws_s3_bucket.a"].action == dr.CHANGED
    assert found["aws_iam_role.r"].action == dr.DELETED and found["aws_iam_role.r"].severity == "high"


def test_rejects_non_plan_json(tmp_path):
    p = tmp_path / "x.json"
    p.write_text('{"hello": 1}')
    with pytest.raises(ValueError):
        dr.load_plan_file(str(p))


def test_run_terraform_is_refresh_only_and_lock_free(tmp_path, monkeypatch):
    (tmp_path / ".terraform").mkdir()
    calls = []
    plan = json.loads(FIXTURE.read_text())

    def runner(cmd, **kw):
        calls.append(cmd)
        out = json.dumps(plan) if "show" in cmd else ""
        return SimpleNamespace(returncode=0, stdout=out, stderr="")

    monkeypatch.setattr(dr.shutil, "which", lambda name: "/usr/bin/" + name)
    findings = dr.run_terraform(str(tmp_path), "tofu", runner=runner)
    assert len(findings) == 6
    plan_cmd, show_cmd = calls
    assert plan_cmd[0] == "tofu" and "plan" in plan_cmd and "-refresh-only" in plan_cmd and "-lock=false" in plan_cmd
    assert not any(a in ("apply", "import", "state", "refresh") for a in plan_cmd + show_cmd)
    assert show_cmd[2:4] == ["show", "-json"]


def test_run_terraform_needs_init(tmp_path, monkeypatch):
    monkeypatch.setattr(dr.shutil, "which", lambda name: "/usr/bin/" + name)
    with pytest.raises(RuntimeError, match="init"):
        dr.run_terraform(str(tmp_path), "tofu", runner=lambda *a, **k: None)


# --- CloudFormation --------------------------------------------------------

class FakePaginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **kw):
        return iter(self.pages)


class FakeCfn:
    """Records calls; only read/drift-check APIs exist, so any write would raise AttributeError."""

    def __init__(self, drifts_by_stack, polls=1, fail=None):
        self.drifts = drifts_by_stack
        self.polls = polls
        self.fail = fail or set()
        self.calls = []

    def get_paginator(self, name):
        assert name == "list_stacks"
        return FakePaginator([{"StackSummaries": [
            {"StackName": n} for n in self.drifts] + [{"StackName": "nested", "ParentId": "arn:parent"}]}])

    def detect_stack_drift(self, StackName):
        self.calls.append(("detect", StackName))
        if StackName in self.fail:
            raise RuntimeError("AccessDenied")
        return {"StackDriftDetectionId": f"det-{StackName}"}

    def describe_stack_drift_detection_status(self, StackDriftDetectionId):
        self.calls.append(("status", StackDriftDetectionId))
        if sum(1 for c in self.calls if c[0] == "status") <= self.polls:
            return {"DetectionStatus": "DETECTION_IN_PROGRESS"}
        name = StackDriftDetectionId[4:]
        return {"DetectionStatus": "DETECTION_COMPLETE",
                "StackDriftStatus": "DRIFTED" if self.drifts[name] else "IN_SYNC"}

    def describe_stack_resource_drifts(self, StackName, StackResourceDriftStatusFilters, NextToken=None):
        self.calls.append(("drifts", StackName, NextToken))
        items = self.drifts[StackName]
        if NextToken is None and len(items) > 1:
            return {"StackResourceDrifts": items[:1], "NextToken": "page2"}
        return {"StackResourceDrifts": items[1:] if NextToken else items}


SG_DRIFT = {
    "LogicalResourceId": "WebSG", "PhysicalResourceId": "sg-0f1e2d3c4b5a69788", "ResourceType": "AWS::EC2::SecurityGroup",
    "StackResourceDriftStatus": "MODIFIED",
    "PropertyDifferences": [{"PropertyPath": "/SecurityGroupIngress/1", "ExpectedValue": "null",
                             "ActualValue": '{"CidrIp":"0.0.0.0/0","FromPort":22,"IpProtocol":"tcp","ToPort":22}',
                             "DifferenceType": "ADD"}]}
TAG_DRIFT = {
    "LogicalResourceId": "ReceiptsBucket", "PhysicalResourceId": "acme-payments-receipts", "ResourceType": "AWS::S3::Bucket",
    "StackResourceDriftStatus": "MODIFIED",
    "PropertyDifferences": [{"PropertyPath": "/Tags/1/Value", "ExpectedValue": "dev", "ActualValue": "prod",
                             "DifferenceType": "NOT_EQUAL"}]}
DELETED_DRIFT = {
    "LogicalResourceId": "JobsQueue", "PhysicalResourceId": "https://sqs.us-east-1.amazonaws.com/111122223333/batch-jobs", "ResourceType": "AWS::SQS::Queue",
    "StackResourceDriftStatus": "DELETED", "PropertyDifferences": []}
LAMBDA_DRIFT = {
    "LogicalResourceId": "WebhookFunction", "PhysicalResourceId": "payments-api-webhook", "ResourceType": "AWS::Lambda::Function",
    "StackResourceDriftStatus": "MODIFIED",
    "PropertyDifferences": [{"PropertyPath": "/MemorySize", "ExpectedValue": "128", "ActualValue": "1024",
                             "DifferenceType": "NOT_EQUAL"}]}


def test_cloudformation_all_stacks_with_wait_and_paging():
    cfn = FakeCfn({"app": [SG_DRIFT, TAG_DRIFT], "data": [DELETED_DRIFT, LAMBDA_DRIFT], "clean": []}, polls=2)
    sleeps = []
    findings, statuses = dr.run_cloudformation(cfn, None, "us-east-1", sleep=sleeps.append, log=lambda *a, **k: None)
    assert statuses == {"app": "DRIFTED", "data": "DRIFTED", "clean": "IN_SYNC"}
    assert "nested" not in statuses
    assert sleeps  # it waited for the in-progress detection
    found = by_addr(findings)
    assert found["WebSG"].severity == "high"
    assert found["WebSG"].changes[0].after["CidrIp"] == "0.0.0.0/0"  # JSON values decoded
    assert "0.0.0.0/0" in found["WebSG"].explanation
    assert found["WebSG"].location == "app (us-east-1)"
    assert found["ReceiptsBucket"].severity == "low"
    assert found["JobsQueue"].action == dr.DELETED and found["JobsQueue"].severity == "medium"
    assert found["WebhookFunction"].severity == "medium" and found["WebhookFunction"].changes[0].after == 1024
    assert ("drifts", "app", "page2") in cfn.calls


def test_cloudformation_stack_error_does_not_stop_others():
    cfn = FakeCfn({"bad": [], "good": [LAMBDA_DRIFT]}, polls=0, fail={"bad"})
    findings, statuses = dr.run_cloudformation(cfn, ["bad", "good"], "", sleep=lambda s: None, log=lambda *a, **k: None)
    assert statuses["bad"].startswith("ERROR") and statuses["good"] == "DRIFTED"
    assert [f.address for f in findings] == ["WebhookFunction"]


def test_detect_drift_timeout():
    cfn = FakeCfn({"slow": []}, polls=10**6)
    with pytest.raises(TimeoutError):
        dr.detect_drift(cfn, "slow", timeout=10, poll=5, sleep=lambda s: None)


# --- severity -------------------------------------------------------------

@pytest.mark.parametrize("rtype,paths,sev", [
    ("aws_vpc_security_group_ingress_rule", ["cidr_ipv4"], "high"),
    ("aws_s3_bucket_public_access_block", ["block_public_acls"], "high"),
    ("aws_kms_key", ["description"], "high"),
    ("aws_s3_bucket", ["server_side_encryption_configuration[0].rule"], "high"),
    ("aws_lambda_function", ["timeout"], "medium"),
    ("aws_lambda_function", ["tags.Owner", "tags_all.Owner"], "low"),
    ("AWS::S3::Bucket", ["/Tags/0/Value"], "low"),
    ("AWS::S3::Bucket", ["/PublicAccessBlockConfiguration/BlockPublicAcls"], "high"),
    ("AWS::IAM::Role", ["/Tags/0/Value"], "high"),
])
def test_severity(rtype, paths, sev):
    assert dr.classify_severity(rtype, dr.CHANGED, paths) == sev


# --- rendering ---------------------------------------------------------------

@pytest.fixture
def report():
    return dr.Report(dr.load_plan_file(str(FIXTURE)), "terraform", "./infra", generated_at="2026-11-20 10:00 UTC")


def test_markdown(report):
    md = dr.render_markdown(report)
    assert "6 drifted resource(s)** · high: 3 · medium: 2 · low: 1" in md
    assert md.index("HIGH") < md.index("MEDIUM") < md.index("LOW")
    assert "6 of these can be fixed with a pull request in Orchesterra" in md
    assert md.rstrip().endswith(dr.FOOTER)
    assert "utm_source=drift-skill&utm_medium=oss" in md


def test_no_drift_has_footer_but_no_pr_line():
    for fmt, render in dr.RENDERERS.items():
        out = render(dr.Report([], "terraform", "x"))
        assert "drift-skill" in out, fmt
        assert "pull request in Orchesterra" not in out, fmt


def test_csv(report):
    rows = list(csv.reader(io.StringIO(dr.render_csv(report))))
    assert rows[0] == dr.CSV_FIELDS
    data = [r for r in rows[1:] if r and not r[0].startswith("#")]
    assert {r[3] for r in data} >= {"aws_security_group.web", "aws_sqs_queue.jobs"}
    assert rows[-1][0].startswith("# Run this daily")


def test_json(report):
    doc = json.loads(dr.render_json(report))
    assert doc["summary"] == {"total": 6, "high": 3, "medium": 2, "low": 1}
    assert doc["findings"][0]["severity"] == "high"
    assert doc["footer"] == dr.FOOTER and "Orchesterra" in doc["note"]


def test_html_is_self_contained_and_escaped(report):
    report.findings[0].explanation = "<script>alert(1)</script>"
    page = dr.render_html(report)
    assert page.startswith("<!doctype html>")
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page
    assert "http" not in page.replace(dr.PRODUCT_URL.replace("&", "&amp;"), "")  # no external assets
    assert "prefers-color-scheme:dark" in page


# --- CLI -----------------------------------------------------------------

def test_cli_plan_json_formats(tmp_path, capsys):
    for fmt in ("md", "csv", "json", "html"):
        out = tmp_path / f"r.{fmt}"
        assert dr.main(["terraform", "--plan-json", str(FIXTURE), "-f", fmt, "-o", str(out)]) == 0
        assert out.read_text()
    assert dr.main(["tf", "--plan-json", str(FIXTURE), "--fail-on-drift"]) == 2
    assert "Drift report" in capsys.readouterr().out


def test_cli_share_is_placeholder_without_network(capsys, monkeypatch):
    import socket
    monkeypatch.setattr(socket, "socket", lambda *a, **k: pytest.fail("network used"))
    assert dr.main(["terraform", "--plan-json", str(FIXTURE), "--share"]) == 0
    assert "coming soon" in capsys.readouterr().err


def test_cli_error_exit_code(capsys):
    assert dr.main(["terraform", "--plan-json", "/nonexistent.json"]) == 1
    assert "error:" in capsys.readouterr().err


def test_script_runs_standalone():
    script = ROOT / "skills" / "aws-drift-report" / "scripts" / "drift_report.py"
    proc = subprocess.run([sys.executable, str(script), "terraform", "--plan-json", str(FIXTURE), "-f", "json"],
                          capture_output=True, text=True, env={**os.environ, "PYTHONPATH": ""})
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["summary"]["total"] == 6

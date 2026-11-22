import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "cloud-drift-report" / "scripts"))

import drift_ignore as ig  # noqa: E402
import drift_report as dr  # noqa: E402

CASES = json.loads((ROOT / "tests" / "fixtures" / "driftignore_cases.json").read_text())["cases"]
PLAN = ROOT / "tests" / "fixtures" / "refresh_plan.json"


def make_finding(spec):
    return dr.Finding(
        source="test", location="", address=spec["address"], type=spec["type"], action=spec["action"],
        changes=[dr.Change(p, None, "x") for p in spec.get("paths", [])],
        physical_id=spec.get("physical_id", ""), tags=spec.get("tags", {}))


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_shared_cases(case):
    rules = ig.parse("\n".join(case["rules"]))
    f = make_finding(case["finding"])
    report = dr.apply_ignore(dr.Report([f], "test", "t"), rules)
    if case["expect"] == "ignored":
        assert not report.findings and len(report.ignored) == 1
    elif case["expect"] == "kept":
        assert report.findings == [f] and [c.path for c in f.changes] == case["finding"].get("paths", [])
    else:
        assert [c.path for c in report.findings[0].changes] == case["kept_paths"]


def test_attribute_rule_recomputes_severity():
    found = {f.address: f for f in dr.load_plan_file(str(PLAN))}
    sg = found["aws_security_group.web"]
    sg.changes.append(dr.Change("tags.Owner", None, "ops"))
    report = dr.apply_ignore(dr.Report([sg], "terraform", "t"), ig.parse("aws_security_group.web.ingress"))
    assert [c.path for c in report.findings[0].changes] == ["tags.Owner"]
    assert report.findings[0].explanation.startswith("Tag")


def test_bad_lines_are_reported():
    assert ig.problems("aws_s3_bucket.ok\naws s3 bucket\ntag:\n!\naws_iam_role.*.\n") == [
        (2, "aws s3 bucket"), (3, "tag:"), (4, "!"), (5, "aws_iam_role.*.")]


def test_cli_reads_driftignore_and_reports_it(tmp_path, monkeypatch, capsys):
    (tmp_path / ".driftignore").write_text("aws_s3_bucket.logs\naws_iam_role_policy.*\n")
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "r.json"
    assert dr.main(["terraform", "--plan-json", str(PLAN), "-f", "json", "-o", str(out), "--fail-on-drift"]) == 2
    doc = json.loads(out.read_text())
    assert doc["schema"] == 1 and doc["summary"]["ignored"] == 2 and doc["summary"]["total"] == 4
    assert {i["rule"] for i in doc["ignored"]} == {"aws_s3_bucket.logs", "aws_iam_role_policy.*"}
    assert all("tags" not in f for f in doc["findings"])
    assert "2 findings ignored by .driftignore " in capsys.readouterr().err  # relative path, no home dir

    md = dr.main(["terraform", "--plan-json", str(PLAN), "--no-ignore", "-f", "json", "-o", str(tmp_path / "all.json")])
    assert md == 0 and json.loads((tmp_path / "all.json").read_text())["summary"]["total"] == 6


def test_everything_ignored_passes_ci(tmp_path, monkeypatch):
    (tmp_path / "rules").write_text("*\n")
    monkeypatch.chdir(tmp_path)
    assert dr.main(["terraform", "--plan-json", str(PLAN), "--ignore", "rules", "--fail-on-drift",
                    "-o", str(tmp_path / "r.md")]) == 0
    assert "6 findings ignored by rules" in (tmp_path / "r.md").read_text()


def test_missing_ignore_file_is_an_error(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert dr.main(["terraform", "--plan-json", str(PLAN), "--ignore", "nope"]) == 1
    assert "nope not found" in capsys.readouterr().err


def test_generated_driftignore_ignores_everything_it_lists(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    gen = tmp_path / "baseline"
    assert dr.main(["terraform", "--plan-json", str(PLAN), "-f", "driftignore", "-o", str(gen)]) == 0
    text = gen.read_text()
    assert text.startswith("# ") and "aws_security_group.web" in text
    report = dr.apply_ignore(dr.Report(dr.load_plan_file(str(PLAN)), "terraform", "t"), ig.parse(text))
    assert not report.findings and len(report.ignored) == 6


def test_escaped_id_matches_only_itself():
    odd = dr.Finding("aws", "us-east-1", "logs.example.com*[1]?", "aws_s3_bucket", dr.UNMANAGED,
                     physical_id="logs.example.com*[1]?")
    other = dr.Finding("aws", "us-east-1", "logsXexample.com-other", "aws_s3_bucket", dr.UNMANAGED,
                       physical_id="logsXexample.com-other")
    rules = ig.parse("aws_s3_bucket." + ig.escape_id(odd.physical_id))
    report = dr.apply_ignore(dr.Report([odd, other], "aws", "t"), rules)
    assert report.findings == [other] and report.ignored[0][0] is odd


def test_coverage_counts_follow_ignores():
    f = dr.Finding("aws", "us-east-1", "scratch", "aws_s3_bucket", dr.UNMANAGED, physical_id="arn:aws:s3:::scratch")
    report = dr.Report([f], "aws", "t", coverage={"listed": 5, "in_iac": 4, "not_in_iac": 1})
    dr.apply_ignore(report, ig.parse("aws_s3_bucket.scratch"), ["rules"])
    assert report.coverage["not_in_iac"] == 0 and report.coverage["ignored"] == 1
    assert "1 finding ignored by rules" in dr.render_markdown(report)


@pytest.mark.parametrize("arn,short", [
    ("arn:aws:iam::111111111111:role/app", "app"),
    ("arn:aws:iam::111111111111:role/service-role/app", "service-role/app"),
    ("arn:aws:ec2:us-east-1:111111111111:security-group/sg-0abc", "sg-0abc"),
    ("arn:aws:logs:us-east-1:111111111111:log-group:/aws/lambda/resize:*", "/aws/lambda/resize"),
    ("arn:aws:lambda:us-east-1:111111111111:function:legacy-report", "legacy-report"),
    ("arn:aws:sqs:us-east-1:111111111111:jobs", "jobs"),
    ("arn:aws:s3:::acme-logs", "acme-logs"),
    ("arn:aws:logs:us-east-1:111111111111:log-group:*", "arn:aws:logs:us-east-1:111111111111:log-group:*"),
    ("i-0abc", "i-0abc"),
])
def test_short_id(arn, short):
    assert ig.short_id(arn) == short


def test_generated_rule_for_a_log_group_hides_only_that_log_group():
    mine = dr.Finding("aws", "us-east-1", "/aws/lambda/resize", "aws_cloudwatch_log_group", dr.UNMANAGED,
                      physical_id="arn:aws:logs:us-east-1:111111111111:log-group:/aws/lambda/resize:*")
    other = dr.Finding("aws", "us-east-1", "/aws/lambda/other", "aws_cloudwatch_log_group", dr.UNMANAGED,
                       physical_id="arn:aws:logs:us-east-1:111111111111:log-group:/aws/lambda/other:*")
    rules = ig.parse(dr.render_driftignore(dr.Report([mine], "aws", "t")))
    report = dr.apply_ignore(dr.Report([mine, other], "aws", "t"), rules)
    assert report.findings == [other]


def test_regenerating_keeps_existing_rules(tmp_path, monkeypatch):
    (tmp_path / ".driftignore").write_text("# ours\ntag:temporary\naws_iam_role_policy.*\n")
    monkeypatch.chdir(tmp_path)
    assert dr.main(["terraform", "--plan-json", str(PLAN), "-o", ".driftignore"]) == 0  # no -f: name decides
    text = (tmp_path / ".driftignore").read_text()
    assert "tag:temporary" in text and text.count("aws_iam_role_policy") == 1
    rules = ig.parse(text)
    report = dr.apply_ignore(dr.Report(dr.load_plan_file(str(PLAN)), "terraform", "t"), rules)
    assert not report.findings

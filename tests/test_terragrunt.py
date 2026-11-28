import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "cloud-drift-report" / "scripts"))

import drift_report as dr  # noqa: E402
import terragrunt as tg  # noqa: E402

PLAN = json.loads((ROOT / "tests" / "fixtures" / "refresh_plan.json").read_text())


class FakeTerragrunt:
    """Stands in for subprocess.run: answers --version, plan and show like Terragrunt would."""

    def __init__(self, version="terragrunt version v1.2.3", plans=None, plan_rc=0, noise=""):
        self.version, self.calls, self.plan_rc, self.noise = version, [], plan_rc, noise
        self.plans = plans  # unit dir name -> plan dict, or None for "no plan written"

    def __call__(self, cmd, **kw):
        self.calls.append((cmd, kw))
        if cmd[1:] == ["--version"]:
            return SimpleNamespace(returncode=0, stdout=self.version + "\n", stderr="")
        if "plan" in cmd:
            return SimpleNamespace(returncode=self.plan_rc, stdout="", stderr="boom" if self.plan_rc else "")
        if "show" in cmd:
            plan = PLAN if self.plans is None else self.plans.get(Path(kw["cwd"]).name)
            if plan is None:
                return SimpleNamespace(returncode=1, stdout="", stderr="no such file")
            return SimpleNamespace(returncode=0, stdout=self.noise + json.dumps(plan), stderr="")
        raise AssertionError(f"unexpected command {cmd}")

    def tf_calls(self):
        return [(c, kw) for c, kw in self.calls if c[1:] != ["--version"]]


@pytest.fixture(autouse=True)
def on_path(monkeypatch):
    monkeypatch.setattr(tg.shutil, "which", lambda name: "/bin/" + name)
    monkeypatch.setattr(dr.shutil, "which", lambda name: "/bin/" + name)


def unit(path: Path, body: str = 'terraform { source = "../modules/x" }\n') -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / "terragrunt.hcl").write_text(body)
    return path


def stack(tmp_path: Path) -> Path:
    (tmp_path / "root.hcl").write_text("remote_state {}\n")
    unit(tmp_path / "live" / "vpc")
    unit(tmp_path / "live" / "app", 'dependency "vpc" { config_path = "../vpc" }\n')
    unit(tmp_path / "live" / "app" / ".terragrunt-cache" / "x" / "y")  # copied code, not a unit
    return tmp_path


def args(**kw):
    base = dict(all=False, terragrunt=False, no_terragrunt=False, terragrunt_bin=None, binary=None,
                var_file=[], profile=None)
    return SimpleNamespace(**{**base, **kw})


# --- detection ------------------------------------------------------------------

def test_detects_unit_and_root(tmp_path):
    assert not tg.wanted(args(), str(tmp_path))
    (tmp_path / "root.hcl").write_text("")
    assert tg.wanted(args(), str(tmp_path))
    assert not tg.wanted(args(no_terragrunt=True), str(tmp_path))
    plain = tmp_path / "plain"
    plain.mkdir()
    assert tg.wanted(args(terragrunt=True), str(plain)) and tg.wanted(args(all=True), str(plain))


def test_find_units_skips_cache_and_include_parent(tmp_path):
    unit(tmp_path, "# include parent\n")
    unit(tmp_path / "a")
    unit(tmp_path / "b" / "c")
    unit(tmp_path / "a" / ".terragrunt-cache" / "h" / "h")
    assert [Path(u).relative_to(tmp_path).as_posix() for u in tg.find_units(str(tmp_path))] == ["a", "b/c"]
    lone = unit(tmp_path / "lone")
    assert tg.find_units(str(lone)) == [str(lone)]


@pytest.mark.parametrize("text,new", [
    ("terragrunt version v0.72.6", False), ("terragrunt version v0.77.2", False),
    ("terragrunt version v0.78.0", True), ("terragrunt version 1.2.3", True), ("terragrunt version dev", True),
])
def test_version_picks_the_cli(text, new):
    assert tg.Cli("terragrunt", tg.parse_version(text), "tofu").new is new


# --- one unit -----------------------------------------------------------------------

def test_one_unit_new_cli_is_refresh_only_with_tofu(tmp_path):
    u = unit(tmp_path / "vpc")
    fake = FakeTerragrunt()
    findings, problems = tg.run(str(u), tf_binary="/bin/tofu", runner=fake)
    assert len(findings) == 6 and problems == []
    assert {f.unit for f in findings} == {str(u)}
    (plan, pkw), (show, _) = fake.tf_calls()
    assert plan[:5] == ["/bin/terragrunt", "run", "--tf-path", "/bin/tofu", "--"]
    assert plan[5:9] == ["plan", "-refresh-only", "-lock=false", "-input=false"]
    assert show[5:7] == ["show", "-json"]
    assert pkw["env"]["TG_TF_PATH"] == "/bin/tofu" and pkw["cwd"] == str(u)
    assert pkw["stdin"] == subprocess.DEVNULL
    everything = [a for c, _ in fake.calls for a in c]
    assert not any(a in ("apply", "destroy", "import", "state", "--non-interactive",
                         "--terragrunt-non-interactive", "--backend-bootstrap") for a in everything)


def test_one_unit_legacy_cli(tmp_path):
    u = unit(tmp_path / "vpc")
    fake = FakeTerragrunt(version="terragrunt version v0.72.6")
    tg.run(str(u), tf_binary="/bin/tofu", runner=fake, profile="prod")
    (plan, pkw), (show, _) = fake.tf_calls()
    assert plan[:3] == ["/bin/terragrunt", "plan", "-refresh-only"]
    assert plan[-2:] == ["--terragrunt-tfpath", "/bin/tofu"]
    assert show[1:3] == ["show", "-json"]
    assert pkw["env"]["TERRAGRUNT_TFPATH"] == "/bin/tofu" and pkw["env"]["AWS_PROFILE"] == "prod"
    assert "run" not in plan and "run-all" not in plan


def test_one_unit_plan_failure_is_an_error(tmp_path):
    with pytest.raises(RuntimeError, match="boom"):
        tg.run(str(unit(tmp_path / "vpc")), runner=FakeTerragrunt(plan_rc=1))


def test_show_json_skips_log_lines():
    assert tg.show_json('INFO hello {x}\n' + json.dumps(PLAN))["format_version"] == PLAN["format_version"]
    with pytest.raises(ValueError):
        tg.show_json("nothing here")


# --- a stack ------------------------------------------------------------------------

def test_stack_runs_all_and_tags_each_unit(tmp_path):
    root = stack(tmp_path)
    fake = FakeTerragrunt(plans={"vpc": PLAN, "app": PLAN})
    findings, problems = tg.run(str(root), all_units=True, tf_binary="tofu", runner=fake)
    (plan, pkw), *shows = fake.tf_calls()
    assert plan[:6] == ["/bin/terragrunt", "run", "--all", "--tf-path", "tofu", "--"]
    assert f"-out={tg.PLAN_NAME}" in plan and pkw["cwd"] == str(root)
    assert sorted(Path(kw["cwd"]).name for _, kw in shows) == ["app", "vpc"]
    assert len(findings) == 12 and problems == []
    assert {f.unit for f in findings} == {str(root / "live" / "app"), str(root / "live" / "vpc")}
    assert {f.location for f in findings} == {f.unit for f in findings}


def test_root_hcl_alone_means_the_whole_stack(tmp_path):
    root = stack(tmp_path)
    fake = FakeTerragrunt(version="terragrunt version v0.72.6", plans={"vpc": PLAN, "app": PLAN})
    tg.run(str(root), runner=fake)
    plan = fake.tf_calls()[0][0]
    assert plan[1:3] == ["run-all", "plan"] and plan[-2:] == ["--terragrunt-tfpath", "tofu"]


def test_stack_unit_without_plan_is_reported_incomplete(tmp_path):
    root = stack(tmp_path)
    fake = FakeTerragrunt(plans={"vpc": PLAN}, plan_rc=1)
    findings, problems = tg.run(str(root), all_units=True, runner=fake)
    assert len(findings) == 6 and problems == [f"{root / 'live' / 'app'}: no plan (it failed or was excluded)"]
    with pytest.raises(RuntimeError, match="boom"):
        tg.run(str(root), all_units=True, runner=FakeTerragrunt(plans={}, plan_rc=1))


def test_stack_removes_plan_files(tmp_path):
    root = stack(tmp_path)
    cache = root / "live" / "vpc" / ".terragrunt-cache" / "a" / "b"
    cache.mkdir(parents=True)
    (cache / tg.PLAN_NAME).write_text("plan")
    (root / "live" / "app" / tg.PLAN_NAME).write_text("plan")
    tg.run(str(root), all_units=True, runner=FakeTerragrunt(plans={"vpc": PLAN, "app": PLAN}))
    assert not list(root.rglob(tg.PLAN_NAME))


# --- through the CLI ------------------------------------------------------------------

def test_cli_stack_report_and_sarif(tmp_path, monkeypatch, capsys):
    root = stack(tmp_path)
    monkeypatch.chdir(root)
    fake = FakeTerragrunt(plans={"vpc": PLAN, "app": PLAN})
    monkeypatch.setattr(dr.subprocess, "run", fake)
    out_json, out_sarif = root / "r.json", root / "r.sarif"
    rc = dr.main(["tf", "--dir", str(root), "--all", "--no-ignore", "--no-config",
                  "-o", str(out_json), "-o", str(out_sarif)])
    assert rc == 0, capsys.readouterr().err
    doc = json.loads(out_json.read_text())
    assert doc["summary"]["total"] == 12
    assert {f["unit"] for f in doc["findings"]} == {"live/app", "live/vpc"}
    results = json.loads(out_sarif.read_text())["runs"][0]["results"]
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results}
    assert uris == {"live/app/terragrunt.hcl", "live/vpc/terragrunt.hcl"}
    names = {r["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] for r in results}
    assert "live/vpc//aws_security_group.web" in names
    assert len({r["partialFingerprints"]["driftFindingHash/v1"] for r in results}) == 12  # same address, 2 units
    md = dr.render_markdown(dr.Report([dr.Finding("terraform", "live/vpc", "aws_s3_bucket.logs", "aws_s3_bucket",
                                                  dr.DELETED, unit="live/vpc")], "terraform", "x"))
    assert "unit: live/vpc" in md


def test_cli_no_terragrunt_runs_tofu_directly(tmp_path, monkeypatch):
    u = unit(tmp_path / "vpc")
    (u / ".terraform").mkdir()
    calls = []

    def fake(cmd, **kw):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout=json.dumps(PLAN) if "show" in cmd else "", stderr="")

    monkeypatch.setattr(dr.subprocess, "run", fake)
    monkeypatch.setattr(dr, "run_terraform", lambda d, b, e, profile=None: dr.parse_plan_json(PLAN, d))
    assert dr.main(["tf", "--dir", str(u), "--no-terragrunt", "--no-ignore", "--no-config", "-f", "json"]) == 0
    assert calls == []  # went through run_terraform, not terragrunt


def test_plain_terraform_json_has_no_unit_key():
    assert "unit" not in dr._finding_json(dr.parse_plan_json(PLAN)[0])

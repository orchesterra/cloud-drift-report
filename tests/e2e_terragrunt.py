"""End-to-end check with real Terragrunt and OpenTofu (CI only; needs both on PATH, no cloud access).

Applies tests/fixtures/terragrunt-stack (random + local providers, local state), deletes one unit's file
outside IaC, then checks that `cloud-drift-report tf` finds it in that unit, both for one unit and with --all,
and that the state files are unchanged afterwards.

    python tests/e2e_terragrunt.py
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "cloud-drift-report" / "scripts"))

import terragrunt as tg  # noqa: E402


def sh(cmd, cwd):
    print("+", " ".join(cmd), flush=True)
    proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    if proc.returncode != 0:
        sys.exit(f"failed ({proc.returncode}):\n{proc.stdout}\n{proc.stderr}")
    return proc


def report(args, cwd):
    proc = sh([sys.executable, str(ROOT / "skills" / "cloud-drift-report" / "scripts" / "drift_report.py"),
               "tf", *args, "--no-ignore", "--no-config", "-f", "json"], cwd)
    print(proc.stderr, flush=True)
    return json.loads(proc.stdout)


def digest(stack: Path) -> dict:
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(stack.glob("state/**/*.tfstate"))}


def main() -> None:
    binary = tg.find_binary()
    cli = tg.Cli(binary, tg.detect_version(binary), shutil.which("tofu") or "tofu")
    print(cli.label(), flush=True)
    with tempfile.TemporaryDirectory() as tmp:
        stack = Path(tmp) / "stack"
        shutil.copytree(ROOT / "tests" / "fixtures" / "terragrunt-stack", stack)
        yes = ["--non-interactive"] if cli.new else ["--terragrunt-non-interactive"]
        apply = cli.tf(["apply", "-auto-approve"], all_units=True)
        sh(apply[:1] + yes + apply[1:] if cli.new else apply + yes, stack)

        clean = report(["--dir", "stack", "--all"], tmp)
        assert clean["summary"]["total"] == 0, clean

        (stack / "live" / "vpc" / "out.txt").unlink()  # changed outside IaC
        before = digest(stack)
        assert before, "no state files written"

        whole = report(["--dir", "stack", "--all"], tmp)
        found = [(f["unit"], f["address"], f["action"]) for f in whole["findings"]]
        assert found == [("stack/live/vpc", "local_file.out", "deleted outside IaC")], found

        one = report(["--dir", "stack/live/vpc"], tmp)
        assert [(f["unit"], f["address"]) for f in one["findings"]] == [("stack/live/vpc", "local_file.out")], one

        sarif = Path(tmp) / "r.sarif"
        sh([sys.executable, str(ROOT / "skills" / "cloud-drift-report" / "scripts" / "drift_report.py"),
            "tf", "--dir", "stack", "--all", "--no-ignore", "--no-config", "-o", str(sarif)], tmp)
        (res,) = json.loads(sarif.read_text())["runs"][0]["results"]
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "stack/live/vpc/terragrunt.hcl"

        assert digest(stack) == before, "state changed: the check must be read-only"
        assert not list(stack.rglob(tg.PLAN_NAME)), "plan files left behind"
        assert not (stack / "live" / "vpc" / "out.txt").exists(), "the check must not re-create resources"
    print("terragrunt e2e passed", flush=True)


if __name__ == "__main__":
    os.environ.setdefault("TF_IN_AUTOMATION", "1")
    main()

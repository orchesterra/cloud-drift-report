"""Terragrunt support for `cloud-drift-report tf`.

Terragrunt only orchestrates: the plan itself is OpenTofu (or Terraform), passed to Terragrunt as its tf path.
A unit is a directory with a terragrunt.hcl; a stack is a directory holding units (often with a root.hcl).

  * one unit:  terragrunt plan -refresh-only -lock=false -out=<tmp>  then  terragrunt show -json <tmp>
  * a stack:   terragrunt run-all plan ... -out=<name>  then  `show -json <name>` in each unit

Terragrunt 0.78 and later use the redesigned CLI (`run -- plan`, `run --all`, `--tf-path`, TG_TF_PATH);
older releases use `plan`, `run-all` and `--terragrunt-tfpath` (TERRAGRUNT_TFPATH). The `run` command needed
an experiment flag from 0.73 to 0.77, where the old commands still work, so the switch is at 0.78.

Read-only like the plain Terraform mode: refresh-only plans with -lock=false, never apply, and never
--non-interactive, so Terragrunt can't answer "yes" to creating a state bucket; stdin is closed, so any
prompt fails instead.
"""

from __future__ import annotations

import glob
import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Callable

UNIT_FILE = "terragrunt.hcl"
ROOT_FILES = ("root.hcl",)
NEW_CLI = (0, 78, 0)
PLAN_NAME = ".cloud-drift-report.tfplan"
_SKIP_DIRS = {".terragrunt-cache", ".terraform", ".git", "node_modules", ".terragrunt-stack"}


def add_args(parser) -> None:
    """The Terragrunt flags on the `tf` subcommand."""
    parser.add_argument("--terragrunt", action="store_true",
                        help="run through Terragrunt (default: when --dir has terragrunt.hcl or root.hcl)")
    parser.add_argument("--no-terragrunt", action="store_true",
                        help="run OpenTofu/Terraform directly even when --dir has terragrunt.hcl")
    parser.add_argument("--terragrunt-bin", default=None, metavar="PATH",
                        help="Terragrunt binary (default: terragrunt on PATH)")
    parser.add_argument("--all", action="store_true",
                        help="Terragrunt: check every unit under --dir (run --all / run-all), one report")


def is_unit(directory: str) -> bool:
    return os.path.isfile(os.path.join(directory, UNIT_FILE))


def is_root(directory: str) -> bool:
    return is_unit(directory) or any(os.path.isfile(os.path.join(directory, n)) for n in ROOT_FILES)


def wanted(args, directory: str) -> bool:
    if getattr(args, "no_terragrunt", False):
        return False
    return bool(getattr(args, "terragrunt", False) or getattr(args, "all", False) or is_root(directory))


def find_units(stack: str) -> list[str]:
    """Unit directories under a stack, sorted. A terragrunt.hcl at the top is an include parent, not a unit,
    when there are units below it (the layout before root.hcl)."""
    units = []
    for root, dirs, names in os.walk(stack):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS and not d.startswith("."))
        if UNIT_FILE in names:
            units.append(root)
    below = [u for u in units if os.path.abspath(u) != os.path.abspath(stack)]
    return below or units


def parse_version(text: str) -> tuple[int, int, int] | None:
    m = re.search(r"v?(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else None  # type: ignore[return-value]


def detect_version(binary: str, runner=subprocess.run) -> tuple[int, int, int] | None:
    try:
        proc = runner([binary, "--version"], capture_output=True, text=True, stdin=subprocess.DEVNULL)
    except OSError:
        return None
    return parse_version((proc.stdout or "") + (proc.stderr or ""))


def find_binary(preferred: str | None = None) -> str:
    name = preferred or "terragrunt"
    path = shutil.which(name) or (name if os.path.isfile(name) else None)
    if not path:
        raise RuntimeError(f"`{name}` was not found. Install Terragrunt, pass --terragrunt-bin, "
                           "or use --no-terragrunt to run OpenTofu directly.")
    return path


class Cli:
    """Builds commands for the old (< 0.78) or the redesigned Terragrunt CLI."""

    def __init__(self, binary: str, version: tuple[int, int, int] | None, tf_path: str):
        self.binary, self.version, self.tf_path = binary, version, tf_path
        self.new = version is None or version >= NEW_CLI  # unknown (a dev build): assume current

    def env(self, profile: str | None = None) -> dict[str, str]:
        env = dict(os.environ)
        env["TG_TF_PATH" if self.new else "TERRAGRUNT_TFPATH"] = self.tf_path
        if profile:
            env["AWS_PROFILE"] = profile
        return env

    def tf(self, tf_args: list[str], all_units: bool = False) -> list[str]:
        if self.new:
            return [self.binary, "run", *(["--all"] if all_units else []), "--tf-path", self.tf_path, "--", *tf_args]
        return [self.binary, *(["run-all"] if all_units else []), *tf_args, "--terragrunt-tfpath", self.tf_path]

    def label(self) -> str:
        v = ".".join(map(str, self.version)) if self.version else "unknown version"
        return f"terragrunt {v} ({'run' if self.new else 'legacy'} CLI)"


def plan_args(out: str, extra_args: list[str] | None) -> list[str]:
    return ["plan", "-refresh-only", "-lock=false", "-input=false", "-no-color", f"-out={out}", *(extra_args or [])]


def show_json(text: str) -> dict[str, Any]:
    """`show -json` output, skipping anything Terragrunt printed before it."""
    text = text or ""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    dec = json.JSONDecoder()
    for m in re.finditer(r"^\s*\{", text, re.M):
        try:
            obj, _ = dec.raw_decode(text, m.end() - 1)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and ("format_version" in obj or "resource_drift" in obj):
            return obj
    raise ValueError("Terragrunt `show -json` printed no plan JSON")


def cache_dir(unit: str) -> str | None:
    """The newest .terragrunt-cache working directory for a unit (where tofu ran), for its backend."""
    hits = [os.path.dirname(p) for p in glob.glob(os.path.join(unit, ".terragrunt-cache", "*", "*", ".terraform"))]
    if not hits and os.path.isdir(os.path.join(unit, ".terraform")):
        return unit  # a unit with no terraform { source }: tofu runs in place
    return max(hits, key=os.path.getmtime) if hits else None


def _remove_plans(unit: str) -> None:
    for p in [os.path.join(unit, PLAN_NAME),
              *glob.glob(os.path.join(unit, ".terragrunt-cache", "*", "*", PLAN_NAME)),
              *glob.glob(os.path.join(unit, ".terragrunt-cache", "*", "*", "**", PLAN_NAME), recursive=True)]:
        try:
            os.remove(p)
        except OSError:
            pass


def _fail(cmd: list[str], proc) -> RuntimeError:
    return RuntimeError(f"`{' '.join(cmd)}` failed:\n{(proc.stderr or proc.stdout or '').strip()[-4000:]}")


def run(directory: str, *, all_units: bool = False, binary: str | None = None, tf_binary: str = "tofu",
        extra_args: list[str] | None = None, profile: str | None = None, runner=None,
        parse: Callable[[dict, str], list] | None = None, shown: Callable[[str], str] = lambda p: p,
        log: Callable[[str], None] = lambda m: None) -> tuple[list, list[str]]:
    """Refresh-only plan through Terragrunt. Returns (findings, problems); each finding's `unit` is its unit."""
    runner = runner or subprocess.run
    if parse is None:
        from drift_report import parse_plan_json as parse
    tg = find_binary(binary)
    cli = Cli(tg, detect_version(tg, runner), tf_binary)
    env = cli.env(profile)
    log(f"using {cli.label()} with {os.path.basename(tf_binary)}")
    stack_mode = all_units or (not is_unit(directory) and is_root(directory))

    def call(cmd, cwd):
        return runner(cmd, capture_output=True, text=True, env=env, cwd=cwd, stdin=subprocess.DEVNULL)

    def tag(findings, unit):
        for f in findings:
            f.unit = shown(unit)
        return findings

    if not stack_mode:
        if not is_unit(directory):
            raise RuntimeError(f"{directory} has no {UNIT_FILE}; use --all for a stack, or --no-terragrunt.")
        with tempfile.TemporaryDirectory(prefix="drift-report-") as tmp:
            planfile = os.path.join(tmp, "refresh.tfplan")
            cmd = cli.tf(plan_args(planfile, extra_args))
            proc = call(cmd, directory)
            if proc.returncode != 0:
                raise _fail(cmd, proc)
            cmd = cli.tf(["show", "-json", "-no-color", planfile])
            show = call(cmd, directory)
            if show.returncode != 0:
                raise _fail(cmd, show)
        return tag(parse(show_json(show.stdout), shown(directory)), directory), []

    units = find_units(directory)
    if not units:
        raise RuntimeError(f"No {UNIT_FILE} found under {directory}.")
    cmd = cli.tf(plan_args(PLAN_NAME, extra_args), all_units=True)
    proc = call(cmd, directory)
    findings, problems, done = [], [], 0
    try:
        for unit in units:
            show = call(cli.tf(["show", "-json", "-no-color", PLAN_NAME]), unit)
            if show.returncode != 0:
                problems.append(f"{shown(unit)}: no plan (it failed or was excluded)")
                continue
            try:
                plan = show_json(show.stdout)
            except ValueError as exc:
                problems.append(f"{shown(unit)}: {exc}")
                continue
            findings += tag(parse(plan, shown(unit)), unit)
            done += 1
    finally:
        for unit in units:
            _remove_plans(unit)
    if not done:
        raise _fail(cmd, proc) if proc.returncode != 0 else RuntimeError(f"No unit under {directory} produced a plan.")
    if proc.returncode != 0 and not problems:
        problems.append("terragrunt run-all plan exited with an error; some units may be missing")
    return findings, problems

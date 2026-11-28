#!/usr/bin/env python3
"""cloud-drift-report: read-only drift report for Terraform/OpenTofu (any cloud) and AWS CloudFormation.

Finds resources that were changed or deleted outside infrastructure as code, and
resources that exist in AWS but no Terraform state or CloudFormation stack lists,
and writes a report as Markdown, CSV, JSON or a self-contained HTML page.

It never writes to AWS or to Terraform state:
  * Terraform/OpenTofu: runs `plan -refresh-only -lock=false` into a temporary
    plan file and reads it with `show -json` (or reads a plan JSON you give it).
  * CloudFormation: calls DetectStackDrift (which only records a drift check)
    and DescribeStackResourceDrifts.
  * Not in IaC: lists the account with List/Describe calls (see aws_inventory.py)
    and compares it with your state files and stacks.

Needs Python 3.10+, the stdlib, and boto3 for the AWS modes.
No telemetry. Licence: Apache-2.0.
"""

from __future__ import annotations

import argparse
import csv
import html
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

__version__ = "0.9.1"

PRODUCT_URL = "https://www.orchesterra.in/?utm_source=drift-skill&utm_medium=oss"
FOOTER = f"Run this daily across all your AWS accounts, with approvals and auto-fix PRs → {PRODUCT_URL}"

SEVERITIES = ("high", "medium", "low")
FILENAME_HINT = ".driftignore"
CHANGED = "changed outside IaC"
DELETED = "deleted outside IaC"
UNMANAGED = "not in IaC"

# --- severity rules -------------------------------------------------------

# Resource types whose drift is security relevant whatever changed.
_SECURITY_TYPE_HINTS = (
    # Terraform
    "aws_security_group", "aws_vpc_security_group_", "aws_network_acl", "aws_iam_",
    "aws_s3_bucket_policy", "aws_s3_bucket_public_access_block", "aws_s3_account_public_access_block",
    "aws_s3_bucket_acl", "aws_s3_bucket_server_side_encryption_configuration", "aws_kms_",
    "aws_lambda_permission", "aws_sns_topic_policy", "aws_sqs_queue_policy", "aws_ecr_repository_policy",
    "aws_secretsmanager_secret_policy", "aws_organizations_policy", "aws_wafv2_",
    # CloudFormation
    "AWS::EC2::SecurityGroup", "AWS::EC2::NetworkAcl", "AWS::IAM::", "AWS::S3::BucketPolicy",
    "AWS::KMS::", "AWS::Lambda::Permission", "AWS::SNS::TopicPolicy", "AWS::SQS::QueuePolicy",
    "AWS::SecretsManager::ResourcePolicy", "AWS::WAFv2::",
)

# Attribute/property names that make a change security relevant on any type.
_SECURITY_ATTR_HINTS = (
    "ingress", "egress", "cidr", "policy", "assume_role", "assumerole", "public", "acl",
    "encrypt", "kms", "sse", "security_group", "securitygroup", "vpc_security_group",
    "iam_instance_profile", "iaminstanceprofile", "role_arn", "rolearn", "principal",
    "permission", "ssl", "tls", "certificate", "publicly_accessible", "publiclyaccessible",
    "block_public", "blockpublic", "restrict_public", "ignore_public", "mfa", "password",
)

_TAG_KEYS = ("tags", "tags_all", "Tags", "TagSet", "TagList")


def _is_tag_path(path: str) -> bool:
    head = path.lstrip("/").split(".")[0].split("/")[0].split("[")[0]
    return head in _TAG_KEYS


def _is_security_type(rtype: str) -> bool:
    return any(rtype.startswith(h) for h in _SECURITY_TYPE_HINTS)


def _is_security_path(path: str) -> bool:
    p = path.lower()
    return any(h in p for h in _SECURITY_ATTR_HINTS)


def classify_severity(rtype: str, action: str, paths: list[str]) -> str:
    """high = security relevant, low = tags only, medium = anything else (scans also raise idle, billing ones)."""
    if _is_security_type(rtype):
        return "high"
    if any(_is_security_path(p) and not _is_tag_path(p) for p in paths):
        return "high"
    if action == CHANGED and paths and all(_is_tag_path(p) for p in paths):
        return "low"
    return "medium"


# --- data model ------------------------------------------------------------

@dataclass
class Change:
    path: str
    before: Any
    after: Any


@dataclass
class Finding:
    source: str            # "terraform" or "cloudformation"
    location: str          # directory / plan file, or stack name + region
    address: str           # Terraform address or CloudFormation logical id
    type: str              # resource type
    action: str            # CHANGED or DELETED
    changes: list[Change] = field(default_factory=list)
    physical_id: str = ""
    severity: str = "medium"
    explanation: str = ""
    tags: dict[str, str] = field(default_factory=dict, repr=False)  # for tag: ignore rules; not in reports
    import_id: str = ""    # not-in-IaC scan: the ID an import {} block takes ("" when not known)
    state_source: str = ""  # Terraform: the state this resource is in (s3://..., a local path, host/org/workspace)
    module: str = ""        # Terraform: module path (module.x.module.y), "" for the root module
    kind: str = field(default="", repr=False)  # not-in-IaC scan: "idle" or "aws-created"; not in reports


def split_address(address: str) -> list[str]:
    """Split a Terraform address on dots that are not inside [...] index keys (which may be quoted)."""
    parts, cur, depth, quoted = [], "", 0, False
    i = 0
    while i < len(address):
        ch = address[i]
        if quoted:
            cur += ch
            if ch == "\\" and i + 1 < len(address):
                cur += address[i + 1]
                i += 1
            elif ch == '"':
                quoted = False
        elif ch == '"':
            quoted, cur = True, cur + ch
        elif ch == "[":
            depth, cur = depth + 1, cur + ch
        elif ch == "]":
            depth, cur = depth - 1, cur + ch
        elif ch == "." and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
        i += 1
    if cur:
        parts.append(cur)
    return parts


def module_of(address: str) -> str:
    """module.network.module.subnets from module.network.module.subnets.aws_subnet.a[0] ("" in the root module)."""
    parts, out = split_address(address), []
    while len(parts) >= 3 and parts[0] == "module":
        out += parts[:2]
        parts = parts[2:]
    return ".".join(out)


def trace_text(f: Finding) -> str:
    """Where a Terraform resource lives: "in state: s3://b/env:/prod/terraform.tfstate, module.network"."""
    bits = ([f"in state: {f.state_source}"] if f.state_source else []) + ([f.module] if f.module else [])
    return ", ".join(bits)


def finalize(f: Finding) -> Finding:
    paths = [c.path for c in f.changes]
    f.severity = classify_severity(f.type, f.action, paths)
    if f.action == UNMANAGED and f.type == "aws_cloudwatch_log_group" and f.address.startswith("/aws/"):
        f.severity = "low"
    f.explanation = explain(f)
    return f


def _fmt_value(v: Any, limit: int = 120) -> str:
    if v is None:
        return "(none)"
    if isinstance(v, str):
        s = v
    elif isinstance(v, dict):  # drop empty fields so an added rule reads as what it allows
        s = json.dumps({k: x for k, x in v.items() if not _blank(x)}, sort_keys=True, default=str)
    else:
        s = json.dumps(v, sort_keys=True, default=str)
    return s if len(s) <= limit else s[: limit - 1] + "…"


def explain(f: Finding) -> str:
    """One plain-English guess at what happened."""
    if f.action == UNMANAGED:
        if f.type == "aws_cloudwatch_log_group" and f.address.startswith("/aws/"):
            return ("Log group an AWS service created for one of your resources; manage it in IaC if you want "
                    "retention and encryption under control.")
        return ("Exists in AWS but no state file or stack checked lists it; likely created in the console, "
                "the CLI or another tool.")
    if f.action == DELETED:
        return "Deleted outside IaC (console, CLI or another tool); the code still expects it."
    paths = [c.path for c in f.changes]
    if not paths:
        return "Changed outside IaC; the provider reported drift without attribute details."
    if all(_is_tag_path(p) for p in paths):
        added = any(c.before in (None, "", {}, []) for c in f.changes)
        removed = any(c.after in (None, "", {}, []) for c in f.changes)
        if added and not removed:
            return "Tag added outside IaC, often by a person, a cost tool or an AWS service."
        if removed and not added:
            return "Tag removed outside IaC."
        return "Tags edited outside IaC."
    joined = " ".join(_fmt_value(c.after, 10_000) for c in f.changes)
    lower_paths = " ".join(paths).lower()
    if ("ingress" in lower_paths or "egress" in lower_paths or "cidr" in lower_paths
            or f.type.startswith(("aws_security_group", "aws_vpc_security_group_", "AWS::EC2::SecurityGroup"))):
        if "0.0.0.0/0" in joined or "::/0" in joined:
            return "Security group rule edited outside IaC and now open to the internet (0.0.0.0/0 or ::/0)."
        return "Security group rules edited outside IaC, likely in the console."
    if any(h in lower_paths for h in ("password", "secret", "token")):
        return "Password or secret changed outside IaC (a console reset or manual rotation)."
    if "policy" in lower_paths or f.type.startswith(("aws_iam_", "AWS::IAM::")):
        return "Policy or permissions edited outside IaC; review who gained or lost access."
    if any(h in lower_paths for h in ("public", "acl")):
        return "Public access setting changed outside IaC."
    if any(h in lower_paths for h in ("encrypt", "kms", "sse")):
        return "Encryption setting changed outside IaC."
    names = ", ".join(sorted({p.split(".")[0].split("[")[0].lstrip("/").split("/")[0] for p in paths})[:4])
    return f"Edited outside IaC, likely a console or CLI change to {names}."


# --- Terraform / OpenTofu ---------------------------------------------------

def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    """Flatten nested dicts/lists into dotted paths: a.b[0].c -> value."""
    out: dict[str, Any] = {}
    if isinstance(value, dict):
        if not value and prefix:
            out[prefix] = {}
        for k, v in value.items():
            out.update(_flatten(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(value, list):
        if not value and prefix:
            out[prefix] = []
        # Lists of scalars compare as a whole, so reordering reads as one change.
        if value and all(not isinstance(v, (dict, list)) for v in value):
            out[prefix] = value
        else:
            for i, v in enumerate(value):
                out.update(_flatten(v, f"{prefix}[{i}]"))
    else:
        out[prefix] = value
    return out


def _sensitive_paths(mask: Any) -> set[str]:
    return {p for p, v in _flatten(mask).items() if v is True}


def _masked(path: str, sensitive: set[str]) -> bool:
    return any(path == s or path.startswith(s + ".") or path.startswith(s + "[") for s in sensitive)


def _blank(v: Any) -> bool:
    return v is None or v == {} or v == [] or v == ""


def _diff(b: Any, a: Any, path: str, out: list[Change]) -> None:
    """Walk before/after together. Added or removed list items are reported whole, empty equals missing."""
    if b == a or (_blank(b) and _blank(a)):
        return
    if isinstance(b, dict) or isinstance(a, dict):
        if (b is None or isinstance(b, dict)) and (a is None or isinstance(a, dict)):
            b, a = b or {}, a or {}
            for k in sorted(set(b) | set(a), key=str):
                _diff(b.get(k), a.get(k), f"{path}.{k}" if path else str(k), out)
            return
    if isinstance(b, list) or isinstance(a, list):
        bl = b if isinstance(b, list) else ([] if b is None else None)
        al = a if isinstance(a, list) else ([] if a is None else None)
        nested = any(isinstance(v, (dict, list)) for v in (bl or []) + (al or []))
        # Lists of scalars compare as a whole, so a reorder or one new CIDR reads as one change.
        if bl is not None and al is not None and nested:
            for i in range(max(len(bl), len(al))):
                if i < len(bl) and i < len(al):
                    _diff(bl[i], al[i], f"{path}[{i}]", out)
                else:  # whole item added or removed
                    out.append(Change(f"{path}[{i}]", bl[i] if i < len(bl) else None, al[i] if i < len(al) else None))
            return
    out.append(Change(path, None if _blank(b) else b, None if _blank(a) else a))


def _drop_mirrored_tags_all(changes: list[Change]) -> list[Change]:
    """tags_all is tags plus provider default_tags, so one tag edit shows as tags.X and tags_all.X.
    Drop the tags_all row only when tags has the same key with the same before/after;
    a tags_all key with no tags row (a default_tags key) stays."""
    tag_rows = {c.path[len("tags"):]: (c.before, c.after) for c in changes
                if c.path == "tags" or c.path.startswith("tags.")}
    if not tag_rows:
        return changes
    return [c for c in changes
            if not ((c.path == "tags_all" or c.path.startswith("tags_all."))
                    and tag_rows.get(c.path[len("tags_all"):], object()) == (c.before, c.after))]


def diff_attributes(before: Any, after: Any, before_sensitive: Any = None,
                    after_sensitive: Any = None) -> list[Change]:
    changes: list[Change] = []
    _diff(dict(before or {}), dict(after or {}), "", changes)
    changes = _drop_mirrored_tags_all(changes)
    sensitive = _sensitive_paths(before_sensitive or {}) | _sensitive_paths(after_sensitive or {})
    for c in changes:
        if _masked(c.path, sensitive):
            c.before, c.after = "(sensitive)", "(sensitive, changed)"
    return changes


def _str_tags(raw: Any) -> dict[str, str]:
    return {str(k): str(v) for k, v in raw.items()} if isinstance(raw, dict) else {}


def parse_plan_json(plan: dict, location: str = "") -> list[Finding]:
    """Parse `terraform/tofu show -json <planfile>` output (the resource_drift list)."""
    findings = []
    for rc in plan.get("resource_drift") or []:
        ch = rc.get("change") or {}
        actions = ch.get("actions") or []
        if actions in (["no-op"], ["read"]) or not actions:
            continue
        action = DELETED if "delete" in actions and not ch.get("after") else CHANGED
        changes = [] if action == DELETED else diff_attributes(
            ch.get("before"), ch.get("after"), ch.get("before_sensitive"), ch.get("after_sensitive"))
        if action == CHANGED and not changes:
            continue
        before = ch.get("before") or {}
        address = rc.get("address", "")
        findings.append(finalize(Finding(
            source="terraform", location=location, address=address,
            type=rc.get("type", ""), action=action, changes=changes,
            physical_id=str(before.get("arn") or before.get("id") or ""),
            tags=_str_tags(before.get("tags_all") or before.get("tags")),
            module=rc.get("module_address") or module_of(address),
        )))
    return findings


def parse_json_log(lines: Iterable[str], location: str = "") -> list[Finding]:
    """Parse the streaming `plan -json` log. It names drifted resources but has no attribute values."""
    findings = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("type") != "resource_drift":
            continue
        ch = msg.get("change") or {}
        res = ch.get("resource") or {}
        action = DELETED if ch.get("action") == "delete" else CHANGED
        findings.append(finalize(Finding(
            source="terraform", location=location, address=res.get("addr", ""),
            type=res.get("resource_type", ""), action=action,
            module=res.get("module") or module_of(res.get("addr", "")),
        )))
    return findings


def load_plan_file(path: str) -> list[Finding]:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return parse_json_log(text.splitlines(), location=path)
    if isinstance(data, dict) and ("resource_drift" in data or "format_version" in data):
        return parse_plan_json(data, location=path)
    if isinstance(data, dict) and data.get("type"):
        return parse_json_log(text.splitlines(), location=path)
    raise ValueError(f"{path} does not look like plan JSON (expected `show -json` output)")


def find_tf_binary(preferred: str | None = None) -> str:
    for name in ([preferred] if preferred else ["tofu", "terraform"]):
        if name and shutil.which(name):
            return name
    raise RuntimeError("Neither `tofu` nor `terraform` was found on PATH (or the one you asked for).")


def run_terraform(directory: str, binary: str | None = None, extra_args: list[str] | None = None,
                  runner=subprocess.run, profile: str | None = None) -> list[Finding]:
    """Refresh-only plan into a temporary file, then `show -json`. Never applies, never takes the state lock."""
    tf = find_tf_binary(binary)
    # --profile is passed to the AWS provider as AWS_PROFILE; other clouds use their own env or config.
    env = {**os.environ, "AWS_PROFILE": profile} if profile else None
    if not os.path.isdir(os.path.join(directory, ".terraform")):
        raise RuntimeError(f"{directory} is not initialised. Run `{tf} init` there first (it does not touch state).")
    with tempfile.TemporaryDirectory(prefix="drift-report-") as tmp:
        planfile = os.path.join(tmp, "refresh.tfplan")
        cmd = [tf, f"-chdir={directory}", "plan", "-refresh-only", "-lock=false", "-input=false",
               "-no-color", f"-out={planfile}", *(extra_args or [])]
        proc = runner(cmd, capture_output=True, text=True, env=env)
        if proc.returncode != 0:
            raise RuntimeError(f"`{' '.join(cmd)}` failed:\n{proc.stderr or proc.stdout}")
        show = runner([tf, f"-chdir={directory}", "show", "-json", planfile], capture_output=True, text=True, env=env)
        if show.returncode != 0:
            raise RuntimeError(f"`{tf} show -json` failed:\n{show.stderr or show.stdout}")
    return parse_plan_json(json.loads(show.stdout), location=directory)


def _current_workspace(directory: str) -> str:
    if os.environ.get("TF_WORKSPACE"):
        return os.environ["TF_WORKSPACE"]
    try:
        with open(os.path.join(directory, ".terraform", "environment"), encoding="utf-8") as fh:
            return fh.read().strip() or "default"
    except OSError:
        return "default"


def _shown_path(path: str) -> str:
    """A path relative to the current directory when it is under it, so reports never show a home directory."""
    rel = os.path.relpath(path)
    return path if rel.startswith("..") else rel


def state_source_of(directory: str) -> str:
    """The state a Terraform directory's current workspace uses, from its backend (no state is read)."""
    import aws_inventory as inv_mod

    try:
        backend = inv_mod.terraform_backend(directory)
    except (OSError, ValueError):
        return ""
    if not backend:
        return ""
    kind, ws = backend.get("type", ""), _current_workspace(directory)
    if kind == "s3" and backend.get("bucket") and backend.get("key"):
        prefix = (backend.get("workspace_key_prefix") or "env:").strip("/")
        key = backend["key"] if ws == "default" else f"{prefix}/{ws}/{backend['key']}"
        return f"s3://{backend['bucket']}/{key}"
    if kind == "local":
        path = backend.get("path") or "terraform.tfstate"
        if ws != "default":
            path = os.path.join(backend.get("workspace_dir") or "terraform.tfstate.d", ws, os.path.basename(path))
        return _shown_path(os.path.normpath(os.path.join(directory, path)))
    if kind in ("cloud", "remote"):
        host = backend.get("hostname") or "app.terraform.io"
        org = backend.get("organization") or os.environ.get("TF_CLOUD_ORGANIZATION") or ""
        spaces = backend.get("workspaces") or {}
        name = spaces.get("name") or (f"{spaces['prefix']}{ws}" if spaces.get("prefix") else ws)
        return f"{host}/{org}/{name}"
    if kind == "gcs" and backend.get("bucket"):
        prefix = (backend.get("prefix") or "").strip("/")
        return f"gs://{backend['bucket']}/{prefix + '/' if prefix else ''}{ws}.tfstate"
    if kind == "azurerm" and backend.get("container_name") and backend.get("key"):
        key = backend["key"] + ("" if ws == "default" else f"env:{ws}")
        return f"azurerm://{backend.get('storage_account_name', '')}/{backend['container_name']}/{key}"
    return f"{kind} backend" + ("" if ws == "default" else f" (workspace {ws})")


# --- CloudFormation -------------------------------------------------------

_LISTABLE = ["CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "IMPORT_COMPLETE",
             "IMPORT_ROLLBACK_COMPLETE"]


def _maybe_json(v: Any) -> Any:
    if isinstance(v, str):
        try:
            return json.loads(v)
        except (json.JSONDecodeError, ValueError):
            return v
    return v


def list_stacks(cfn) -> list[str]:
    names = []
    for page in cfn.get_paginator("list_stacks").paginate(StackStatusFilter=_LISTABLE):
        for s in page.get("StackSummaries", []):
            if not s.get("ParentId"):  # nested stacks are checked through their root
                names.append(s["StackName"])
    return names


def detect_drift(cfn, stack: str, timeout: float = 600, poll: float = 5, sleep=time.sleep,
                 problems: list[str] | None = None) -> str:
    """Start a drift check and wait. Returns the stack drift status."""
    det_id = cfn.detect_stack_drift(StackName=stack)["StackDriftDetectionId"]
    waited = 0.0
    while True:
        st = cfn.describe_stack_drift_detection_status(StackDriftDetectionId=det_id)
        status = st.get("DetectionStatus")
        if status == "DETECTION_COMPLETE":
            return st.get("StackDriftStatus", "UNKNOWN")
        if status == "DETECTION_FAILED":
            # Partial results are still useful (some resource types can't be checked).
            reason = st.get("DetectionStatusReason", "")
            print(f"warning: drift detection for {stack} failed partly: {reason}", file=sys.stderr)
            if problems is not None:
                problems.append(f"drift detection for {stack} failed partly ({reason or 'no reason given'})")
            return st.get("StackDriftStatus", "UNKNOWN")
        if waited >= timeout:
            raise TimeoutError(f"drift detection for {stack} did not finish in {timeout:.0f}s")
        sleep(poll)
        waited += poll


def stack_findings(cfn, stack: str, region: str = "") -> list[Finding]:
    findings = []
    kwargs = {"StackName": stack, "StackResourceDriftStatusFilters": ["MODIFIED", "DELETED"]}
    while True:
        resp = cfn.describe_stack_resource_drifts(**kwargs)
        for d in resp.get("StackResourceDrifts", []):
            action = DELETED if d.get("StackResourceDriftStatus") == "DELETED" else CHANGED
            changes = [Change(p.get("PropertyPath", ""), _maybe_json(p.get("ExpectedValue")),
                              _maybe_json(p.get("ActualValue")))
                       for p in d.get("PropertyDifferences", [])]
            findings.append(finalize(Finding(
                source="cloudformation", location=f"{stack} ({region})" if region else stack,
                address=d.get("LogicalResourceId", ""), type=d.get("ResourceType", ""),
                action=action, changes=changes, physical_id=d.get("PhysicalResourceId", ""),
            )))
        token = resp.get("NextToken")
        if not token:
            return findings
        kwargs["NextToken"] = token


def run_cloudformation(cfn, stacks: list[str] | None, region: str = "", timeout: float = 600,
                       sleep=time.sleep, log=print,
                       problems: list[str] | None = None) -> tuple[list[Finding], dict[str, str]]:
    problems = [] if problems is None else problems
    names = stacks or list_stacks(cfn)
    findings: list[Finding] = []
    statuses: dict[str, str] = {}
    for name in names:
        log(f"checking stack {name} …", file=sys.stderr)
        try:
            statuses[name] = detect_drift(cfn, name, timeout=timeout, sleep=sleep, problems=problems)
        except Exception as exc:  # keep going; one bad stack shouldn't sink the report
            statuses[name] = f"ERROR: {exc}"
            problems.append(f"stack {name} was not checked ({exc})")
            continue
        findings.extend(stack_findings(cfn, name, region))
    return findings, statuses


def cfn_client(profile: str | None, region: str | None, args=None):
    session = aws_session(profile, region)
    if args is not None and getattr(args, "role_arn", None):
        session = assume_role(session, args.role_arn, args.external_id, args.role_session_name)
    import aws_inventory as inv_mod

    inv_mod.check_regions(session, [session.region_name])
    return session.client("cloudformation"), session.region_name


# --- ignore rules ------------------------------------------------------------

def apply_ignore(report: "Report", rules: list, files: list[str] | None = None) -> "Report":
    """Move findings that .driftignore rules cover out of the report, and drop ignored attributes."""
    import drift_ignore as ignore

    report.ignore_files = list(files or [])
    if not rules:
        return report
    kept = []
    for f in report.findings:
        outcome = ignore.evaluate(rules, f)
        if outcome.ignored:
            report.ignored.append((f, outcome.rule))
            continue
        if outcome.dropped_paths:
            f.changes = [c for c in f.changes if c.path not in outcome.dropped_paths]
            finalize(f)
        kept.append(f)
    report.findings = kept
    if report.eol is not None:
        eol_kept = []
        for f in report.eol.findings:
            outcome = ignore.evaluate(rules, f)
            if outcome.ignored:
                report.ignored.append((f, outcome.rule))
            else:
                eol_kept.append(f)
        report.eol.findings = eol_kept
    if report.coverage:
        report.coverage["not_in_iac"] = len(kept)
        report.coverage["ignored"] = len(report.ignored)
    return report


# --- reports ---------------------------------------------------------------

@dataclass
class Report:
    findings: list[Finding]
    source: str
    target: str
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    checked: dict[str, str] = field(default_factory=dict)  # CloudFormation stack -> drift status
    coverage: dict[str, Any] = field(default_factory=dict)  # not-in-IaC scan totals
    ignored: list[tuple[Finding, str]] = field(default_factory=list)  # (finding, .driftignore line)
    ignore_files: list[str] = field(default_factory=list)
    ignore_text: str = ""  # the rules as written, kept when a new .driftignore is generated
    incomplete: list[str] = field(default_factory=list)  # what the scan couldn't read
    code_dir: str = ""  # Terraform directory, to point SARIF results at the code declaring a resource
    eol: Any = None  # eol.EolResult when the end-of-life check ran
    eol_only: bool = False  # --eol-only: no not-in-IaC listing

    def incomplete_line(self) -> str:
        if not self.incomplete:
            return ""
        shown = "; ".join(self.incomplete[:5]) + (f"; and {len(self.incomplete) - 5} more" if len(self.incomplete) > 5 else "")
        effect = ("Resources there may be missing from this report, or listed as not in IaC when they are."
                  if self.source == "aws" else "Drift there may be missing from this report.")
        return f"Incomplete scan: {shown}. {effect}"

    def ignored_line(self) -> str:
        if not self.ignored:
            return ""
        n = len(self.ignored)
        return (f"{n} finding{'' if n == 1 else 's'} ignored by {', '.join(self.ignore_files) or FILENAME_HINT}"
                " (run with --no-ignore to see everything).")

    def noun(self, n: int | None = None) -> str:
        if self.eol_only:
            n = len(self.eol.findings) if n is None else n
            return f"{n} resource{'' if n == 1 else 's'} past or near end of life"
        n = len(self.findings) if n is None else n
        if self.source == "aws":
            return f"{n} resource{'' if n == 1 else 's'} not in IaC"
        return f"{n} drifted resource{'' if n == 1 else 's'}"

    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in SEVERITIES}
        for f in (self.eol.findings if self.eol_only else self.findings):
            c[f.severity] += 1
        return c

    def sorted(self) -> list[Finding]:
        order = {s: i for i, s in enumerate(SEVERITIES)}
        return sorted(self.findings, key=lambda f: (order[f.severity], f.location, f.address))

    def pr_line(self) -> str:
        n = len(self.findings)  # changed and deleted drift both map to a fix PR
        if not n:
            return ""
        noun = "this" if n == 1 else f"{n} of these"
        if self.source == "aws":
            return (f"{noun[0].upper() + noun[1:]} can be adopted into Terraform with review and approval "
                    f"in OrchesTerra ({PRODUCT_URL}).")
        return f"{noun[0].upper() + noun[1:]} can be fixed with a pull request in OrchesTerra ({PRODUCT_URL})."


def _changes_text(f: Finding, sep: str = "; ") -> str:
    if f.action == DELETED:
        return "resource no longer exists"
    if f.action == UNMANAGED:
        return f"{f.physical_id} is in no state file or stack checked"
    if not f.changes:
        return "(no attribute details)"
    return sep.join(f"{c.path}: {_fmt_value(c.before)} → {_fmt_value(c.after)}" for c in f.changes)


def _md_cell(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def _idle_where(i: dict[str, Any]) -> str:
    if not i.get("in_iac"):
        return ""
    bits = ([f"in state: {i['state_source']}"] if i.get("state_source") else []) + ([i["module"]] if i.get("module") else [])
    return f" (in IaC{': ' + ', '.join(bits) if bits else ''})"


def coverage_line(cov: dict[str, Any]) -> str:
    pct = cov.get("percent_in_iac")
    parts = ([f"{pct:g}% in IaC"] if pct is not None else []) + [
        f"{cov.get('listed', 0)} resources listed", f"{cov.get('in_iac', 0)} in IaC",
        f"{cov.get('not_in_iac', 0)} not in IaC", f"{cov.get('aws_owned_skipped', 0)} AWS-owned skipped"]
    if cov.get("types_not_listed"):
        parts.append(f"{cov['types_not_listed']} type/region pairs could not be listed (see JSON output)")
    sources = cov.get("iac_sources") or []
    line = "Coverage: " + " · ".join(parts) + (f". Compared with: {', '.join(sources)}." if sources else ".")
    dups = cov.get("duplicate_imports") or []
    if dups:
        line += (f" Warning: {len(dups)} resource{'s are' if len(dups) != 1 else ' is'} in state at more than one "
                 f"address (" + "; ".join(f"{d['type']} {d['id']}" for d in dups[:5]) + (", ..." if len(dups) > 5 else "")
                 + "); see the JSON output.")
    idle = cov.get("idle") or []
    if idle:
        line += (" Idle and still billing: " + "; ".join(
            f"{i['type']} {i['id']}{_idle_where(i)}" for i in idle[:5])
                 + (", ..." if len(idle) > 5 else "") + "; see the JSON output.")
    return line


def render_markdown(r: Report) -> str:
    c = r.counts()
    if r.eol_only:
        import eol
        return "\n".join([f"# End of life: {r.target}", "", f"Source: AWS account scan · Generated: {r.generated_at}"]
                         + (["", r.ignored_line()] if r.ignored else []) + eol.markdown(r.eol)[2:]
                         + ["", "---", FOOTER, ""])
    out = [f"# {'Not in IaC' if r.source == 'aws' else 'Drift report'}: {r.target}", "",
           f"Source: {'AWS account scan' if r.source == 'aws' else r.source} · Generated: {r.generated_at}", ""]
    if r.incomplete:
        out += [f"> **Warning:** {_md_cell(r.incomplete_line())}", ""]
    if r.findings:
        out.append(f"**{r.noun()}** · high: {c['high']} · medium: {c['medium']} · low: {c['low']}")
    elif r.source == "aws":
        out.append("**Everything listed is in IaC.**" if r.coverage.get("listed", 1) else "**No resources found.**")
    else:
        out.append("**No drift found.** Everything matches the code.")
    if r.coverage:
        out += ["", coverage_line(r.coverage)]
    if r.checked:
        out += ["", "Stacks checked: " + ", ".join(f"{k} ({v})" for k, v in r.checked.items())]
    if r.ignored:
        out += ["", r.ignored_line()]
    if r.findings and r.source == "aws":
        out += ["", "| Severity | Resource | Region | Type | ID or ARN | What probably happened |", "|---|---|---|---|---|---|"]
        for f in r.sorted():
            out.append("| " + " | ".join(_md_cell(x) for x in (
                f.severity.upper(), f.address, f.location, f.type, f.physical_id, f.explanation)) + " |")
        out += ["", r.pr_line()]
    elif r.findings:
        out += ["", "| Severity | Resource | Type | Action | Changes (before → after) | What probably happened |",
                "|---|---|---|---|---|---|"]
        for f in r.sorted():
            res = f.address + (f" ({f.location})" if r.source in ("cloudformation", "aws") else "")
            if trace_text(f):
                res += f"<br>{trace_text(f)}"
            out.append("| " + " | ".join(_md_cell(x) for x in (
                f.severity.upper(), res, f.type, f.action, _changes_text(f, "<br>"), f.explanation)) + " |")
        out += ["", r.pr_line()]
    if r.eol is not None:
        import eol
        out += eol.markdown(r.eol)
    out += ["", "---", FOOTER, ""]
    return "\n".join(out)


CSV_FIELDS = ["severity", "source", "location", "address", "type", "action", "physical_id",
              "attribute", "before", "after", "what_probably_happened", "state_source", "module"]


def render_csv(r: Report) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_FIELDS)
    for f in r.sorted():
        rows = f.changes or [Change("", None, None)]
        for ch in rows:
            w.writerow([f.severity, f.source, f.location, f.address, f.type, f.action, f.physical_id,
                        ch.path, "" if ch.before is None else _fmt_value(ch.before, 10_000),
                        "" if ch.after is None else _fmt_value(ch.after, 10_000), f.explanation,
                        f.state_source, f.module])
    if r.eol is not None:
        import eol
        w.writerows(eol.csv_rows(r.eol))
    w.writerow([])
    if r.ignored:
        w.writerow([f"# {r.ignored_line()}"])
    w.writerow([f"# {FOOTER}"])
    return buf.getvalue()


def _finding_json(f: Finding) -> dict[str, Any]:
    d = asdict(f)
    d.pop("tags", None)
    d.pop("kind", None)
    if not d["import_id"]:
        d.pop("import_id")
    if f.source != "terraform":  # state and module only mean something for Terraform resources
        d.pop("state_source")
        d.pop("module")
    return d


def _eol_json(r: Report) -> dict[str, Any] | None:
    if r.eol is None:
        return None
    import eol
    return eol.json_section(r.eol)


def render_json(r: Report) -> str:
    doc = {
        "tool": "cloud-drift-report", "version": __version__, "source": r.source, "target": r.target,
        "schema": 1,
        "generated_at": r.generated_at,
        "summary": {"total": len(r.findings), **r.counts(), **({"ignored": len(r.ignored)} if r.ignored else {})},
        "stacks_checked": r.checked or None,
        "coverage": r.coverage or None,
        "incomplete": r.incomplete or None,
        "findings": [_finding_json(f) for f in r.sorted()],
        "end_of_life": _eol_json(r),
        "ignored": [{"type": f.type, "address": f.address, "physical_id": f.physical_id, "location": f.location,
                     "rule": rule} for f, rule in r.ignored] or None,
        "note": r.pr_line() or None, "footer": FOOTER,
    }
    return json.dumps({k: v for k, v in doc.items() if v is not None}, indent=2, default=str) + "\n"


_HTML_CSS = """
:root{--bg:#f7f8fa;--card:#fff;--ink:#16181d;--muted:#5d6470;--line:#e3e6eb;--high:#c62828;--high-bg:#fdecea;
--med:#b26a00;--med-bg:#fff4e0;--low:#2e6b3a;--low-bg:#e8f5ea;--accent:#3949ab;--code:#f1f3f6}
@media (prefers-color-scheme:dark){:root{--bg:#111318;--card:#1a1d24;--ink:#e8eaee;--muted:#9aa1ad;--line:#2b2f38;
--high:#ff8a80;--high-bg:#3a1d1d;--med:#ffc266;--med-bg:#3a2e17;--low:#8fd19e;--low-bg:#1b3222;--accent:#9fa8ff;--code:#22262e}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:1200px;margin:0 auto;padding:32px 16px 48px}h1{font-size:24px;margin:0 0 4px}
.meta{color:var(--muted);margin:0 0 24px}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:24px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.tile b{display:block;font-size:28px;font-variant-numeric:tabular-nums}.tile span{color:var(--muted);font-size:13px}
.tile.high b{color:var(--high)}.tile.medium b{color:var(--med)}.tile.low b{color:var(--low)}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}.filters button{border:1px solid var(--line);background:var(--card);
color:var(--ink);border-radius:999px;padding:4px 12px;font:inherit;font-size:13px;cursor:pointer}
.filters button[aria-pressed=true]{background:var(--ink);color:var(--bg);border-color:var(--ink)}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;min-width:760px}th,td{text-align:left;vertical-align:top;padding:10px 12px;border-bottom:1px solid var(--line)}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-weight:600}tr:last-child td{border-bottom:0}
.sev{display:inline-block;font-size:12px;font-weight:600;border-radius:4px;padding:2px 8px}
.sev.high{color:var(--high);background:var(--high-bg)}.sev.medium{color:var(--med);background:var(--med-bg)}.sev.low{color:var(--low);background:var(--low-bg)}
code{font:12.5px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--code);border-radius:4px;padding:1px 4px;word-break:break-word}
ul.ch{margin:0;padding:0;list-style:none}ul.ch li{margin:0 0 4px}.arrow{color:var(--muted)}.type{color:var(--muted);font-size:13px}
.warn{background:var(--med-bg);color:var(--ink);border:1px solid var(--med);border-radius:10px;padding:12px 16px;margin:0 0 24px}
.ok{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:20px}
.note{margin:16px 0 0}.note a,footer a{color:var(--accent)}footer{margin-top:32px;padding-top:16px;border-top:1px solid var(--line);color:var(--muted);font-size:14px}
"""

_HTML_JS = """
document.querySelectorAll('.filters button').forEach(b=>b.addEventListener('click',()=>{
document.querySelectorAll('.filters button').forEach(x=>x.setAttribute('aria-pressed',x===b));
const s=b.dataset.sev;document.querySelectorAll('tbody tr').forEach(r=>{r.hidden=s!=='all'&&r.dataset.sev!==s;});}));
"""


def _linkify(text: str) -> str:
    url = html.escape(PRODUCT_URL)
    return html.escape(text).replace(url, f'<a href="{url}">orchesterra.in</a>')


def render_html(r: Report) -> str:
    e = html.escape
    c = r.counts()
    rows = []
    for f in r.sorted():
        if f.action == DELETED:
            ch = "<em>resource no longer exists</em>"
        elif f.action == UNMANAGED:
            ch = f"<code>{e(f.physical_id)}</code>"
        elif not f.changes:
            ch = "<em>no attribute details</em>"
        else:
            ch = "<ul class=ch>" + "".join(
                f"<li><code>{e(x.path)}</code><br><code>{e(_fmt_value(x.before, 300))}</code> "
                f"<span class=arrow>→</span> <code>{e(_fmt_value(x.after, 300))}</code></li>" for x in f.changes) + "</ul>"
        where = f"<div class=type>{e(f.location)}</div>" if r.source in ("cloudformation", "aws") else ""
        if trace_text(f):
            where += f"<div class=type>{e(trace_text(f))}</div>"
        rows.append(
            f"<tr data-sev={f.severity}><td><span class='sev {f.severity}'>{f.severity.upper()}</span></td>"
            f"<td><code>{e(f.address)}</code>{where}<div class=type>{e(f.type)}</div></td>"
            f"<td>{e(f.action)}</td><td>{ch}</td><td>{e(f.explanation)}</td></tr>")
    checked = f"<p class=meta>{e(coverage_line(r.coverage))}</p>" if r.coverage else ""
    if r.checked:
        checked += "<p class=meta>Stacks checked: " + ", ".join(f"{e(k)} ({e(v)})" for k, v in r.checked.items()) + "</p>"
    if r.ignored:
        checked += f"<p class=meta>{e(r.ignored_line())}</p>"
    if r.findings:
        body = (
            "<div class=tiles>"
            f"<div class=tile><b>{len(r.findings)}</b><span>{e(r.noun().split(' ', 1)[1])}</span></div>"
            + "".join(f"<div class='tile {s}'><b>{c[s]}</b><span>{s}</span></div>" for s in SEVERITIES)
            + "</div>" + checked +
            "<div class=filters role=group aria-label='Filter by severity'>"
            "<button data-sev=all aria-pressed=true>All</button>"
            + "".join(f"<button data-sev={s} aria-pressed=false>{s.title()}</button>" for s in SEVERITIES) +
            "</div><div class=wrap><table><thead><tr><th>Severity</th><th>Resource</th><th>Action</th>"
            + ("<th>ID or ARN</th>" if r.source == "aws" else "<th>Changes (before → after)</th>")
            + "<th>What probably happened</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table></div>"
            f"<p class=note>{_linkify(r.pr_line())}</p>")
    else:
        ok = (("<strong>Everything listed is in IaC.</strong>" if r.coverage.get("listed", 1)
               else "<strong>No resources found.</strong>") if r.source == "aws"
              else "<strong>No drift found.</strong> Everything matches the code.")
        body = checked + f"<div class=ok>{ok}</div>"
    if r.eol is not None:
        import eol
        section = eol.html_section(r.eol)
        body = checked + section if r.eol_only else body + section
    footer_html = _linkify(FOOTER)
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>{'End-of-life report' if r.eol_only else 'Not-in-IaC report' if r.source == 'aws' else 'Drift report'}</title><style>{_HTML_CSS}</style></head><body><main>"
        f"<h1>{'End of life' if r.eol_only else 'Not in IaC' if r.source == 'aws' else 'Drift report'}: {e(r.target)}</h1>"
        f"<p class=meta>{e('AWS account scan' if r.source == 'aws' else r.source.title())} · generated {e(r.generated_at)} · read-only check by cloud-drift-report {__version__}</p>"
        + (f"<p class=warn role=alert><strong>Warning:</strong> {e(r.incomplete_line())}</p>" if r.incomplete else "")
        + f"{body}<footer>{footer_html}</footer></main><script>{_HTML_JS}</script></body></html>\n")


def render_driftignore(r: Report) -> str:
    """One rule per finding, to accept everything found today and report only what's new later."""
    import drift_ignore as ignore

    out = [f"# .driftignore generated by cloud-drift-report {__version__} on {r.generated_at}",
           f"# from {r.target}. Delete a line to report that resource again.", ""]
    if r.ignore_text.strip():
        out += [f"# Rules already in {', '.join(r.ignore_files)}:", r.ignore_text.rstrip("\n"), "",
                "# Found in this run:" if r.findings else "# Nothing new found in this run."]
    for f in r.sorted():
        if f.action == CHANGED and f.changes:
            what = ", ".join(c.path for c in f.changes[:3]) + (" …" if len(f.changes) > 3 else "")
        else:
            what = f.action
        out.append(f"# {f.severity}: {f.address} ({what})")
        rid = f.physical_id or f.address
        if rid.startswith("arn:"):  # the short id reads better and still matches (see candidate_ids)
            rid = ignore.short_id(rid)
        elif "://" in rid and f.address:  # a queue's name or logical id rather than its URL
            rid = f.address
        out.append(f"{f.type}.{ignore.escape_id(rid)}")
    return "\n".join(out) + "\n"


def _tf_name(text: str, taken: set[str]) -> str:
    """A Terraform resource name from a display name: lowercase letters, digits and underscores, unique."""
    base = re.sub(r"[^a-z0-9_]+", "_", text.rsplit("/", 1)[-1].rsplit(":", 1)[-1].lower()).strip("_") or "resource"
    if not base[0].isalpha() and base[0] != "_":
        base = f"r_{base}"
    name, n = base, 2
    while name in taken:
        name, n = f"{base}_{n}", n + 1
    taken.add(name)
    return name


def render_imports(r: Report) -> str:
    """Terraform import {} blocks for every resource not in IaC, to generate code with -generate-config-out."""
    out = [f"# Import blocks generated by cloud-drift-report {__version__} on {r.generated_at}",
           f"# for {r.target}: resources no state file or stack accounts for.", ""]
    if r.source != "aws":
        return "\n".join(out + ["# Import blocks come from the not-in-IaC scan (cloud-drift-report unmanaged)."]) + "\n"
    if not r.findings:
        return "\n".join(out + ["# Nothing to import: everything listed is in IaC."]) + "\n"
    out += ["# Put this file in your Terraform directory, then run", "#   terraform plan -generate-config-out=generated.tf",
            "# and review generated.tf before you apply. Delete the blocks you don't want to manage."]
    regions = sorted({f.location for f in r.findings if f.location != "global"})
    if len(regions) > 1:
        out.append(f"# Blocks for regions other than your provider's need provider = aws.<alias> (one alias per region).")
    taken: dict[str, set[str]] = {}
    for region in sorted({f.location for f in r.findings}, key=lambda x: (x == "global", x)):
        out += ["", f"# --- {region} ---"]
        for f in sorted((f for f in r.findings if f.location == region), key=lambda f: (f.type, f.address)):
            to = f"{f.type}.{_tf_name(f.address or f.import_id or f.physical_id, taken.setdefault(f.type, set()))}"
            block = ["import {", f"  to = {to}", f"  id = {json.dumps(f.import_id or f.physical_id)}", "}"]
            if f.import_id:
                out += [""] + block
            else:
                out += ["", f"# {f.type} {f.address}: import ID not known (listed as {f.physical_id}); see the resource's",
                        "# Import section in the Terraform AWS provider docs, fix the id, then uncomment:"]
                out += ["# " + line for line in block]
    return "\n".join(out) + "\n"


# --- SARIF ------------------------------------------------------------------

REPO_URL = "https://github.com/orchesterra/cloud-drift-report"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_LEVELS = {"high": "error", "medium": "warning", "low": "note"}

# One rule per kind of finding: (id, name, short description, full description, default level).
SARIF_RULES = [
    ("drift/changed-outside-iac", "ChangedOutsideIaC", "Resource changed outside IaC",
     "The live resource no longer matches its Terraform state or CloudFormation template: someone changed it "
     "in the console, CLI or another tool. Put the change in code, or revert it.", "warning"),
    ("drift/deleted-outside-iac", "DeletedOutsideIaC", "Resource deleted outside IaC",
     "The resource is in Terraform state or a CloudFormation stack but no longer exists in the cloud.", "warning"),
    ("drift/not-in-iac", "NotInIaC", "Resource not in IaC",
     "The resource exists in the AWS account but no Terraform state file or CloudFormation stack checked "
     "lists it. Import it into Terraform, or delete it if nobody needs it.", "warning"),
    ("drift/idle-not-in-iac", "IdleNotInIaC", "Idle resource not in IaC",
     "The resource is in no IaC and looks idle while it still bills.", "error"),
    ("drift/aws-created", "AwsCreatedResource", "Resource AWS created itself",
     "AWS created this resource (a default VPC, a service-linked role, ...). Reported because of --strict.", "note"),
    ("drift/idle-in-iac", "IdleInIaC", "Idle resource in IaC",
     "The resource is managed by IaC but looks idle while it still bills.", "warning"),
    ("drift/end-of-life", "EndOfLife", "Version past or near end of life",
     "The resource runs an engine, Kubernetes or runtime version that AWS has retired, bills extended support "
     "for, or retires within 90 days. Upgrade it.", "warning"),
]


def sarif_rule_id(f: Finding) -> str:
    if f.action == CHANGED:
        return "drift/changed-outside-iac"
    if f.action == DELETED:
        return "drift/deleted-outside-iac"
    return {"idle": "drift/idle-not-in-iac", "aws-created": "drift/aws-created"}.get(f.kind, "drift/not-in-iac")


def _uri(path: str) -> str:
    """A path relative to the current directory (the repository root in CI) with forward slashes, else a file URI."""
    rel = os.path.relpath(os.path.abspath(path))
    if rel.startswith(".."):
        from pathlib import Path
        return Path(os.path.abspath(path)).as_uri()
    return rel.replace(os.sep, "/")


def _module_dirs(code_dir: str) -> dict[str, str]:
    """Module key (network.subnets) -> directory, from `terraform init`'s .terraform/modules/modules.json."""
    try:
        with open(os.path.join(code_dir, ".terraform", "modules", "modules.json"), encoding="utf-8") as fh:
            mods = (json.load(fh) or {}).get("Modules") or []
    except (OSError, ValueError):
        return {}
    return {m.get("Key", ""): os.path.join(code_dir, m["Dir"]) for m in mods if m.get("Dir")}


def _declarations(directory: str, rtype: str, name: str, recursive: bool = False) -> list[tuple[str, int]]:
    pattern = re.compile(r'^[ \t]*resource\s+"' + re.escape(rtype) + r'"\s+"' + re.escape(name) + r'"', re.M)
    if recursive:
        files = []
        for root, dirs, names in os.walk(directory):
            dirs[:] = [d for d in dirs if not d.startswith(".")]  # not .terraform or .git
            files += [os.path.join(root, n) for n in names if n.endswith(".tf")]
    else:
        files = [os.path.join(directory, n) for n in sorted(os.listdir(directory)) if n.endswith(".tf")] \
            if os.path.isdir(directory) else []
    found = []
    for path in sorted(files):
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except (OSError, UnicodeDecodeError):
            continue
        for m in pattern.finditer(text):
            found.append((path, text.count("\n", 0, m.start()) + 1))
    return found


def find_declaration(code_dir: str, address: str, modules: dict[str, str] | None = None) -> tuple[str, int] | None:
    """(file, line) of the `resource "type" "name"` block a Terraform address comes from, when it can be found."""
    if not code_dir or not os.path.isdir(code_dir):
        return None
    parts = split_address(address)
    path: list[str] = []
    while len(parts) >= 3 and parts[0] == "module":
        path.append(parts[1].split("[", 1)[0])
        parts = parts[2:]
    if len(parts) != 2 or parts[0] == "data":
        return None
    rtype, name = parts[0], parts[1].split("[", 1)[0]
    if not path:
        hits = _declarations(code_dir, rtype, name)
        return hits[0] if len(hits) == 1 else None
    modules = _module_dirs(code_dir) if modules is None else modules
    key = ".".join(path)
    if key in modules:
        hits = _declarations(modules[key], rtype, name)
    else:  # not initialised: accept a match anywhere under the directory only when it is the only one
        hits = _declarations(code_dir, rtype, name, recursive=True)
    return hits[0] if len(hits) == 1 else None


def _sarif_location(f: Finding, code_dir: str, modules: dict[str, str]) -> dict[str, Any]:
    logical = {"name": f.address or f.physical_id, "kind": "resource",
               "fullyQualifiedName": f.address if f.source == "terraform" else (f.physical_id or f.address)}
    region = None
    if f.source == "terraform" and (hit := find_declaration(code_dir, f.address, modules)):
        uri, region = _uri(hit[0]), {"startLine": hit[1]}
    elif f.source == "terraform" and f.state_source and "://" not in f.state_source and os.path.isfile(f.state_source):
        uri = _uri(f.state_source)
    elif f.source == "terraform" and f.location:
        uri = _uri(f.location)  # the Terraform directory or plan file checked
    else:  # nothing in the repository: a stable path naming where the resource is
        where = re.sub(r"[^A-Za-z0-9._-]+", "-", f.location or "global").strip("-") or "global"
        uri = f"{f.source}/{where}/{re.sub(r'[^A-Za-z0-9._-]+', '-', f.type) or 'resource'}"
    physical: dict[str, Any] = {"artifactLocation": {"uri": uri}}
    if region:
        physical["region"] = region
    return {"physicalLocation": physical, "logicalLocations": [logical]}


def _fingerprint(*parts: str) -> str:
    import hashlib
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


def _sarif_message(f: Finding) -> str:
    where = f" ({f.location})" if f.source in ("cloudformation", "aws") else ""
    text = f"{f.severity.upper()}: {f.address}{where} ({f.type}) {f.action}: {_changes_text(f)}."
    if trace_text(f):
        text += f" {trace_text(f)[0].upper()}{trace_text(f)[1:]}."
    return f"{text} {f.explanation}".strip()


def render_sarif(r: Report) -> str:
    """SARIF 2.1.0 for GitHub code scanning (upload with github/codeql-action/upload-sarif)."""
    index = {rid: i for i, (rid, *_rest) in enumerate(SARIF_RULES)}
    modules = _module_dirs(r.code_dir) if r.code_dir else {}
    results = []
    for f in r.sorted():
        rid = sarif_rule_id(f)
        key = ([rid, f.type, f.address, f.state_source] if f.source == "terraform"
               else [rid, f.source, f.type, f.address, f.physical_id, f.location])
        props = {"severity": f.severity, "resourceType": f.type, "address": f.address, "action": f.action}
        props.update({k: v for k, v in (("physicalId", f.physical_id), ("stateSource", f.state_source),
                                        ("module", f.module), ("location", f.location)) if v})
        results.append({
            "ruleId": rid, "ruleIndex": index[rid], "level": SARIF_LEVELS[f.severity],
            "message": {"text": _sarif_message(f)},
            "locations": [_sarif_location(f, r.code_dir, modules)],
            "partialFingerprints": {"driftFindingHash/v1": _fingerprint(*key)},
            "properties": props,
        })
    for i in (r.coverage.get("idle") or []) if r.coverage else []:
        if not i.get("in_iac"):
            continue  # already a not-in-IaC finding above
        trace = ", ".join(([f"state {i['state_source']}"] if i.get("state_source") else [])
                          + ([i["module"]] if i.get("module") else [])
                          + ([i["stack"]] if i.get("stack") else []))
        state = i.get("state_source") or ""
        if state and "://" not in state and os.path.isfile(state):
            uri = _uri(state)
        else:
            uri = f"aws/{i.get('region') or 'global'}/{i['type']}"
        rid = "drift/idle-in-iac"
        results.append({
            "ruleId": rid, "ruleIndex": index[rid], "level": "warning",
            "message": {"text": f"MEDIUM: {i['type']} {i['id']} ({i.get('region') or 'global'}) is in IaC and idle: "
                                f"{i['reason']}." + (f" In {trace}." if trace else "")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}},
                           "logicalLocations": [{"name": i.get("address") or i["id"], "kind": "resource",
                                                 "fullyQualifiedName": i["id"]}]}],
            "partialFingerprints": {"driftFindingHash/v1": _fingerprint(rid, i["type"], i["id"], i.get("region") or "")},
            "properties": {"severity": "medium", "resourceType": i["type"], "monthlyUsd": i.get("monthly_usd"),
                           **{k: i[k] for k in ("state_source", "module", "stack") if i.get(k)}},
        })
    for f in (r.eol.sorted() if r.eol is not None else []):
        rid = "drift/end-of-life"
        results.append({
            "ruleId": rid, "ruleIndex": index[rid], "level": SARIF_LEVELS[f.severity],
            "message": {"text": f"{f.severity.upper()}: {f.address} ({f.location}, {f.type}) runs {f.version}, "
                                f"{f.status}: {f.explanation}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f"aws/{f.location}/{f.type}"}},
                           "logicalLocations": [{"name": f.address, "kind": "resource",
                                                 "fullyQualifiedName": f.physical_id}]}],
            "partialFingerprints": {"driftFindingHash/v1": _fingerprint(rid, f.type, f.physical_id, f.location)},
            "properties": {"severity": f.severity, "resourceType": f.type, "status": f.status, "version": f.version,
                           "ends": f.ends, **({"monthlyUsd": round(f.monthly_usd, 2)} if f.monthly_usd is not None else {})},
        })
    rules = [{"id": rid, "name": name, "shortDescription": {"text": short}, "fullDescription": {"text": full},
              "helpUri": f"{REPO_URL}#readme", "defaultConfiguration": {"level": level},
              "properties": {"tags": ["drift", "iac"]}}
             for rid, name, short, full, level in SARIF_RULES]
    doc = {
        "$schema": SARIF_SCHEMA, "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "cloud-drift-report", "version": __version__, "semanticVersion": __version__,
                                "informationUri": REPO_URL, "rules": rules}},
            "automationDetails": {"id": f"cloud-drift-report/{r.source}/"},
            "results": results,
            "properties": {"target": r.target, "generatedAt": r.generated_at, "footer": FOOTER,
                           **({"incomplete": r.incomplete} if r.incomplete else {})},
        }],
    }
    return json.dumps(doc, indent=2, default=str) + "\n"


RENDERERS = {"md": render_markdown, "csv": render_csv, "json": render_json, "html": render_html,
             "driftignore": render_driftignore, "imports": render_imports, "sarif": render_sarif}


# --- CLI ------------------------------------------------------------------

IMPORT_URL = ("https://app.orchesterra.in/cloud-operations?section=settings&tab=import-report"
              "&utm_source=drift-skill&utm_medium=oss")


def import_hint(json_path: str) -> str:
    return (f"To see this report in OrchesTerra, drop {json_path} on {IMPORT_URL} "
            "(you upload it yourself; this tool sends nothing).")


def share_report(json_paths: list[str]) -> None:
    """--share prints how to open the report in OrchesTerra. It makes no network call and uploads nothing."""
    if json_paths:
        print(import_hint(json_paths[0]), file=sys.stderr)
    else:
        print("--share: save the report as JSON (-f json -o report.json), then drop it on "
              f"{IMPORT_URL}. Nothing was uploaded.", file=sys.stderr)


def add_role_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--role-arn", help="assume this IAM role first, to check another account (read-only role)")
    parser.add_argument("--external-id", help="external ID the role's trust policy asks for")
    parser.add_argument("--role-session-name", default="cloud-drift-report",
                        help="session name in the target account's CloudTrail (default cloud-drift-report)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cloud-drift-report",
        description="Read-only drift report for Terraform/OpenTofu (any cloud) and AWS CloudFormation, "
                    "plus AWS resources that are in no IaC at all.",
        epilog=FOOTER)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--format", "-f", choices=sorted(RENDERERS), default="md", help="report format (default md)")
    common.add_argument("--output", "-o", action="append", default=[],
                        help="write the report to this file (default stdout); may repeat, and a .md, .csv, "
                             ".json or .html extension picks that file's format (.sarif always writes SARIF)")
    common.add_argument("--fail-on-drift", action="store_true", help="exit 2 when drift is found (for CI)")
    common.add_argument("--ignore", action="append", default=[], metavar="FILE",
                        help="ignore rules (driftctl .driftignore syntax); may repeat "
                             "(default: .driftignore in --dir and in the current directory)")
    common.add_argument("--no-ignore", action="store_true", help="report everything, ignoring any .driftignore")
    common.add_argument("--share", action="store_true",
                        help="print how to open the JSON report in OrchesTerra (uploads nothing)")
    common.add_argument("--config", metavar="FILE",
                        help=f"read defaults from this file (default: {CONFIG_NAMES[0]} in --dir or the current directory)")
    common.add_argument("--no-config", action="store_true", help=f"don't read {CONFIG_NAMES[0]}")
    sub = p.add_subparsers(dest="mode", required=True)

    tf = sub.add_parser("terraform", aliases=["tf", "tofu"], parents=[common],
                        help="refresh-only plan of a Terraform/OpenTofu directory, or a plan JSON file")
    src = tf.add_mutually_exclusive_group()
    src.add_argument("--dir", "-d", default=None, help="Terraform/OpenTofu directory (default: current directory)")
    src.add_argument("--plan-json", help="read `show -json` output (or a `plan -json` log) instead of running a plan")
    tf.add_argument("--binary", choices=["tofu", "terraform"], help="which CLI to run (default: tofu, then terraform)")
    tf.add_argument("--var-file", action="append", default=[], help="passed through to plan; may repeat")
    tf.add_argument("--profile", "-p", help="AWS profile for the AWS provider (sets AWS_PROFILE; default: env/default)")

    cf = sub.add_parser("cloudformation", aliases=["cfn"], parents=[common],
                        help="run CloudFormation drift detection on stacks")
    cf.add_argument("--stack", "-s", action="append", default=[], help="stack name; may repeat (default: all stacks)")
    cf.add_argument("--region", "-r", help="AWS region (default: profile/env region)")
    cf.add_argument("--profile", "-p", help="AWS profile (default: env/default credentials)")
    add_role_args(cf)
    cf.add_argument("--timeout", type=float, default=600, help="seconds to wait per stack (default 600)")

    un = sub.add_parser("unmanaged", aliases=["scan"], parents=[common],
                        help="list the AWS account and report resources no state file or stack accounts for")
    un.add_argument("--state", action="append", default=[],
                    help="Terraform state: a .tfstate file, s3://bucket/key.tfstate, s3://bucket/prefix/ "
                         "(every .tfstate under it) or an initialised Terraform directory; may repeat")
    un.add_argument("--no-cloudformation", action="store_true",
                    help="don't count resources in CloudFormation stacks as managed")
    un.add_argument("--region", "-r", action="append", default=[], help="region to scan; may repeat (default: profile region)")
    un.add_argument("--all-regions", action="store_true", help="scan every enabled region")
    un.add_argument("--profile", "-p", help="AWS profile (default: env/default credentials)")
    add_role_args(un)
    un.add_argument("--strict", action="store_true",
                    help="also report resources AWS created itself (default VPCs, service-linked roles, ...)")
    un.add_argument("--explain", metavar="TEXT",
                    help="say why resources whose id, name or ARN contains TEXT did or didn't match IaC")
    un.add_argument("--type", "-t", action="append", default=[],
                    help="only these types (Terraform or CloudFormation name, substring match); may repeat")
    un.add_argument("--workers", type=int, default=4, help="parallel list calls (default 4)")
    eol_group = un.add_mutually_exclusive_group()
    eol_group.add_argument("--eol-only", action="store_true",
                           help="only check for end-of-life versions (RDS/Aurora engines, EKS Kubernetes, Lambda runtimes)")
    eol_group.add_argument("--no-eol", action="store_true", help="skip the end-of-life check")
    un.add_argument("--eol-data", metavar="FILE",
                    help="JSON with lambda_runtimes deprecation dates laid over the built-in table")
    return p


def aws_session(profile: str | None, region: str | None):
    try:
        import boto3
    except ImportError as exc:
        raise RuntimeError("This mode needs boto3: pip install boto3") from exc
    session = boto3.Session(profile_name=profile, region_name=region)
    if not session.region_name:
        raise RuntimeError("No AWS region set. Pass --region or set AWS_REGION / a profile region.")
    return session


def assume_role(session, role_arn: str, external_id: str | None = None, session_name: str | None = None):
    """A session acting as `role_arn`. Its credentials renew themselves, so a long scan never expires."""
    import boto3
    import botocore.session
    from botocore.credentials import AssumeRoleCredentialFetcher, DeferredRefreshableCredentials

    source = session.get_credentials()
    if source is None:
        raise RuntimeError(f"No AWS credentials to assume {role_arn} with. Set a profile or AWS_* variables.")
    extra = {"RoleSessionName": session_name or "cloud-drift-report"}
    if external_id:
        extra["ExternalId"] = external_id
    fetcher = AssumeRoleCredentialFetcher(client_creator=session._session.create_client, source_credentials=source,
                                          role_arn=role_arn, extra_args=extra)
    credentials = DeferredRefreshableCredentials(method="assume-role", refresh_using=fetcher.fetch_credentials)
    try:
        credentials.get_frozen_credentials()  # fail now, with a clear message, rather than mid-scan
    except Exception as exc:
        raise RuntimeError(f"Could not assume {role_arn}: {exc}") from exc
    core = botocore.session.Session()
    core._credentials = credentials
    return boto3.Session(botocore_session=core, region_name=session.region_name)


def read_state(src: str, base, session, read, problems: list[str] | None = None):
    """State often lives in a central account: read it as yourself first, then as the assumed role."""
    def attempt(creds):
        if problems is None:
            return read(src, session=creds)
        noted: list[str] = []  # kept only from the attempt that worked
        docs = read(src, session=creds, problems=noted)
        problems.extend(noted)
        return docs

    if session is base or not src.startswith("s3://"):
        return attempt(session)
    try:
        return attempt(base)
    except Exception as own:
        try:
            return attempt(session)
        except Exception as assumed:
            raise RuntimeError(f"Could not read {src} with your own credentials ({own}) "
                               f"or with the assumed role ({assumed}).") from assumed


def _matched_trace(entry) -> dict[str, str]:
    """Where a matched resource is managed: its state file and module (Terraform), or its stack (CloudFormation)."""
    if entry is None:
        return {}
    if entry.cc_type:
        return {"stack": entry.where}
    return {"state_source": entry.where, "address": entry.address, "module": entry.module}


def run_unmanaged(args, log=print) -> Report:
    import aws_inventory as inv_mod

    base = aws_session(args.profile, args.region[0] if args.region else None)
    session = assume_role(base, args.role_arn, args.external_id, args.role_session_name) if args.role_arn else base
    regions = inv_mod.enabled_regions(session) if args.all_regions else (args.region or [session.region_name])
    if not args.all_regions:
        inv_mod.check_regions(session, regions, log=log)
    if getattr(args, "eol_only", False):
        return run_eol(args, session, regions, inv_mod.Prices(session, log=log), log=log)
    iac: list = []
    sources: list[str] = []
    problems: list[str] = []
    unread = 0
    if not args.state and (backend := inv_mod.terraform_backend(".")) is not None:
        args.state = ["."]  # the Terraform code here says where its state is
        log(f"note: no --state given; reading the state of the Terraform code here ({backend['type']} backend, "
            "every workspace).", file=sys.stderr)
    for src in args.state:
        try:  # one unreadable source (or file in it) doesn't stop the others
            docs = read_state(src, base, session, inv_mod.read_state_source, problems)
        except Exception as exc:
            unread += 1
            problems.append(f"state {src} could not be read ({inv_mod._short_reason(str(exc))}); "
                            "its resources are listed as not in IaC")
            log(f"warning: could not read state {src}: {exc}", file=sys.stderr)
            continue
        count = 0
        for label, doc in docs:
            entries = inv_mod.parse_state(doc, label)
            iac.extend(entries)
            count += len(entries)
        files = f"{len(docs)} state files, " if len(docs) != 1 else ""
        sources.append(f"{src} ({files}{count} resources)")
    if args.state and unread == len(args.state):
        raise RuntimeError("No --state could be read, so every resource would be reported as not in IaC: "
                           + "; ".join(problems))
    if not args.no_cloudformation:
        stack_total = 0
        for region in regions:
            entries = inv_mod.stack_entries(session, region, log=log, problems=problems)
            stack_total += len(entries)
            iac.extend(entries)
        sources.append(f"CloudFormation stacks in {', '.join(regions)} ({stack_total} resources)")
    if not args.state:
        log("note: no --state and --no-cloudformation, so nothing counts as IaC and every resource is listed."
            if args.no_cloudformation else
            "note: no --state given, so only CloudFormation stacks count as IaC. Pass --state to include Terraform.",
            file=sys.stderr)
    cc_types = list(inv_mod.CLOUDCONTROL_TO_TERRAFORM)
    if args.type:
        wanted = [t.lower() for t in args.type]
        cc_types = [c for c in cc_types if any(w in c.lower() or w in inv_mod.terraform_type(c) for w in wanted)]
        if not cc_types:
            raise RuntimeError(f"No supported type matches {', '.join(args.type)}.")
    inventory = inv_mod.list_inventory(session, regions, cc_types, workers=args.workers, log=log)
    owned = {id(res): why for res, why in inventory.owned}
    if args.strict:  # report what AWS created too, so nothing is skipped silently
        inventory.resources += [res for res, _ in inventory.owned]
    try:
        account = session.client("sts").get_caller_identity()["Account"]
    except Exception:
        account = ""
        problems.append("the AWS account could not be read, so state from other accounts counts as IaC too")
    gaps = {k: v for k, v in inventory.not_listed.items() if v not in inv_mod.KNOWN_LIMITS}
    if gaps:
        first, why = next(iter(gaps.items()))
        n = len(gaps)
        problems.insert(0, f"{n} resource type/region pair{'s' if n != 1 else ''} could not be listed "
                           f"(e.g. {first}: {why}; all in the JSON's coverage.not_listed)")
    for line in (inv_mod.explain(inventory, iac, args.explain, account) if args.explain else []):
        log(line, file=sys.stderr)
    result = inv_mod.match(inventory, iac, account)
    unmanaged = {id(res) for res in result.unmanaged}
    prices = inv_mod.Prices(session, log=log)
    idle = {id(res): found for res in inventory.resources if (found := inv_mod.idle_cost(res, prices))}
    findings = []
    for res in result.unmanaged:
        f = finalize(Finding(
            source="aws", location=res.region or "global", address=res.name or res.identifier, type=res.tf_type,
            action=UNMANAGED, physical_id=res.arn or res.identifier, tags=inv_mod._tag_map(res.props.get("Tags")),
            import_id=inv_mod.import_id(res, account)))
        if id(res) in owned:
            f.severity, f.kind = "low", "aws-created"
            f.explanation = f"AWS created this ({owned[id(res)]}); shown because of --strict."
        elif id(res) in idle:  # costs money for nothing, and nobody's code owns it
            label = inv_mod.idle_label(res)  # anything short of certainly idle is medium
            f.severity, f.kind = ("high" if label == "idle" else "medium"), "idle"
            f.explanation = f"Not in IaC and {label}: {idle[id(res)][0]}."
        findings.append(f)
    duplicates = inv_mod.duplicate_imports(iac)
    for d in duplicates:
        log(f"warning: {d['type']} {d['id']} is in state at {len(d['addresses'])} addresses: "
            f"{'; '.join(d['addresses'])}", file=sys.stderr)
    by_type: dict[str, dict[str, int]] = {}
    for res, _ in result.managed:
        by_type.setdefault(res.tf_type, {"in_iac": 0, "not_in_iac": 0})["in_iac"] += 1
    for res in result.unmanaged:
        by_type.setdefault(res.tf_type, {"in_iac": 0, "not_in_iac": 0})["not_in_iac"] += 1
    listed = len(inventory.resources)
    coverage = {
        "listed": listed, "in_iac": len(result.managed), "not_in_iac": len(result.unmanaged),
        "percent_in_iac": round(100 * len(result.managed) / listed, 1) if listed else None,
        "aws_owned_skipped": 0 if args.strict else len(inventory.owned), "types_not_listed": len(inventory.not_listed),
        "regions": regions, "iac_sources": sources, "not_listed": inventory.not_listed or None,
        "by_type": dict(sorted(by_type.items())) or None, "duplicate_imports": duplicates or None,
        "idle": [{"type": res.tf_type, "id": res.identifier, "region": res.region, "in_iac": id(res) not in unmanaged,
                  "reason": idle[id(res)][0], "monthly_usd": round(idle[id(res)][1], 2),
                  **_matched_trace(result.entries.get(id(res)))}
                 for res in inventory.resources if id(res) in idle] or None,
    }
    report = Report(findings, "aws", f"{account or 'AWS account'} ({', '.join(regions)})", coverage=coverage,
                    incomplete=problems)
    if not getattr(args, "no_eol", False):
        report.eol = run_eol(args, session, regions, prices, account=account, log=log).eol
    return report


def run_eol(args, session, regions: list[str], prices, account: str | None = None, log=print) -> Report:
    """The end-of-life check (eol.py) as a report of its own; run_unmanaged attaches it to the not-in-IaC report."""
    import eol

    if account is None:
        try:
            account = session.client("sts").get_caller_identity()["Account"]
        except Exception:
            account = ""
    table = eol.load_overrides(getattr(args, "eol_data", None))
    result = eol.scan(session, regions, prices, table, log=log)
    log(eol.summary_line(result), file=sys.stderr)
    return Report([], "aws", f"{account or 'AWS account'} ({', '.join(regions)})", eol=result,
                  eol_only=bool(getattr(args, "eol_only", False)))


def ignore_files(args) -> list[str]:
    """--ignore files (which must exist), else .driftignore in --dir and the current directory."""
    if args.ignore:
        missing = [p for p in args.ignore if not os.path.isfile(p)]
        if missing:
            raise OSError(f"{', '.join(missing)} not found")
        return list(args.ignore)
    dirs = [os.path.abspath(getattr(args, "dir", None) or "."), os.path.abspath(".")]
    return list(dict.fromkeys(os.path.join(d, FILENAME_HINT) for d in dirs))


# --- config file ---------------------------------------------------------------

CONFIG_NAMES = (".driftreport.yml", ".driftreport.yaml")
CONFIG_SECTIONS = {"terraform": "terraform", "tf": "terraform", "tofu": "terraform", "cloudformation": "cloudformation",
                   "cfn": "cloudformation", "unmanaged": "unmanaged", "scan": "unmanaged"}
_CONFIG_PATHS = {"output", "ignore", "var_file", "dir", "plan_json", "state", "eol_data"}  # relative to the config file


def config_path(args) -> str | None:
    if args.no_config:
        return None
    if args.config:
        if not os.path.isfile(args.config):
            raise OSError(f"config file {args.config} not found")
        return args.config
    dirs = [getattr(args, "dir", None) or ".", "."]
    return next((os.path.join(d, n) for d in dict.fromkeys(dirs) for n in CONFIG_NAMES
                 if os.path.isfile(os.path.join(d, n))), None)


def apply_config(parser: argparse.ArgumentParser, argv: list[str] | None, args) -> tuple[argparse.Namespace, str | None]:
    """Flags from a .driftreport.yml: top-level keys for every mode, a section per mode. The command line wins."""
    path = config_path(args)
    if path is None:
        return args, None
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError(f"Reading {path} needs PyYAML: pip install pyyaml") from exc
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected keys such as `format:` or `unmanaged:`, not a {type(data).__name__}")
    modes = parser._subparsers._group_actions[0].choices
    mode = CONFIG_SECTIONS[args.mode]

    def flags(name):
        return {a.dest: a for a in modes[name]._actions if a.option_strings and a.dest not in ("help", "config", "no_config")}

    known = {d for name in set(CONFIG_SECTIONS.values()) for d in flags(name)}
    mine = flags(mode)
    wanted: dict[str, Any] = {}
    for key, value in data.items():
        if key in CONFIG_SECTIONS:
            if not isinstance(value, dict):
                raise ValueError(f"{path}: `{key}:` should hold keys such as `region:`")
            continue
        dest = str(key).replace("-", "_")
        if dest not in known:
            raise ValueError(f"{path}: unknown key `{key}` (keys are flag names, such as fail-on-drift)")
        if dest in mine:
            wanted[dest] = value
    for key, value in ((k, v) for s, sec in data.items() if CONFIG_SECTIONS.get(s) == mode for k, v in sec.items()):
        dest = str(key).replace("-", "_")
        if dest not in mine:
            raise ValueError(f"{path}: `{key}` isn't a {mode} option")
        wanted[dest] = value
    base = os.path.dirname(path)
    defaults = {}
    for dest, value in wanted.items():
        action, flag = mine[dest], dest.replace("_", "-")
        if isinstance(action, argparse._AppendAction):
            value = [str(v) for v in (value if isinstance(value, list) else [value])]
        elif isinstance(action, argparse._StoreTrueAction):
            if not isinstance(value, bool):
                raise ValueError(f"{path}: {flag} should be true or false")
        elif value is not None:
            value = action.type(value) if action.type else str(value)
            if action.choices and value not in action.choices:
                raise ValueError(f"{path}: {flag} should be one of {', '.join(map(str, action.choices))}")
        if dest in _CONFIG_PATHS and base:
            value = [v if "://" in v else os.path.normpath(os.path.join(base, v)) for v in value] \
                if isinstance(value, list) else os.path.normpath(os.path.join(base, value))
        defaults[dest] = value
    modes[args.mode].set_defaults(**defaults)
    merged = parser.parse_args(argv)
    for dest in defaults:  # a repeatable flag given on the command line replaces the file's list
        if isinstance(mine[dest], argparse._AppendAction) and getattr(args, dest):
            setattr(merged, dest, getattr(args, dest))
    return merged, path


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args, used_config = apply_config(parser, argv, args)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if used_config:
        print(f"using {os.path.relpath(used_config)}", file=sys.stderr)
    try:
        if args.mode in ("terraform", "tf", "tofu"):
            if args.plan_json:
                findings, target = load_plan_file(args.plan_json), args.plan_json
            else:
                directory = os.path.abspath(args.dir or ".")
                extra = [f"-var-file={v}" for v in args.var_file]
                findings, target = run_terraform(directory, args.binary, extra, profile=args.profile), directory
                source = state_source_of(directory)
                for f in findings:
                    f.state_source = source
            report = Report(findings, "terraform", target, code_dir="" if args.plan_json else directory)
        elif args.mode in ("unmanaged", "scan"):
            report = run_unmanaged(args)
        else:
            cfn, region = cfn_client(args.profile, args.region, args)
            problems: list[str] = []
            findings, statuses = run_cloudformation(cfn, args.stack, region, args.timeout, problems=problems)
            if not statuses:
                print(f"No stacks found in {region}.", file=sys.stderr)
            target = ", ".join(args.stack) if args.stack else f"all stacks in {region}"
            report = Report(findings, "cloudformation", target, checked=statuses, incomplete=problems)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not args.no_ignore:
        import drift_ignore as ignore

        try:
            rules, used = ignore.load(ignore_files(args), warn=lambda m: print(f"warning: {m}", file=sys.stderr))
        except OSError as exc:
            print(f"error: could not read ignore file: {exc}", file=sys.stderr)
            return 1
        # Relative names in reports, so they never show a home directory.
        apply_ignore(report, rules, [os.path.relpath(u) if not os.path.relpath(u).startswith("..")
                                     else os.path.basename(u) for u in used])
        report.ignore_text = "\n".join(open(u, encoding="utf-8").read().rstrip("\n") for u in used)
        if report.ignored:
            print(report.ignored_line(), file=sys.stderr)

    c = report.counts()
    json_paths = []
    for path in args.output:
        ext = os.path.splitext(path)[1].lstrip(".").lower() or os.path.basename(path).lstrip(".").lower()
        fmt = ext if len(args.output) > 1 and ext in RENDERERS else args.format
        if os.path.basename(path) == FILENAME_HINT:  # never write a report over an ignore file
            fmt = "driftignore"
        elif ext == "tf":  # never write a report into Terraform code
            fmt = "imports"
        elif ext == "sarif":  # code scanning reads only SARIF from a .sarif file
            fmt = "sarif"
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(RENDERERS[fmt](report))
        if fmt == "json":
            json_paths.append(path)
        print(f"Wrote {path}: {report.noun()} (high {c['high']}, medium {c['medium']}, "
              f"low {c['low']}).", file=sys.stderr)
    if not args.output:
        sys.stdout.write(RENDERERS[args.format](report))
    if report.incomplete:
        print(f"warning: {report.incomplete_line()}", file=sys.stderr)
    if args.share:
        share_report(json_paths)
    elif json_paths and report.findings:
        print(import_hint(json_paths[0]), file=sys.stderr)
    found = report.findings or (report.eol_only and report.eol is not None and report.eol.findings)
    return 2 if args.fail_on_drift and found else 0


if __name__ == "__main__":
    sys.exit(main())

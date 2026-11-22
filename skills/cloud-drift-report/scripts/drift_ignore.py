"""`.driftignore` rules: leave known, accepted findings out of the report.

The syntax is driftctl's, so an existing driftctl file keeps working, plus tag rules:

    # a comment; text after " #" on a line is a comment too
    aws_s3_bucket.cloudtrail-logs-*        whole resource: <type>.<id>, * and ? are wildcards
    aws_iam_role.*                         every resource of a type (a bare type works too)
    aws_instance.i-0abc123.tags.Patched    one attribute: <type>.<id>.<attribute path>
    aws_s3_bucket.logs\\.example\\.com     escape a dot that is part of the id with a backslash
    tag:ManagedBy=karpenter                any resource with this tag (tag:Key alone matches any value)
    !aws_iam_role.prod-admin               exception: report this one even if an earlier line ignores it

Later lines win, as in .gitignore. The <id> is compared with the Terraform address (with and without
module path and index), the resource name, the physical id or ARN and the last part of the ARN, so
both driftctl-style ids and Terraform names work.

Standard library only. OrchesTerra runs the same cases (tests/fixtures/driftignore_cases.json), so
keep the two in step when the syntax changes.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any, Iterable

FILENAME = ".driftignore"


@dataclass(frozen=True)
class Rule:
    line: str          # as written, for "ignored by" messages
    negate: bool
    type: str = ""     # type glob; empty for tag rules
    rest: str = ""     # id glob, possibly followed by an attribute path (escapes kept)
    tag_key: str = ""
    tag_value: str | None = None  # None = any value


def _strip_comment(raw: str) -> str:
    line = raw.strip()
    if line.startswith("#"):
        return ""
    return re.split(r"\s+#", line, maxsplit=1)[0].strip()


def _rule(line: str) -> Rule | None:
    """The rule on one comment-free line, or None when the line is not a valid rule."""
    negate = line.startswith("!")
    body = line[1:].strip() if negate else line
    if not body or re.search(r"\s", body):
        return None
    if body.startswith("tag:"):
        key, sep, value = body[4:].partition("=")
        return Rule(line, negate, tag_key=key, tag_value=value if sep else None) if key else None
    rtype, dot, rest = body.partition(".")
    if not rtype or (dot and not rest) or re.search(r"(?<!\\)\.$", body):
        return None
    return Rule(line, negate, type=rtype, rest=rest or "*")


def parse(text: str) -> list[Rule]:
    """Valid rules in order; invalid lines are skipped (see problems())."""
    return [r for r in (_rule(line) for line in map(_strip_comment, text.splitlines()) if line) if r]


def problems(text: str) -> list[tuple[int, str]]:
    """(line number, text) for every line that is not a comment, blank or a valid rule."""
    out = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = _strip_comment(raw)
        if line and _rule(line) is None:
            out.append((n, line))
    return out


def escape_id(value: str) -> str:
    """Write an id so a rule matches exactly it: dots escaped, wildcard characters bracketed."""
    return re.sub(r"([*?\[])", r"[\1]", value).replace(".", "\\.")


def load(paths: Iterable[str], warn=None) -> tuple[list[Rule], list[str]]:
    """Rules from every file that exists, in order, and the files that were read.

    warn(message) is called for each line that is not a valid rule.
    """
    rules: list[Rule] = []
    used = []
    for path in paths:
        if path and os.path.isfile(path):
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            rules.extend(parse(text))
            if warn:
                for n, line in problems(text):
                    warn(f"{path}:{n}: not a valid rule, skipped: {line}")
            used.append(path)
    return rules, used


def _split_unescaped(text: str) -> list[str]:
    return [p.replace("\\.", ".") for p in re.split(r"(?<!\\)\.", text)]


def _norm_path(path: str) -> str:
    """ingress[0].cidr_blocks and /SecurityGroupIngress/0 both become dotted paths."""
    p = re.sub(r"\[(\d+)\]", r".\1", path.strip().lstrip("/").replace("/", "."))
    return p.strip(".")


def candidate_ids(f: Any) -> set[str]:
    """Names a rule's <id> may refer to for this finding."""
    out = set()
    address = getattr(f, "address", "") or ""
    physical = getattr(f, "physical_id", "") or ""
    rtype = getattr(f, "type", "") or ""
    for value in (address, physical):
        if value:
            out.add(value)
    if address and rtype and f"{rtype}." in address:
        name = address.rsplit(f"{rtype}.", 1)[1]  # drops module.x. prefix
        out.add(name)
        out.add(re.sub(r"\[[^\]]*\]$", "", name))  # drops [0] / ["key"]
    short = short_id(physical)
    if short != physical:
        out.add(short)
    return {c for c in out if c}


def short_id(physical: str) -> str:
    """The resource part of an ARN: role/app -> app, security-group/sg-1 -> sg-1, log-group:/aws/x:* -> /aws/x.

    Anything that is not an ARN comes back unchanged.
    """
    if not physical.startswith("arn:") or physical.count(":") < 5:
        return physical
    tail = physical.split(":", 5)[5]
    if "/" not in tail and ":" not in tail:  # s3:::bucket, sqs:...:queue
        return tail if tail.strip("*") else physical
    if tail.endswith(":*"):
        tail = tail[:-2]
    for sep in ("/", ":"):
        kind, found, rest = tail.partition(sep)
        if found and rest.strip("*") and re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", kind):
            return rest
    return physical


def _type_ok(rule: Rule, f: Any) -> bool:
    return fnmatchcase(getattr(f, "type", "") or "", rule.type)


def _id_ok(pattern: str, ids: set[str]) -> bool:
    return any(fnmatchcase(i, pattern) for i in ids)


def _resource_match(rule: Rule, f: Any, ids: set[str]) -> bool:
    if rule.tag_key:
        tags = getattr(f, "tags", None) or {}
        return any(fnmatchcase(k, rule.tag_key) and (rule.tag_value is None or fnmatchcase(str(v), rule.tag_value))
                   for k, v in tags.items())
    return _type_ok(rule, f) and _id_ok(rule.rest.replace("\\.", "."), ids)


def _attribute_rule(rule: Rule, f: Any, ids: set[str]) -> str | None:
    """The attribute path this rule ignores on this finding, or None."""
    if rule.tag_key or not _type_ok(rule, f):
        return None
    parts = _split_unescaped(rule.rest)
    for i in range(1, len(parts)):
        if _id_ok(".".join(parts[:i]), ids):
            return _norm_path(".".join(parts[i:]))
    return None


def _path_ok(pattern: str, path: str) -> bool:
    p = _norm_path(path)
    return fnmatchcase(p, pattern) or p.startswith(pattern + ".")


@dataclass
class Outcome:
    ignored: bool = False
    rule: str = ""                 # line that ignored the whole finding
    dropped_paths: tuple[str, ...] = ()  # attribute changes removed by attribute rules


def evaluate(rules: list[Rule], f: Any) -> Outcome:
    if not rules:
        return Outcome()
    ids = candidate_ids(f)
    ignored, by = False, ""
    for rule in rules:
        if _resource_match(rule, f, ids):
            ignored, by = (not rule.negate), rule.line
    if ignored:
        return Outcome(True, by)
    changes = getattr(f, "changes", None) or []
    if not changes:
        return Outcome()
    dropped = []
    for ch in changes:
        drop = False
        for rule in rules:
            pattern = _attribute_rule(rule, f, ids)
            if pattern and _path_ok(pattern, ch.path):
                drop = not rule.negate
        if drop:
            dropped.append(ch.path)
    if dropped and len(dropped) == len(changes):
        return Outcome(True, "attribute rules", tuple(dropped))
    return Outcome(False, "", tuple(dropped))

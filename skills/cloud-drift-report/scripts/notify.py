"""Notifications for cloud-drift-report: Slack, Microsoft Teams (Workflows) and a generic JSON webhook.

Only runs when asked with --notify. Messages carry counts, the top findings and attribute NAMES; attribute
values (which can be secrets) are left out unless --notify-values is given. A failed notification is a
warning and never fails the scan, unless --notify-strict is given. Webhook URLs are never printed in full.

Standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

import drift_report as dr

CHANNELS = ("slack", "teams", "webhook")
TRIGGERS = ("drift", "always", "change")
TOP = 5
RETRIES = 3          # attempts after the first, on 429, 5xx and network errors
MAX_WAIT = 30.0      # cap on Retry-After and backoff, in seconds
SIGNATURE_HEADER = "X-Drift-Signature"

# channel -> (URL flag dest, env-name flag dest, default env var)
URLS = {
    "slack": ("slack_webhook_url", "slack_webhook_url_env", "SLACK_WEBHOOK_URL"),
    "teams": ("teams_webhook_url", "teams_webhook_url_env", "TEAMS_WEBHOOK_URL"),
    "webhook": ("webhook_url", "webhook_url_env", "WEBHOOK_URL"),
}
SECRET_ENV_DEFAULT = "WEBHOOK_SECRET"
# Settings that hold secrets: refused in .driftreport.yml (name the environment variable with *-env instead).
SECRET_DESTS = {"slack_webhook_url", "teams_webhook_url", "webhook_url", "webhook_secret"}

_sleep: Callable[[float], None] = time.sleep  # replaced in tests


class NotifyError(Exception):
    pass


# --- flags -------------------------------------------------------------------------

def add_args(parser: argparse.ArgumentParser) -> None:
    g = parser.add_argument_group("notifications")
    g.add_argument("--notify", action="append", default=[], metavar="CHANNEL",
                   help="send a summary to slack, teams or webhook (JSON report); may repeat")
    g.add_argument("--notify-on", choices=TRIGGERS, default="drift",
                   help="drift: when anything is found (default); always; change: only new or resolved "
                        "findings compared with --baseline")
    g.add_argument("--baseline", metavar="FILE",
                   help="a previous JSON report, for --notify-on change (a missing file counts as empty)")
    g.add_argument("--notify-values", action="store_true",
                   help="include attribute values in messages (off by default: values can be secrets)")
    g.add_argument("--notify-strict", action="store_true", help="exit 1 when a notification can't be sent")
    g.add_argument("--notify-timeout", type=float, default=10.0, help="seconds per request (default 10)")
    labels = {"slack": "Slack incoming webhook", "teams": "Teams Workflows webhook", "webhook": "JSON webhook"}
    for channel, (dest, env_dest, env) in URLS.items():
        flag = dest.replace("_", "-")
        g.add_argument(f"--{flag}", dest=dest, metavar="URL", help=f"{labels[channel]} URL (default: ${env})")
        g.add_argument(f"--{flag}-env", dest=env_dest, metavar="NAME", default=env,
                       help=f"environment variable holding the {labels[channel]} URL (default {env})")
    g.add_argument("--webhook-secret", metavar="SECRET",
                   help=f"sign webhook bodies with HMAC-SHA256 in {SIGNATURE_HEADER} (default: ${SECRET_ENV_DEFAULT})")
    g.add_argument("--webhook-secret-env", metavar="NAME", default=SECRET_ENV_DEFAULT,
                   help=f"environment variable holding the webhook secret (default {SECRET_ENV_DEFAULT})")


def check_args(args) -> str:
    """A usage problem with the notification flags, or "". Checked before the scan runs."""
    channels = getattr(args, "notify", None) or []
    bad = [c for c in channels if c not in CHANNELS]
    if bad:
        return f"--notify takes {', '.join(CHANNELS)}, not {', '.join(bad)}"
    if channels and args.notify_on == "change" and not args.baseline:
        return "--notify-on change needs --baseline (a previous JSON report)"
    return ""


def mask_url(url: str) -> str:
    """https://hooks.slack.com/services/T0/B0/xyz -> https://hooks.slack.com/***"""
    try:
        p = urllib.parse.urlsplit(url)
    except ValueError:
        return "***"
    if not p.scheme or not p.hostname:
        return "***"
    return f"{p.scheme}://{p.hostname}/***"


def run_url(env=os.environ) -> str:
    """Link to the GitHub Actions run, when running in one."""
    server, repo, run = env.get("GITHUB_SERVER_URL"), env.get("GITHUB_REPOSITORY"), env.get("GITHUB_RUN_ID")
    return f"{server.rstrip('/')}/{repo}/actions/runs/{run}" if server and repo and run else ""


# --- what to send --------------------------------------------------------------------

def finding_key(d: dict[str, Any]) -> tuple:
    return (d.get("source", ""), d.get("type", ""), d.get("address", ""), d.get("physical_id", ""))


def load_baseline(path: str) -> list[dict[str, Any]] | None:
    """Findings of a previous JSON report; None when the file doesn't exist yet (a first run)."""
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict) or not isinstance(doc.get("findings", []), list):
        raise ValueError(f"{path} is not a cloud-drift-report JSON report")
    return doc.get("findings", [])


def compare(current: list[dict[str, Any]], baseline: list[dict[str, Any]]) -> tuple[list, list]:
    """(new, resolved) findings."""
    before = {finding_key(d) for d in baseline}
    now = {finding_key(d) for d in current}
    return ([d for d in current if finding_key(d) not in before],
            [d for d in baseline if finding_key(d) not in now])


def strip_values(d: dict[str, Any]) -> dict[str, Any]:
    out = dict(d)
    if out.get("changes"):
        out["changes"] = [{"path": c.get("path", "")} for c in out["changes"]]
    return out


def kind_label(d: dict[str, Any]) -> str:
    action = d.get("action", "")
    if action == dr.UNMANAGED:
        return {"idle": "idle and not in IaC", "aws-created": "created by AWS"}.get(d.get("kind", ""), dr.UNMANAGED)
    return action


def what_changed(d: dict[str, Any], values: bool) -> str:
    action = d.get("action", "")
    if action == dr.DELETED:
        return "deleted outside IaC"
    if action == dr.UNMANAGED:
        return kind_label(d) + (f": {d['physical_id']}" if d.get("physical_id") else "")
    changes = d.get("changes") or []
    if not changes:
        return "changed outside IaC (no attribute details)"
    if values:
        parts = [f"{c['path']}: {dr._fmt_value(c.get('before'), 60)} → {dr._fmt_value(c.get('after'), 60)}"
                 for c in changes[:3]]
    else:
        parts = [c["path"] for c in changes[:5]]
    more = len(changes) - len(parts)
    return "changed: " + ", ".join(parts) + (f" and {more} more" if more > 0 else "")


def _shown_path(path: str) -> str:
    """A Terraform directory or plan file relative to the current directory, else its name: never a home directory."""
    if not os.path.isabs(path):
        return path
    rel = os.path.relpath(path)
    return rel if not rel.startswith("..") else os.path.basename(path.rstrip(os.sep)) or path


def _shown_target(r: dr.Report) -> str:
    return _shown_path(r.target) if r.source == "terraform" else r.target


def build_summary(r: dr.Report, args, baseline: list[dict[str, Any]] | None = None,
                  env=os.environ) -> dict[str, Any]:
    """Everything the three message formats need, values already stripped unless --notify-values."""
    values = bool(getattr(args, "notify_values", False))
    current = []
    for f in r.sorted():
        d = dr._finding_json(f)
        if f.kind:
            d["kind"] = f.kind
        if f.source == "terraform":
            d["location"] = _shown_path(d.get("location", ""))
        current.append(d if values else strip_values(d))
    new = resolved = None
    if baseline is not None:
        new, resolved = compare(current, [b if values else strip_values(b) for b in baseline])
    kinds: dict[str, int] = {}
    for d in current:
        kinds[kind_label(d)] = kinds.get(kind_label(d), 0) + 1
    states = list(dict.fromkeys(d["state_source"] for d in current if d.get("state_source")))
    title = ("Not in IaC" if r.source == "aws" else "Drift report") + f": {_shown_target(r)}"
    return {
        "title": title, "source": r.source, "target": _shown_target(r), "generated_at": r.generated_at,
        "headline": r.noun(), "total": len(current), "severity": r.counts(), "kinds": kinds,
        "states": states, "incomplete": r.incomplete_line(), "ignored": len(r.ignored),
        "findings": current, "new": new, "resolved": resolved, "values": values,
        "run_url": run_url(env), "footer": dr.FOOTER, "product_url": dr.PRODUCT_URL,
    }


def top_lines(s: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """(prefix, finding) for the findings worth listing: new then resolved on a change run, else the top ones."""
    if s["new"] is not None:
        rows = [("new", d) for d in s["new"]] + [("resolved", d) for d in s["resolved"]]
    else:
        rows = [("", d) for d in s["findings"]]
    return rows[:TOP]


def _line(prefix: str, d: dict[str, Any], s: dict[str, Any]) -> tuple[str, str]:
    """(address, detail) for one listed finding."""
    where = d.get("location", "") if d.get("source") != "terraform" else ""  # Terraform: the checked dir, shown once
    detail = (f"{d.get('severity', '')} · {d.get('type', '')}" + (f" · {where}" if where else "")
              + f" · {what_changed(d, s['values'])}")
    if prefix == "resolved":
        detail = "resolved · " + detail
    elif prefix == "new":
        detail = "new · " + detail
    return d.get("address") or d.get("physical_id", ""), detail


def counts_text(s: dict[str, Any]) -> str:
    sev = s["severity"]
    text = f"{s['headline']}: high {sev['high']}, medium {sev['medium']}, low {sev['low']}"
    if s["kinds"]:
        text += " (" + ", ".join(f"{n} {k}" for k, n in s["kinds"].items()) + ")"
    return text


def change_text(s: dict[str, Any]) -> str:
    if s["new"] is None:
        return ""
    return f"Since the baseline: {len(s['new'])} new, {len(s['resolved'])} resolved."


def scope_text(s: dict[str, Any]) -> str:
    text = {"aws": "Account", "cloudformation": "Stacks"}.get(s["source"], "Checked") + f": {s['target']}"
    if s["states"]:
        shown = s["states"][:3]
        more = len(s["states"]) - len(shown)
        text += " · State: " + ", ".join(shown) + (f" and {more} more" if more > 0 else "")
    return text


def remaining(s: dict[str, Any]) -> int:
    pool = len(s["new"]) + len(s["resolved"]) if s["new"] is not None else s["total"]
    return max(pool - TOP, 0)


# --- payloads ------------------------------------------------------------------------

def _slack_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slack_payload(s: dict[str, Any]) -> dict[str, Any]:
    e = _slack_escape
    head = [f"*{e(counts_text(s))}*"]
    if change_text(s):
        head.append(e(change_text(s)))
    head.append(e(scope_text(s)))
    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": s["title"][:150]}},
        {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(head)}},
    ]
    rows = top_lines(s)
    if rows:
        lines = [f"• `{e(addr)}` {e(detail)}" for addr, detail in (_line(p, d, s) for p, d in rows)]
        if remaining(s):
            lines.append(f"…and {remaining(s)} more in the full report")
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)[:3000]}})
    if s["incomplete"]:
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": e(s["incomplete"])[:3000]}]})
    context = []
    if s["run_url"]:
        context.append(f"<{s['run_url']}|View the run>")
    context.append(e(s["footer"].split(" → ")[0]) + f" → <{s['product_url']}|orchesterra.in>")
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": " · ".join(context)}]})
    return {"text": f"{s['title']}: {counts_text(s)}", "blocks": blocks}


def teams_payload(s: dict[str, Any]) -> dict[str, Any]:
    """A message with an Adaptive Card, as Teams Workflows' "When a Teams webhook request is received" takes."""
    body: list[dict[str, Any]] = [
        {"type": "TextBlock", "text": s["title"], "weight": "Bolder", "size": "Medium", "wrap": True},
        {"type": "TextBlock", "text": counts_text(s), "wrap": True, "spacing": "Small"},
    ]
    if change_text(s):
        body.append({"type": "TextBlock", "text": change_text(s), "wrap": True, "spacing": "Small"})
    body.append({"type": "TextBlock", "text": scope_text(s), "wrap": True, "isSubtle": True, "spacing": "Small"})
    rows = top_lines(s)
    if rows:
        body.append({"type": "FactSet", "facts": [{"title": addr, "value": detail}
                                                  for addr, detail in (_line(p, d, s) for p, d in rows)]})
        if remaining(s):
            body.append({"type": "TextBlock", "text": f"…and {remaining(s)} more in the full report",
                         "wrap": True, "isSubtle": True})
    if s["incomplete"]:
        body.append({"type": "TextBlock", "text": s["incomplete"], "wrap": True, "color": "Warning"})
    body.append({"type": "TextBlock", "text": s["footer"].split(" → ")[0] + f" → [orchesterra.in]({s['product_url']})",
                 "wrap": True, "isSubtle": True, "size": "Small"})
    card: dict[str, Any] = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
                            "version": "1.4", "body": body}
    if s["run_url"]:
        card["actions"] = [{"type": "Action.OpenUrl", "title": "View the run", "url": s["run_url"]}]
    return {"type": "message", "attachments": [
        {"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": card}]}


def webhook_payload(r: dr.Report, s: dict[str, Any], trigger: str) -> dict[str, Any]:
    """The JSON report (values stripped unless --notify-values) plus a `notification` block."""
    doc = json.loads(dr.render_json(r))
    doc["target"] = s["target"]
    doc["findings"] = [{k: v for k, v in d.items() if k != "kind"} for d in s["findings"]]
    note: dict[str, Any] = {"trigger": trigger, "summary": counts_text(s), "kinds": s["kinds"],
                            "values_included": s["values"]}
    if s["new"] is not None:
        note["new"] = [{k: v for k, v in d.items() if k != "kind"} for d in s["new"]]
        note["resolved"] = [{k: v for k, v in d.items() if k != "kind"} for d in s["resolved"]]
    if s["run_url"]:
        note["run_url"] = s["run_url"]
    doc["notification"] = note
    return doc


def signature(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


# --- sending -------------------------------------------------------------------------

def _retry_after(err: urllib.error.HTTPError, attempt: int) -> float:
    try:
        wait = float(err.headers.get("Retry-After", ""))
    except (TypeError, ValueError):
        wait = 2.0 ** attempt
    return min(max(wait, 0.0), MAX_WAIT)


def post(url: str, body: bytes, headers: dict[str, str], timeout: float, log=print) -> int:
    """POST with retries on 429, 5xx and network errors. Returns the status; raises NotifyError."""
    masked = mask_url(url)
    req_headers = {"Content-Type": "application/json", "User-Agent": f"cloud-drift-report/{dr.__version__}", **headers}
    for attempt in range(RETRIES + 1):
        req = urllib.request.Request(url, data=body, headers=req_headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (the user's own URL)
                return resp.status
        except urllib.error.HTTPError as exc:
            retry = exc.code == 429 or exc.code >= 500
            if not retry or attempt == RETRIES:
                raise NotifyError(f"{masked} answered HTTP {exc.code}") from None
            wait = _retry_after(exc, attempt)
            log(f"notify: {masked} answered HTTP {exc.code}; retrying in {wait:g}s")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = str(getattr(exc, "reason", exc)).replace(url, masked)
            if attempt == RETRIES:
                raise NotifyError(f"{masked} unreachable: {reason}") from None
            wait = min(2.0 ** attempt, MAX_WAIT)
            log(f"notify: {masked} unreachable ({reason}); retrying in {wait:g}s")
        _sleep(wait)
    raise NotifyError(f"{masked}: no answer")  # not reached


def _url_for(channel: str, args, env) -> str:
    dest, env_dest, default_env = URLS[channel]
    return getattr(args, dest, None) or env.get(getattr(args, env_dest, None) or default_env, "")


def run(report: dr.Report, args, log=None, env=os.environ) -> int:
    """Send the notifications --notify asks for. Returns 1 only when --notify-strict and something failed."""
    channels = list(dict.fromkeys(getattr(args, "notify", None) or []))
    if not channels:
        return 0
    if log is None:
        import sys

        def log(m):
            print(m, file=sys.stderr)

    strict = bool(getattr(args, "notify_strict", False))
    trigger = args.notify_on
    failed = False

    baseline = None
    if trigger == "change":
        try:
            baseline = load_baseline(args.baseline)
        except (OSError, ValueError) as exc:
            log(f"warning: notify: could not read baseline {args.baseline}: {exc}; nothing sent")
            return 1 if strict else 0
        if baseline is None:
            log(f"notify: baseline {args.baseline} not found; every finding counts as new")
            baseline = []
    s = build_summary(report, args, baseline, env)
    if trigger == "drift" and not s["total"]:
        log("notify: nothing found; nothing sent (use --notify-on always to send anyway)")
        return 0
    if trigger == "change" and not (s["new"] or s["resolved"]):
        log("notify: no new or resolved findings since the baseline; nothing sent")
        return 0

    for channel in channels:
        url = _url_for(channel, args, env)
        if not url:
            dest, env_dest, default_env = URLS[channel]
            log(f"warning: notify {channel}: no URL (--{dest.replace('_', '-')} or "
                f"${getattr(args, env_dest, None) or default_env}); skipped")
            failed = True
            continue
        if not url.lower().startswith(("https://", "http://")):
            log(f"warning: notify {channel}: {mask_url(url)} is not an http(s) URL; skipped")
            failed = True
            continue
        headers: dict[str, str] = {}
        if channel == "slack":
            payload = slack_payload(s)
        elif channel == "teams":
            payload = teams_payload(s)
        else:
            payload = webhook_payload(report, s, trigger)
        body = json.dumps(payload, default=str).encode()
        if channel == "webhook":
            secret = getattr(args, "webhook_secret", None) or env.get(
                getattr(args, "webhook_secret_env", None) or SECRET_ENV_DEFAULT, "")
            if secret:
                headers[SIGNATURE_HEADER] = signature(secret, body)
        try:
            status = post(url, body, headers, args.notify_timeout, log=log)
            log(f"notify {channel}: sent to {mask_url(url)} (HTTP {status})")
        except NotifyError as exc:
            log(f"warning: notify {channel}: {exc}")
            failed = True
    return 1 if failed and strict else 0

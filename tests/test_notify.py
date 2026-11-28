import hashlib
import hmac
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "cloud-drift-report" / "scripts"))

import drift_report as dr  # noqa: E402
import notify  # noqa: E402

PLAN = ROOT / "tests" / "fixtures" / "refresh_plan.json"
SNAPSHOTS = ROOT / "tests" / "fixtures" / "notify"
GITHUB = {"GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "acme/infra", "GITHUB_RUN_ID": "42"}
TOKEN = "T000/B000/supersecrettoken"


# --- a local HTTP server that records what it receives ---------------------------------

class Hook:
    def __init__(self):
        self.requests = []   # (path, headers, body bytes)
        self.answers = []    # (status, headers) to give, in order; then 200

    def url(self, path=f"/services/{TOKEN}"):
        return f"http://127.0.0.1:{self.port}{path}"

    def json(self, i=-1):
        return json.loads(self.requests[i][2])


@pytest.fixture
def hook():
    h = Hook()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            h.requests.append((self.path, dict(self.headers), body))
            status, headers = h.answers.pop(0) if h.answers else (200, {})
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    h.port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    t.start()
    yield h
    server.shutdown()
    server.server_close()


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    waits = []
    monkeypatch.setattr(notify, "_sleep", waits.append)
    return waits


def report():
    r = dr.Report(dr.load_plan_file(str(PLAN)), "terraform", "plan.json", generated_at="2026-11-28 06:00 UTC")
    for f in r.findings:
        f.state_source = "s3://acme-tf-state/prod/terraform.tfstate"
    return r


def args(**kw):
    a = dr.build_parser().parse_args(["terraform", "--plan-json", str(PLAN)])
    for k, v in kw.items():
        setattr(a, k, v)
    return a


def send(r, logs=None, env=None, **kw):
    logs = [] if logs is None else logs
    return notify.run(r, args(**kw), log=logs.append, env=env if env is not None else dict(GITHUB))


def snapshot(name, payload):
    """Compare with tests/fixtures/notify/<name>.json; UPDATE_SNAPSHOTS=1 rewrites it."""
    text = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True).replace(dr.__version__, "VERSION") + "\n"
    path = SNAPSHOTS / f"{name}.json"
    if os.environ.get("UPDATE_SNAPSHOTS"):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    assert text == path.read_text(encoding="utf-8")


# --- the three channels ----------------------------------------------------------------

def test_slack_payload(hook):
    assert send(report(), notify=["slack"], slack_webhook_url=hook.url()) == 0
    (path, headers, _), = hook.requests
    assert path == f"/services/{TOKEN}" and headers["Content-Type"] == "application/json"
    payload = hook.json()
    snapshot("slack", payload)
    text = json.dumps(payload)
    assert "6 drifted resources: high 3, medium 2, low 1" in text
    assert "<https://github.com/acme/infra/actions/runs/42|View the run>" in text
    assert "orchesterra.in" in text and "s3://acme-tf-state/prod/terraform.tfstate" in text
    assert "and 1 more" in text  # six findings, five listed


def test_teams_payload_is_an_adaptive_card(hook):
    assert send(report(), notify=["teams"], teams_webhook_url=hook.url("/workflows/abc")) == 0
    payload = hook.json()
    snapshot("teams", payload)
    (att,) = payload["attachments"]
    assert payload["type"] == "message" and att["contentType"] == "application/vnd.microsoft.card.adaptive"
    card = att["content"]
    assert card["type"] == "AdaptiveCard" and card["version"] == "1.4"
    assert card["actions"][0]["url"] == "https://github.com/acme/infra/actions/runs/42"
    assert len(next(b for b in card["body"] if b["type"] == "FactSet")["facts"]) == 5


def test_webhook_posts_the_json_report_signed(hook):
    assert send(report(), notify=["webhook"], webhook_url=hook.url("/drift"), webhook_secret="s3cret") == 0
    _, headers, body = hook.requests[0]
    expected = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    assert headers[notify.SIGNATURE_HEADER] == expected
    doc = json.loads(body)
    snapshot("webhook", doc)
    assert doc["tool"] == "cloud-drift-report" and doc["summary"]["total"] == 6 and len(doc["findings"]) == 6
    assert doc["notification"]["trigger"] == "drift"
    assert doc["notification"]["run_url"].endswith("/runs/42")


def test_webhook_secret_from_env_and_unsigned_without(hook):
    send(report(), env={"WEBHOOK_URL": hook.url("/a"), "WEBHOOK_SECRET": "k"}, notify=["webhook"])
    send(report(), env={"WEBHOOK_URL": hook.url("/b")}, notify=["webhook"])
    signed, unsigned = hook.requests
    assert signed[1][notify.SIGNATURE_HEADER] == notify.signature("k", signed[2])
    assert notify.SIGNATURE_HEADER not in unsigned[1]


def test_all_channels_at_once_from_env(hook):
    env = {"SLACK_WEBHOOK_URL": hook.url("/s"), "TEAMS_WEBHOOK_URL": hook.url("/t"), "WEBHOOK_URL": hook.url("/w")}
    assert send(report(), env=env, notify=["slack", "teams", "webhook", "slack"]) == 0
    assert [p for p, _, _ in hook.requests] == ["/s", "/t", "/w"]


def test_env_var_name_can_be_chosen(hook):
    send(report(), env={"PROD_SLACK": hook.url("/p")}, notify=["slack"], slack_webhook_url_env="PROD_SLACK")
    assert hook.requests[0][0] == "/p"


# --- values stay out unless asked ---------------------------------------------------------

def test_no_attribute_values_by_default(hook):
    send(report(), notify=["slack", "teams", "webhook"], slack_webhook_url=hook.url("/s"),
         teams_webhook_url=hook.url("/t"), webhook_url=hook.url("/w"))
    for _, _, body in hook.requests:
        text = body.decode()
        assert "t3.small" not in text and "t3.large" not in text  # instance_type values
        assert "ingress[1]" in text or "ingress" in text           # names are kept
    findings = json.loads(hook.requests[2][2])["findings"]
    assert all(set(c) == {"path"} for f in findings for c in f.get("changes", []))
    assert json.loads(hook.requests[2][2])["notification"]["values_included"] is False


def test_notify_values_opt_in(hook):
    send(report(), notify=["slack", "webhook"], notify_values=True, slack_webhook_url=hook.url("/s"),
         webhook_url=hook.url("/w"))
    assert "t3.small → t3.large" in json.dumps(json.loads(hook.requests[0][2]), ensure_ascii=False)
    findings = json.loads(hook.requests[1][2])["findings"]
    assert any("after" in c for f in findings for c in f.get("changes", []))
    assert "old-secret" not in hook.requests[1][2].decode()  # sensitive values stay masked anyway


# --- when to send ---------------------------------------------------------------------------

def test_drift_trigger_sends_nothing_when_clean(hook):
    logs = []
    clean = dr.Report([], "terraform", "plan.json")
    assert send(clean, logs, notify=["slack"], slack_webhook_url=hook.url()) == 0
    assert hook.requests == [] and "nothing sent" in logs[0]
    send(clean, notify=["slack"], notify_on="always", slack_webhook_url=hook.url())
    assert "0 drifted resources" in hook.requests[0][2].decode()


def write_baseline(tmp_path, r):
    path = tmp_path / "baseline.json"
    path.write_text(dr.render_json(r), encoding="utf-8")
    return str(path)


def test_change_trigger_new_and_resolved(hook, tmp_path):
    old = report()
    gone = old.findings.pop(0)          # will be "resolved"
    base_r = dr.Report(list(old.findings), "terraform", "plan.json")
    base_r.findings.append(gone)
    base_r.findings = [f for f in base_r.findings if f.address != "aws_sqs_queue.jobs"]  # will be "new"
    base = write_baseline(tmp_path, base_r)

    current = report()
    current.findings = [f for f in current.findings if f.address != gone.address]
    assert send(current, notify=["slack", "webhook"], notify_on="change", baseline=base,
                slack_webhook_url=hook.url("/s"), webhook_url=hook.url("/w")) == 0
    slack = hook.requests[0][2].decode()
    assert "Since the baseline: 1 new, 1 resolved." in slack
    assert "aws_sqs_queue.jobs" in slack and gone.address in slack
    note = json.loads(hook.requests[1][2])["notification"]
    assert [d["address"] for d in note["new"]] == ["aws_sqs_queue.jobs"]
    assert [d["address"] for d in note["resolved"]] == [gone.address]


def test_change_trigger_quiet_when_nothing_changed(hook, tmp_path):
    logs = []
    base = write_baseline(tmp_path, report())
    assert send(report(), logs, notify=["slack"], notify_on="change", baseline=base,
                slack_webhook_url=hook.url()) == 0
    assert hook.requests == [] and "no new or resolved" in logs[-1]


def test_change_trigger_missing_baseline_counts_everything_new(hook, tmp_path):
    send(report(), notify=["slack"], notify_on="change", baseline=str(tmp_path / "none.json"),
         slack_webhook_url=hook.url())
    assert "6 new, 0 resolved" in hook.requests[0][2].decode()


def test_change_needs_baseline_and_known_channels():
    assert "needs --baseline" in notify.check_args(args(notify=["slack"], notify_on="change"))
    assert "not email" in notify.check_args(args(notify=["email"]))
    assert notify.check_args(args()) == ""


# --- robustness -----------------------------------------------------------------------------

def test_retries_429_and_5xx_with_backoff(hook, no_sleep):
    hook.answers = [(429, {"Retry-After": "3"}), (503, {}), (200, {})]
    logs = []
    assert send(report(), logs, notify=["slack"], slack_webhook_url=hook.url()) == 0
    assert len(hook.requests) == 3 and no_sleep == [3.0, 2.0]
    assert any("sent to" in m for m in logs)


def test_gives_up_without_failing_the_scan(hook, no_sleep):
    hook.answers = [(500, {})] * 10
    logs = []
    assert send(report(), logs, notify=["slack"], slack_webhook_url=hook.url()) == 0
    assert len(hook.requests) == notify.RETRIES + 1
    assert "HTTP 500" in logs[-1] and logs[-1].startswith("warning")
    hook.answers = [(500, {})] * 10
    assert send(report(), notify=["slack"], notify_strict=True, slack_webhook_url=hook.url()) == 1


def test_client_errors_are_not_retried(hook):
    hook.answers = [(404, {})]
    assert send(report(), notify=["teams"], teams_webhook_url=hook.url()) == 0
    assert len(hook.requests) == 1


def test_unreachable_and_missing_urls(no_sleep):
    logs = []
    assert send(report(), logs, env={}, notify=["slack", "webhook"],
                slack_webhook_url=f"http://127.0.0.1:9/services/{TOKEN}") == 0
    assert any("unreachable" in m for m in logs) and any("no URL" in m for m in logs)
    assert send(report(), env={}, notify=["webhook"], notify_strict=True) == 1


def test_urls_are_masked_in_logs(hook, no_sleep):
    hook.answers = [(502, {}), (200, {})]
    logs = []
    send(report(), logs, notify=["slack"], slack_webhook_url=hook.url())
    assert logs and not any(TOKEN in m or "supersecret" in m for m in logs)
    assert any("http://127.0.0.1/***" in m for m in logs)
    assert notify.mask_url("https://hooks.slack.com/services/T/B/x") == "https://hooks.slack.com/***"
    assert notify.mask_url("not a url") == "***"


# --- command line, settings file and run link --------------------------------------------------

def test_main_sends_after_writing_reports(hook, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("WEBHOOK_URL", hook.url("/w"))
    out = tmp_path / "r.json"
    code = dr.main(["terraform", "--plan-json", str(PLAN), "--no-config", "--no-ignore", "-o", str(out),
                    "--notify", "webhook", "--fail-on-drift"])
    assert code == 2 and len(hook.requests) == 1
    assert json.loads(hook.requests[0][2])["summary"]["total"] == 6
    assert "/w" not in capsys.readouterr().err


def test_main_strict_failure_exits_1(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    assert dr.main(["terraform", "--plan-json", str(PLAN), "--no-config", "--no-ignore", "-o", "r.md",
                    "--notify", "slack", "--notify-strict"]) == 1
    assert dr.main(["terraform", "--plan-json", str(PLAN), "--no-config", "--no-ignore", "-o", "r.md",
                    "--notify", "slack"]) == 0


def test_settings_file_names_env_vars_only(hook, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TEAM_HOOK", hook.url("/cfg"))
    (tmp_path / ".driftreport.yml").write_text(
        "notify: [webhook]\nnotify-on: always\nwebhook-url-env: TEAM_HOOK\n", encoding="utf-8")
    assert dr.main(["terraform", "--plan-json", str(PLAN), "--no-ignore", "-o", "r.md"]) == 0
    assert hook.requests[0][0] == "/cfg"

    (tmp_path / ".driftreport.yml").write_text("webhook-url: https://example.com/x\n", encoding="utf-8")
    assert dr.main(["terraform", "--plan-json", str(PLAN), "--no-ignore", "-o", "r.md"]) == 1
    assert "webhook-url-env" in capsys.readouterr().err


def test_run_link_only_in_github_actions():
    assert notify.run_url(GITHUB) == "https://github.com/acme/infra/actions/runs/42"
    assert notify.run_url({}) == ""
    s = notify.build_summary(report(), args(), env={})
    assert "View the run" not in json.dumps(notify.slack_payload(s))
    assert "actions" not in notify.teams_payload(s)["attachments"][0]["content"]


def test_not_in_iac_kinds_and_scope():
    def f(addr, kind="", sev="medium"):
        return dr.Finding(source="aws", location="us-east-1", address=addr, type="aws_s3_bucket",
                          action=dr.UNMANAGED, physical_id=f"arn:aws:s3:::{addr}", severity=sev, kind=kind)
    r = dr.Report([f("a"), f("b", "idle", "high"), f("c", "aws-created", "low")], "aws",
                  "111122223333 (us-east-1)")
    s = notify.build_summary(r, args(), env={})
    assert s["kinds"] == {"idle and not in IaC": 1, "not in IaC": 1, "created by AWS": 1}
    text = json.dumps(notify.slack_payload(s), ensure_ascii=False)
    assert "Account: 111122223333 (us-east-1)" in text
    assert "`b` high · aws_s3_bucket · us-east-1 · idle and not in IaC: arn:aws:s3:::b" in text

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "cloud-drift-report" / "scripts"))

import aws_inventory as inv  # noqa: E402
import drift_report as dr  # noqa: E402


# --- a fake boto3 session --------------------------------------------------

class FakeClient:
    def __init__(self, service, region, data):
        self.service, self.region, self.data = service, region, data

    def can_paginate(self, method):
        return False

    def __getattr__(self, method):
        def call(**kwargs):
            handler = self.data.get((self.service, method))
            if handler is None:
                raise AttributeError(f"{self.service}.{method} not faked")
            return handler(self.region, **kwargs) if callable(handler) else handler
        return call


class FakeSession:
    region_name = "us-east-1"

    def __init__(self, data):
        self.data = data

    def client(self, service, region_name=None, config=None):
        return FakeClient(service, region_name or self.region_name, self.data)


def _denied(region, **kwargs):
    raise RuntimeError("AccessDeniedException: not authorized to perform cloudformation:ListResources")


def _list_resources(region, TypeName, **kwargs):
    rows = {
        "AWS::SQS::Queue": [
            {"Identifier": "https://sqs.us-east-1.amazonaws.com/111111111111/jobs", "Properties": "{}"},
            {"Identifier": "https://sqs.us-east-1.amazonaws.com/111111111111/clickops", "Properties": "{}"},
        ],
        "AWS::Lambda::Function": [{"Identifier": "api-handler", "Properties": json.dumps({"FunctionName": "api-handler"})}],
    }
    if TypeName == "AWS::Glue::Job":
        return _denied(region)
    return {"ResourceDescriptions": rows.get(TypeName, [])}


AWS = {
    ("ec2", "describe_vpcs"): lambda region, **kw: {"Vpcs": [
        {"VpcId": "vpc-default", "IsDefault": True},
        {"VpcId": "vpc-app", "IsDefault": False, "Tags": [{"Key": "Name", "Value": "app"}]},
    ]},
    ("iam", "list_roles"): {"Roles": [
        {"RoleName": "AWSServiceRoleForECS", "Path": "/aws-service-role/ecs.amazonaws.com/",
         "Arn": "arn:aws:iam::111111111111:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS"},
        {"RoleName": "deploy", "Path": "/", "Arn": "arn:aws:iam::111111111111:role/deploy"},
    ]},
    ("cloudcontrol", "list_resources"): _list_resources,
    ("cloudformation", "list_stacks"): {"StackSummaries": [{"StackName": "api"}]},
    ("cloudformation", "list_stack_resources"): {"StackResourceSummaries": [
        {"ResourceType": "AWS::Lambda::Function", "PhysicalResourceId": "api-handler", "LogicalResourceId": "Fn"},
    ]},
    ("sts", "get_caller_identity"): {"Account": "111111111111"},
}

TYPES = ["AWS::EC2::VPC", "AWS::IAM::Role", "AWS::SQS::Queue", "AWS::Lambda::Function", "AWS::Glue::Job"]

STATE = {
    "version": 4,
    "resources": [
        {"mode": "managed", "type": "aws_vpc", "name": "app", "instances": [
            {"attributes": {"id": "vpc-app", "arn": "arn:aws:ec2:us-east-1:111111111111:vpc/vpc-app"}}]},
        {"mode": "managed", "type": "aws_sqs_queue", "name": "jobs", "instances": [
            {"attributes": {"id": "https://sqs.us-east-1.amazonaws.com/111111111111/jobs", "name": "jobs",
                            "arn": "arn:aws:sqs:us-east-1:111111111111:jobs"}}]},
        {"mode": "data", "type": "aws_iam_role", "name": "deploy", "instances": [{"attributes": {"id": "deploy"}}]},
    ],
}


# --- listing ---------------------------------------------------------------

def test_list_inventory_skips_aws_owned_and_records_unlisted_types():
    result = inv.list_inventory(FakeSession(AWS), ["us-east-1"], TYPES, workers=2, log=lambda *a, **k: None)
    ids = {r.identifier for r in result.resources}
    assert ids == {"vpc-app", "deploy", "api-handler",
                   "https://sqs.us-east-1.amazonaws.com/111111111111/jobs",
                   "https://sqs.us-east-1.amazonaws.com/111111111111/clickops"}
    owned = {r.identifier: why for r, why in result.owned}
    assert owned == {"vpc-default": "default VPC resource", "AWSServiceRoleForECS": "service-linked or AWS SSO role"}
    assert result.not_listed == {"AWS::Glue::Job (us-east-1)": "access denied"}
    queue = next(r for r in result.resources if r.identifier.endswith("/clickops"))
    assert queue.name == "clickops" and queue.tf_type == "aws_sqs_queue"


def test_global_types_are_listed_once():
    result = inv.list_inventory(FakeSession(AWS), ["us-east-1", "eu-west-1"], ["AWS::IAM::Role", "AWS::SQS::Queue"],
                                log=lambda *a, **k: None)
    roles = [r for r in result.resources if r.tf_type == "aws_iam_role"]
    queues = [r for r in result.resources if r.tf_type == "aws_sqs_queue"]
    assert len(roles) == 1 and roles[0].region == ""
    assert {q.region for q in queues} == {"us-east-1", "eu-west-1"}


def _elbv2():
    arn = "arn:aws:elasticloadbalancing:us-east-1:111111111111:{}"
    lbs = [{"LoadBalancerArn": arn.format(f"loadbalancer/app/k8s-app-{i}/abc{i}"), "LoadBalancerName": f"k8s-app-{i}"}
           for i in range(25)]
    k8s = [{"Key": "elbv2.k8s.aws/cluster", "Value": "prod"}]
    calls = []

    def describe_tags(region, ResourceArns):
        calls.append(len(ResourceArns))
        assert len(ResourceArns) <= 20
        return {"TagDescriptions": [
            {"ResourceArn": a, "Tags": [{"Key": "Port", "Value": "443"}] if "listener" in a
             else k8s if a.endswith("abc0") or "targetgroup" in a else []}
            for a in ResourceArns]}

    data = {
        ("elbv2", "describe_load_balancers"): {"LoadBalancers": lbs},
        ("elbv2", "describe_target_groups"): {"TargetGroups": [
            {"TargetGroupArn": arn.format("targetgroup/k8s-tg/1"), "TargetGroupName": "k8s-tg"}]},
        ("elbv2", "describe_listeners"): lambda region, LoadBalancerArn: {"Listeners": [
            {"ListenerArn": LoadBalancerArn.replace(":loadbalancer/", ":listener/") + "/l1", "Port": 443}]
            if LoadBalancerArn.endswith("abc0") else []},
        ("elbv2", "describe_tags"): describe_tags,
    }
    return data, calls


def test_elbv2_resources_carry_tags_for_ignore_rules():
    data, calls = _elbv2()
    types = ["AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::ElasticLoadBalancingV2::TargetGroup",
             "AWS::ElasticLoadBalancingV2::Listener"]
    result = inv.list_inventory(FakeSession(data), ["us-east-1"], types, workers=1, log=lambda *a, **k: None)
    by_name = {r.name: r for r in result.resources}
    assert len([r for r in result.resources if r.tf_type == "aws_lb"]) == 25
    assert by_name["k8s-app-0"].arn.endswith("abc0") and by_name["k8s-app-1"].props["Tags"] == []
    assert inv._tag_map(by_name["k8s-app-0"].props["Tags"]) == {"elbv2.k8s.aws/cluster": "prod"}
    assert inv._tag_map(by_name["k8s-tg"].props["Tags"]) == {"elbv2.k8s.aws/cluster": "prod"}
    # The listener keeps its own tags and inherits its load balancer's.
    assert inv._tag_map(by_name["k8s-app-0:443"].props["Tags"]) == {"elbv2.k8s.aws/cluster": "prod", "Port": "443"}
    assert max(calls) == 20


def test_controller_tag_rule_ignores_elbv2_findings(tmp_path, monkeypatch, capsys):
    data, _ = _elbv2()
    data.update({("sts", "get_caller_identity"): {"Account": "111111111111"}})
    monkeypatch.setattr(dr, "aws_session", lambda profile, region: FakeSession(data))
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".driftignore").write_text("tag:elbv2.k8s.aws/cluster\n")
    out = tmp_path / "r.json"
    code = dr.main(["unmanaged", "--region", "us-east-1", "--no-cloudformation", "--type", "aws_lb",
                    "-f", "json", "-o", str(out)])
    assert code == 0
    report = json.loads(out.read_text())
    # Only the untagged load balancers are left; the tagged one, its listener and the target group are ignored.
    assert {f["address"] for f in report["findings"]} == {f"k8s-app-{i}" for i in range(1, 25)}
    assert {i["address"] for i in report["ignored"]} == {"k8s-app-0", "k8s-tg", "k8s-app-0:443"}


# --- matching --------------------------------------------------------------

def _live(tf_type, identifier, region="us-east-1", cc_type="", **props):
    cc = cc_type or next(c for c, t in inv.CLOUDCONTROL_TO_TERRAFORM.items() if t == tf_type)
    return inv.LiveResource(cc, tf_type, identifier, region, inv._name(identifier, props),
                            str(props.get("Arn") or ""), props)


def test_state_and_stacks_mark_resources_managed():
    inventory = inv.list_inventory(FakeSession(AWS), ["us-east-1"], TYPES, log=lambda *a, **k: None)
    iac = inv.parse_state(STATE, "prod.tfstate") + inv.stack_entries(FakeSession(AWS), "us-east-1")
    result = inv.match(inventory, iac)
    assert {r.name for r in result.unmanaged} == {"deploy", "clickops"}  # data sources do not manage anything
    where = {r.identifier: w for r, w in result.managed}
    assert where["vpc-app"] == "prod.tfstate"
    assert where["api-handler"] == "stack api (us-east-1)"


def test_composite_identifier_needs_every_part():
    # Two AppConfig environments of one application must not match each other's state.
    state = {"resources": [{"mode": "managed", "type": "aws_appconfig_environment", "instances": [
        {"attributes": {"id": "env1:app1", "application_id": "app1", "environment_id": "env1"}}]}]}
    entries = inv.parse_state(state, "s")
    env1 = _live("aws_appconfig_environment", "app1|env1")
    env2 = _live("aws_appconfig_environment", "app1|env2")
    result = inv.match(inv.Inventory(resources=[env1, env2]), entries)
    assert [r.identifier for r in result.unmanaged] == ["app1|env2"]


def test_same_name_in_another_region_is_not_managed():
    state = {"resources": [{"mode": "managed", "type": "aws_cloudwatch_log_group", "instances": [
        {"attributes": {"id": "/app/api", "name": "/app/api",
                        "arn": "arn:aws:logs:us-east-1:111111111111:log-group:/app/api"}}]}]}
    here = _live("aws_cloudwatch_log_group", "/app/api", "us-east-1")
    there = _live("aws_cloudwatch_log_group", "/app/api", "eu-west-1")
    result = inv.match(inv.Inventory(resources=[here, there]), inv.parse_state(state, "s"))
    assert [r.region for r in result.unmanaged] == ["eu-west-1"]



def test_same_name_in_another_account_is_not_managed():
    # Only account A's state is supplied; scanning account B, B's /app/api must stay not in IaC.
    state = {"resources": [{"mode": "managed", "type": "aws_cloudwatch_log_group", "instances": [
        {"attributes": {"id": "/app/api", "name": "/app/api",
                        "arn": "arn:aws:logs:us-east-1:111111111111:log-group:/app/api"}}]}]}
    entries = inv.parse_state(state, "s")
    assert entries[0].account == "111111111111"
    in_b = _live("aws_cloudwatch_log_group", "/app/api", "us-east-1")
    assert inv.match(inv.Inventory(resources=[in_b]), entries, "222222222222").unmanaged == [in_b]
    assert inv.match(inv.Inventory(resources=[in_b]), entries, "111111111111").unmanaged == []
    # The live ARN's account wins over the scanned one, and owner_id counts when there is no ARN.
    in_b.arn = "arn:aws:logs:us-east-1:222222222222:log-group:/app/api"
    assert inv.match(inv.Inventory(resources=[in_b]), entries).unmanaged == [in_b]
    vpc = {"resources": [{"mode": "managed", "type": "aws_vpc", "instances": [
        {"attributes": {"id": "vpc-1", "owner_id": "111111111111"}}]}]}
    assert inv.parse_state(vpc, "s")[0].account == "111111111111"
    # Another resource's ARN in an attribute says nothing about this one's account.
    perm = {"resources": [{"mode": "managed", "type": "aws_lambda_permission", "instances": [
        {"attributes": {"id": "allow-s3", "source_arn": "arn:aws:s3:us-east-1:333333333333:x"}}]}]}
    assert inv.parse_state(perm, "s")[0].account == ""
    # On member and sharing types account_id is the other side, so it doesn't set the account.
    member = {"resources": [{"mode": "managed", "type": "aws_guardduty_member", "instances": [
        {"attributes": {"id": "det1:333333333333", "detector_id": "det1", "account_id": "333333333333"}}]}]}
    assert inv.parse_state(member, "s")[0].account == ""
    lines = inv.explain(inv.Inventory(resources=[in_b]), entries, "/app/api", "222222222222")
    assert lines[1] == "  Close: aws_cloudwatch_log_group in s (recorded for account 111111111111)."
    # The same id in two accounts' state files is not a duplicate import.
    other = json.loads(json.dumps(state).replace("111111111111", "222222222222"))
    assert inv.duplicate_imports(entries + inv.parse_state(other, "t")) == []

def test_terraform_type_aliases_match():
    state = {"resources": [{"mode": "managed", "type": "aws_alb", "instances": [
        {"attributes": {"id": "arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/web/abc",
                        "arn": "arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/web/abc", "name": "web"}}]}]}
    lb = _live("aws_lb", "arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/web/abc")
    assert inv.match(inv.Inventory(resources=[lb]), inv.parse_state(state, "s")).unmanaged == []


# --- AWS-owned rules -------------------------------------------------------

def test_aws_owned_rules():
    owned = [
        _live("aws_security_group", "sg-1", GroupName="default"),
        _live("aws_kms_key", "k1", KeyManager="AWS"),
        _live("aws_kms_alias", "alias/aws/s3"),
        _live("aws_subnet", "subnet-1", DefaultForAz=True),
        _live("aws_route_table", "rtb-1", Main=True),
        _live("aws_vpc_endpoint", "vpce-1", RequesterManaged=True),
        _live("aws_secretsmanager_secret", "arn:aws:secretsmanager:us-east-1:1:secret:rds!db-1-abc"),
        _live("aws_instance", "i-1", Tags=[{"Key": "aws:autoscaling:groupName", "Value": "asg"}]),
        _live("aws_ebs_volume", "vol-1", LaunchedWithInstance=True),
        _live("aws_db_parameter_group", "default.postgres16"),
        _live("aws_cloudwatch_event_bus", "default"),
        _live("aws_route53_resolver_rule", "rslvr-autodefined-rr-internet-resolver"),
    ]
    for res in owned:
        assert inv.aws_owned_reason(res), res
    customer = [
        _live("aws_security_group", "sg-2", GroupName="web"),
        _live("aws_kms_key", "k2", KeyManager="CUSTOMER"),
        _live("aws_iam_role", "deploy", Path="/"),
        _live("aws_instance", "i-2", Tags=[{"Key": "Name", "Value": "bastion"}]),
        _live("aws_secretsmanager_secret", "arn:aws:secretsmanager:us-east-1:1:secret:app/db-abc"),
    ]
    for res in customer:
        assert not inv.aws_owned_reason(res), res


# --- CLI end to end ----------------------------------------------------------

def test_cli_unmanaged_report(tmp_path, monkeypatch, capsys):
    state_file = tmp_path / "prod.tfstate"
    state_file.write_text(json.dumps(STATE))
    monkeypatch.setattr(dr, "aws_session", lambda profile, region: FakeSession(AWS))
    monkeypatch.setattr(inv, "CLOUDCONTROL_TO_TERRAFORM", {t: inv.CLOUDCONTROL_TO_TERRAFORM[t] for t in TYPES})
    out = tmp_path / "report.json"
    code = dr.main(["unmanaged", "--region", "us-east-1", "--state", str(state_file), "-f", "json",
                    "-o", str(out), "--fail-on-drift"])
    assert code == 2
    doc = json.loads(out.read_text())
    assert doc["source"] == "aws" and doc["target"] == "111111111111 (us-east-1)"
    assert {f["address"] for f in doc["findings"]} == {"deploy", "clickops"}
    assert all(f["action"] == dr.UNMANAGED for f in doc["findings"])
    severity = {f["address"]: f["severity"] for f in doc["findings"]}
    assert severity == {"deploy": "high", "clickops": "medium"}  # IAM is security relevant
    cov = doc["coverage"]
    assert (cov["listed"], cov["in_iac"], cov["not_in_iac"], cov["aws_owned_skipped"]) == (5, 3, 2, 2)
    assert cov["not_listed"] == {"AWS::Glue::Job (us-east-1)": "access denied"}
    assert "2 resources not in IaC" in capsys.readouterr().err


def test_markdown_and_html_wording():
    f = dr.finalize(dr.Finding(source="aws", location="us-east-1", address="clickops", type="aws_sqs_queue",
                               action=dr.UNMANAGED, physical_id="https://sqs/clickops"))
    report = dr.Report([f], "aws", "111 (us-east-1)", coverage={"listed": 3, "in_iac": 2, "not_in_iac": 1,
                                                                 "aws_owned_skipped": 4})
    md = dr.render_markdown(report)
    assert md.startswith("# Not in IaC: 111 (us-east-1)")
    assert "**1 resource not in IaC**" in md
    assert "Coverage: 3 resources listed · 2 in IaC · 1 not in IaC · 4 AWS-owned skipped." in md
    assert "adopted into Terraform" in md
    page = dr.render_html(report)
    assert "<h1>Not in IaC: 111 (us-east-1)</h1>" in page and "resource not in IaC" in page
    empty = dr.render_markdown(dr.Report([], "aws", "x"))
    assert "Everything listed is in IaC." in empty


# --- assuming a role -------------------------------------------------------

class FakeSts:
    def __init__(self, calls, fail=False):
        self.calls, self.fail = calls, fail

    def assume_role(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail:
            raise RuntimeError("AccessDenied: not authorized to perform sts:AssumeRole")
        import datetime
        expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        return {"Credentials": {"AccessKeyId": "ASIAROLE", "SecretAccessKey": "s", "SessionToken": "t",
                                "Expiration": expires}}


class FakeCaller:
    """Stands in for a boto3 session: the caller's own credentials and an STS client."""

    region_name = "eu-west-1"

    def __init__(self, fail=False):
        from botocore.credentials import Credentials
        self.calls = []
        self._creds = Credentials("AKIAOWN", "secret")
        self._session = self
        self.fail = fail

    def get_credentials(self):
        return self._creds

    def create_client(self, service, *args, **kwargs):
        assert service == "sts"
        return FakeSts(self.calls, self.fail)


def test_assume_role_uses_external_id_and_keeps_region():
    caller = FakeCaller()
    session = dr.assume_role(caller, "arn:aws:iam::222222222222:role/drift-read", "ext-123", "ci-run")
    assert caller.calls == [{"RoleArn": "arn:aws:iam::222222222222:role/drift-read", "RoleSessionName": "ci-run",
                             "ExternalId": "ext-123"}]
    assert session.get_credentials().get_frozen_credentials().access_key == "ASIAROLE"
    assert session.region_name == "eu-west-1"


def test_assume_role_failure_is_clear():
    import pytest
    with pytest.raises(RuntimeError, match="Could not assume arn:aws:iam::222222222222:role/x"):
        dr.assume_role(FakeCaller(fail=True), "arn:aws:iam::222222222222:role/x")


def test_state_is_read_as_yourself_first_then_as_the_role():
    base, role, tried = object(), object(), []

    def read(src, session):
        tried.append(session)
        if session is base:
            raise RuntimeError("AccessDenied")
        return [("s3://b/k.tfstate", {})]

    assert dr.read_state("s3://b/k.tfstate", base, role, read) == [("s3://b/k.tfstate", {})]
    assert tried == [base, role]
    tried.clear()
    dr.read_state("./local.tfstate", base, role, lambda src, session: tried.append(session))
    assert tried == [role]  # local files and directories don't use AWS credentials for the read


def test_state_read_error_names_both_attempts():
    import pytest

    def read(src, session):
        raise RuntimeError("denied " + session)

    with pytest.raises(RuntimeError, match=r"your own credentials \(denied own\).*assumed role \(denied role\)"):
        dr.read_state("s3://b/", "own", "role", read)


def test_cli_scans_the_assumed_account(tmp_path, monkeypatch):
    own = FakeSession(AWS)
    target = FakeSession({**AWS, ("sts", "get_caller_identity"): {"Account": "222222222222"}})
    seen = {}

    def fake_assume(session, role_arn, external_id, session_name):
        seen.update(base=session, role=role_arn, ext=external_id, name=session_name)
        return target

    monkeypatch.setattr(dr, "aws_session", lambda profile, region: own)
    monkeypatch.setattr(dr, "assume_role", fake_assume)
    monkeypatch.setattr(inv, "CLOUDCONTROL_TO_TERRAFORM", {t: inv.CLOUDCONTROL_TO_TERRAFORM[t] for t in TYPES})
    out = tmp_path / "r.json"
    dr.main(["unmanaged", "--region", "us-east-1", "--role-arn", "arn:aws:iam::222222222222:role/drift-read",
             "--external-id", "ext-1", "-f", "json", "-o", str(out)])
    assert seen == {"base": own, "role": "arn:aws:iam::222222222222:role/drift-read", "ext": "ext-1",
                    "name": "cloud-drift-report"}
    assert json.loads(out.read_text())["target"] == "222222222222 (us-east-1)"


# --- Organizations / Control Tower, --strict, coverage, duplicates, --explain ----

def test_organizations_and_control_tower_defaults_are_aws_owned():
    owned = [
        _live("aws_iam_role", "OrganizationAccountAccessRole", RoleName="OrganizationAccountAccessRole", Path="/"),
        _live("aws_iam_role", "AWSControlTowerExecution", RoleName="AWSControlTowerExecution", Path="/"),
        _live("aws_iam_role", "aws-controltower-ConfigRecorderRole", RoleName="aws-controltower-ConfigRecorderRole"),
        _live("aws_iam_role", "stacksets-exec-1a2b3c", RoleName="stacksets-exec-1a2b3c", Path="/"),
        _live("aws_iam_role", "AWSCloudFormationStackSetExecutionRole", RoleName="AWSCloudFormationStackSetExecutionRole"),
        _live("aws_cloudwatch_log_group", "aws-controltower/CloudTrailLogs", LogGroupName="aws-controltower/CloudTrailLogs"),
    ]
    for res in owned:
        assert inv.aws_owned_reason(res), res
    assert not inv.aws_owned_reason(_live("aws_iam_role", "OrgAdmin", RoleName="OrgAdmin", Path="/"))


def test_duplicate_imports_name_both_addresses():
    state = {"resources": [
        {"mode": "managed", "type": "aws_s3_bucket", "name": "logs", "instances": [{"attributes": {"id": "acme-logs"}}]},
        {"mode": "managed", "module": "module.audit", "type": "aws_s3_bucket", "name": "trail",
         "instances": [{"index_key": "a", "attributes": {"id": "acme-logs"}}]},
        {"mode": "managed", "type": "aws_s3_bucket", "name": "other", "instances": [{"attributes": {"id": "acme-other"}}]},
    ]}
    dups = inv.duplicate_imports(inv.parse_state(state, "prod.tfstate"))
    assert dups == [{"type": "aws_s3_bucket", "id": "acme-logs",
                     "addresses": ["aws_s3_bucket.logs (prod.tfstate)", 'module.audit.aws_s3_bucket.trail["a"] (prod.tfstate)']}]


def test_explain_says_why():
    inventory = inv.list_inventory(FakeSession(AWS), ["us-east-1"], TYPES, log=lambda *a, **k: None)
    iac = inv.parse_state(STATE, "prod.tfstate")
    lines = inv.explain(inventory, iac, "jobs")
    assert lines == ["aws_sqs_queue jobs (us-east-1): in IaC, matched aws_sqs_queue.jobs in prod.tfstate."]
    lines = inv.explain(inventory, iac, "clickops")
    assert lines[0].startswith("aws_sqs_queue clickops (us-east-1): NOT in IaC. Looked for any of: ")
    assert lines[1] == "  1 aws_sqs_queue entries compared; none has these values."
    assert inv.explain(inventory, iac, "deploy")[1] == "  No aws_iam_role or AWS::IAM::Role entries in the state files or stacks compared."
    assert inv.explain(inventory, iac, "vpc-default") == [
        "aws_vpc vpc-default (us-east-1): skipped as AWS-owned (default VPC resource); --strict reports it."]
    assert inv.explain(inventory, iac, "nothing-like-this")[0].startswith("nothing-like-this: not among the 7 listed")


def test_explain_points_at_another_region():
    state = {"resources": [{"mode": "managed", "type": "aws_cloudwatch_log_group", "name": "api", "instances": [
        {"attributes": {"id": "/app/api", "name": "/app/api", "arn": "arn:aws:logs:eu-west-1:1:log-group:/app/api"}}]}]}
    here = _live("aws_cloudwatch_log_group", "/app/api", "us-east-1")
    lines = inv.explain(inv.Inventory(resources=[here]), inv.parse_state(state, "s"), "/app/api")
    assert lines[1] == "  Close: aws_cloudwatch_log_group.api in s (recorded for region eu-west-1)."


def test_cli_strict_coverage_and_explain(tmp_path, monkeypatch, capsys):
    state_file = tmp_path / "prod.tfstate"
    state_file.write_text(json.dumps(STATE))
    monkeypatch.setattr(dr, "aws_session", lambda profile, region: FakeSession(AWS))
    monkeypatch.setattr(inv, "CLOUDCONTROL_TO_TERRAFORM", {t: inv.CLOUDCONTROL_TO_TERRAFORM[t] for t in TYPES})
    out = tmp_path / "r.json"
    dr.main(["unmanaged", "--region", "us-east-1", "--state", str(state_file), "-f", "json", "-o", str(out),
             "--explain", "clickops"])
    cov = json.loads(out.read_text())["coverage"]
    assert cov["percent_in_iac"] == 60.0 and cov["by_type"]["aws_sqs_queue"] == {"in_iac": 1, "not_in_iac": 1}
    err = capsys.readouterr().err
    assert "aws_sqs_queue clickops (us-east-1): NOT in IaC" in err
    assert "Coverage: 60% in IaC" in dr.coverage_line(cov)

    dr.main(["unmanaged", "--region", "us-east-1", "--state", str(state_file), "-f", "json", "-o", str(out), "--strict"])
    doc = json.loads(out.read_text())
    strict = {f["address"]: f for f in doc["findings"]}
    assert set(strict) == {"deploy", "clickops", "vpc-default", "AWSServiceRoleForECS"}
    assert strict["vpc-default"]["severity"] == "low"
    assert strict["vpc-default"]["explanation"] == "AWS created this (default VPC resource); shown because of --strict."
    assert doc["coverage"]["aws_owned_skipped"] == 0


def test_coverage_line_warns_about_duplicates():
    line = dr.coverage_line({"listed": 2, "in_iac": 1, "not_in_iac": 1, "percent_in_iac": 50.0,
                             "duplicate_imports": [{"type": "aws_s3_bucket", "id": "acme-logs", "addresses": ["a", "b"]}]})
    assert line.startswith("Coverage: 50% in IaC · 2 resources listed")
    assert line.endswith("Warning: 1 resource is in state at more than one address (aws_s3_bucket acme-logs); "
                         "see the JSON output.")


# --- idle and still billing ------------------------------------------------

IDLE_AWS = {
    ("ec2", "describe_route_tables"): {"RouteTables": [{"RouteTableId": "rtb-1", "Routes": [
        {"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"},
        {"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-used"}]}]},
    ("ec2", "describe_nat_gateways"): lambda region, Filter, **kw: {"NatGateways": [
        {"NatGatewayId": "nat-used", "VpcId": "vpc-app", "SubnetId": "subnet-a"},
        {"NatGatewayId": "nat-idle", "VpcId": "vpc-app", "SubnetId": "subnet-b",
         "NatGatewayAddresses": [{"AllocationId": "eipalloc-nat", "PublicIp": "203.0.113.7"}]},
        {"NatGatewayId": "nat-idle-tf", "VpcId": "vpc-app", "SubnetId": "subnet-c"}]},
    ("ec2", "describe_addresses"): {"Addresses": [
        {"AllocationId": "eipalloc-used", "PublicIp": "3.3.3.3", "AssociationId": "eipassoc-1"},
        {"AllocationId": "eipalloc-spare", "PublicIp": "4.4.4.4"},
        {"AllocationId": "eipalloc-alb", "PublicIp": "5.5.5.5", "ServiceManaged": "alb"}]},
}

IDLE_STATE = {"version": 4, "resources": [
    {"mode": "managed", "type": "aws_nat_gateway", "name": "main", "instances": [{"attributes": {"id": "nat-idle-tf"}}]},
    {"mode": "managed", "type": "aws_nat_gateway", "name": "used", "instances": [{"attributes": {"id": "nat-used"}}]},
    {"mode": "managed", "type": "aws_eip", "name": "used", "instances": [{"attributes": {"id": "eipalloc-used"}}]},
]}


def test_nat_gateway_routed_and_eip_attached():
    s = FakeSession(IDLE_AWS)
    listed = {r["Identifier"]: r["Properties"] for r in inv._nat_gateways(s, "us-east-1")}
    assert {k: v["Routed"] for k, v in listed.items()} == {"nat-used": True, "nat-idle": False, "nat-idle-tf": False}
    assert listed["nat-idle"]["PublicIps"] == 1 and listed["nat-used"]["PublicIps"] == 0
    eips = {r["Identifier"]: r["Properties"]["Attached"] for r in inv._elastic_ips(s, "us-east-1")}
    assert eips == {"eipalloc-used": True, "eipalloc-spare": False, "eipalloc-alb": False}


def _price(usagetype, usd):
    return json.dumps({"product": {"attributes": {"usagetype": usagetype}},
                       "terms": {"OnDemand": {"t": {"priceDimensions": {"d": {"pricePerUnit": {"USD": usd}}}}}}})


def _get_products(region, ServiceCode, Filters, **kwargs):
    where = {f["Field"]: f["Value"] for f in Filters}
    assert region == "us-east-1"  # the pricing endpoint, whatever region is priced
    prefix = {"eu-west-1": "EU-", "us-east-1": ""}[where["regionCode"]]
    if ServiceCode == "AmazonEC2":
        assert where["operation"] == "NatGateway"
        return {"PriceList": [_price(prefix + "NatGateway-Bytes", "0.048"), _price("RegionalNatGateway-Hours", "9"),
                              _price(prefix + "NatGateway-Hours", "0.048")]}
    return {"PriceList": [_price(prefix + "PublicIPv4:InUseAddress", "0.005"),
                          _price(prefix + "PublicIPv4:IdleAddress", "0.006")]}


PRICING = {("pricing", "get_products"): _get_products}


def test_idle_cost_uses_live_regional_prices():
    prices = inv.Prices(FakeSession(PRICING))
    nat = _live("aws_nat_gateway", "nat-1", Routed=False, PublicIps=2)
    nat.region = "eu-west-1"
    why, monthly = inv.idle_cost(nat, prices)
    assert why.endswith("about $42.34/month ($35.04 for the gateway, $7.30 for 2 public IPv4 addresses) in eu-west-1")
    assert round(monthly, 2) == 42.34
    eip = _live("aws_eip", "eipalloc-1", Attached=False)
    eip.region = "eu-west-1"
    assert inv.idle_reason(eip, prices) == "attached to nothing; an Elastic IP still bills about $4.38/month in eu-west-1"


def test_idle_cost_falls_back_to_us_east_1_prices_once():
    notes = []
    denied = {("pricing", "get_products"): lambda region, **kw: (_ for _ in ()).throw(
        RuntimeError("AccessDeniedException: not authorized to perform pricing:GetProducts"))}
    prices = inv.Prices(FakeSession(denied), log=lambda *a, **k: notes.append(a[0]))
    nat = inv.idle_reason(_live("aws_nat_gateway", "nat-1", Routed=False, PublicIps=1), prices)
    assert "about $36.50/month ($32.85 for the gateway, $3.65 for 1 public IPv4 address)" in nat
    assert nat.endswith("(us-east-1 list price used where the live us-east-1 price could not be read)")
    assert "$32.85/month" in inv.idle_reason(_live("aws_nat_gateway", "nat-2", Routed=False), prices)  # private NAT
    assert len(notes) == 1 and "access denied" in notes[0]


def test_idle_reason():
    assert inv.idle_reason(_live("aws_nat_gateway", "nat-1", Routed=True)) == ""
    assert inv.idle_reason(_live("aws_nat_gateway", "nat-1")) == ""  # listed without route data: say nothing
    assert "$3.65/month" in inv.idle_reason(_live("aws_eip", "eipalloc-1", Attached=False))
    assert inv.idle_reason(_live("aws_eip", "eipalloc-1", Attached=False, ServiceManaged="nlb")) == ""


def test_cli_flags_idle_nat_and_eip_in_and_out_of_iac(tmp_path, monkeypatch):
    state_file = tmp_path / "net.tfstate"
    state_file.write_text(json.dumps(IDLE_STATE))
    monkeypatch.setattr(dr, "aws_session", lambda profile, region: FakeSession({**AWS, **IDLE_AWS, **PRICING}))
    monkeypatch.setattr(inv, "CLOUDCONTROL_TO_TERRAFORM", {t: inv.CLOUDCONTROL_TO_TERRAFORM[t]
                                                           for t in ("AWS::EC2::NatGateway", "AWS::EC2::EIP")})
    out = tmp_path / "r.json"
    dr.main(["unmanaged", "--region", "us-east-1", "--state", str(state_file), "-f", "json", "-o", str(out)])
    doc = json.loads(out.read_text())
    found = {f["address"]: f for f in doc["findings"]}
    assert set(found) == {"nat-idle", "eipalloc-spare", "eipalloc-alb"}
    assert found["nat-idle"]["severity"] == "high"
    assert found["nat-idle"]["explanation"].startswith("Not in IaC and idle: no route table")
    assert found["eipalloc-spare"]["severity"] == "high"
    assert found["eipalloc-alb"]["severity"] == "medium"
    idle = {(i["id"], i["in_iac"]) for i in doc["coverage"]["idle"]}
    assert idle == {("nat-idle", False), ("nat-idle-tf", True), ("eipalloc-spare", False)}
    costs = {i["id"]: i["monthly_usd"] for i in doc["coverage"]["idle"]}
    assert costs == {"nat-idle": 38.69, "nat-idle-tf": 35.04, "eipalloc-spare": 4.38}
    line = dr.coverage_line(doc["coverage"])
    assert "Idle and still billing: " in line and "aws_nat_gateway nat-idle-tf (in IaC)" in line


def _quiet_aws(calls):
    from datetime import datetime, timedelta, timezone
    old, new = datetime.now(timezone.utc) - timedelta(days=60), datetime.now(timezone.utc) - timedelta(days=2)
    traffic = {"nat-quiet": [1e6, 2e6], "nat-busy": [4e9, 3e9]}

    def get_metric_data(region, MetricDataQueries, StartTime, EndTime, **kw):
        calls.append([q["MetricStat"]["Metric"]["Dimensions"][0]["Value"] for q in MetricDataQueries])
        assert (EndTime - StartTime).days == inv.QUIET_DAYS
        return {"MetricDataResults": [
            {"Id": q["Id"], "Values": traffic[q["MetricStat"]["Metric"]["Dimensions"][0]["Value"]]}
            for q in MetricDataQueries]}

    return {
        ("ec2", "describe_route_tables"): {"RouteTables": [{"RouteTableId": "rtb-1", "Routes": [
            {"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": nat} for nat in ("nat-quiet", "nat-busy", "nat-new")]}]},
        ("ec2", "describe_nat_gateways"): lambda region, Filter, **kw: {"NatGateways": [
            {"NatGatewayId": "nat-quiet", "CreateTime": old,
             "NatGatewayAddresses": [{"AllocationId": "eipalloc-q", "PublicIp": "203.0.113.9"}]},
            {"NatGatewayId": "nat-busy", "CreateTime": old},
            {"NatGatewayId": "nat-new", "CreateTime": new},
            {"NatGatewayId": "nat-unrouted", "CreateTime": old}]},
        ("cloudwatch", "get_metric_data"): get_metric_data,
    }


def test_routed_nat_with_almost_no_traffic_is_quiet():
    calls = []
    listed = {r["Identifier"]: r["Properties"] for r in inv._nat_gateways(FakeSession(_quiet_aws(calls)), "us-east-1")}
    # Only routed gateways at least 14 days old are looked up; one call for all of them.
    assert calls == [["nat-quiet", "nat-quiet", "nat-busy", "nat-busy"]]
    assert listed["nat-quiet"]["BytesLast14Days"] == 6e6 and listed["nat-busy"]["BytesLast14Days"] == 14e9
    assert "BytesLast14Days" not in listed["nat-new"] and "BytesLast14Days" not in listed["nat-unrouted"]
    quiet = inv.idle_reason(_live("aws_nat_gateway", "nat-quiet", **listed["nat-quiet"]))
    assert quiet.startswith("a route table points at it, but it moved only 6.0 MB in the last 14 days; "
                            "a NAT gateway that quiet still bills about $36.50/month")
    assert inv.idle_reason(_live("aws_nat_gateway", "nat-busy", **listed["nat-busy"])) == ""
    assert inv.idle_reason(_live("aws_nat_gateway", "nat-new", **listed["nat-new"])) == ""


def test_nat_traffic_unreadable_says_nothing():
    data = _quiet_aws([])
    data[("cloudwatch", "get_metric_data")] = _denied
    listed = {r["Identifier"]: r["Properties"] for r in inv._nat_gateways(FakeSession(data), "us-east-1")}
    assert all("BytesLast14Days" not in p for p in listed.values())


def test_cli_reports_quiet_nat_as_medium(tmp_path, monkeypatch):
    monkeypatch.setattr(dr, "aws_session", lambda profile, region: FakeSession({**AWS, **_quiet_aws([]), **PRICING}))
    monkeypatch.setattr(inv, "CLOUDCONTROL_TO_TERRAFORM", {"AWS::EC2::NatGateway": "aws_nat_gateway"})
    out = tmp_path / "r.json"
    dr.main(["unmanaged", "--region", "us-east-1", "--no-cloudformation", "-f", "json", "-o", str(out)])
    found = {f["address"]: f for f in json.loads(out.read_text())["findings"]}
    assert found["nat-quiet"]["severity"] == "medium"
    assert found["nat-quiet"]["explanation"].startswith("Not in IaC and nearly unused: a route table points at it")
    assert found["nat-unrouted"]["severity"] == "high"
    assert not found["nat-busy"]["explanation"].startswith("Not in IaC and")  # an ordinary unmanaged gateway

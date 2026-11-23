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

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "cloud-drift-report" / "scripts"))

import aws_inventory as inv  # noqa: E402
import drift_report as dr  # noqa: E402
import eol  # noqa: E402

NOW = datetime(2026, 11, 28, tzinfo=timezone.utc)
QUIET = dict(log=lambda *a, **k: None)


class FakeClient:
    def __init__(self, service, region, data):
        self.service, self.region, self.data = service, region, data

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


def _cycles(major, std_end, ext_start, ext_end):
    return {"MajorEngineVersion": major, "SupportedEngineLifecycles": [
        {"LifecycleSupportName": "open-source-rds-standard-support", "LifecycleSupportStartDate": "2019-01-01T00:00:00Z",
         "LifecycleSupportEndDate": std_end},
        {"LifecycleSupportName": "open-source-rds-extended-support", "LifecycleSupportStartDate": ext_start,
         "LifecycleSupportEndDate": ext_end}]}


MAJORS = {
    "mysql": [_cycles("5.7", "2024-02-29T23:59:59Z", "2024-03-01T00:00:00Z", "2029-06-30T00:00:00Z"),
              _cycles("8.0", "2027-01-31T23:59:59Z", "2027-02-01T00:00:00Z", "2029-07-31T00:00:00Z")],
    "postgres": [_cycles("11", "2024-02-29T23:59:59Z", "2024-03-01T00:00:00Z", "2026-03-31T00:00:00Z"),
                 _cycles("13", "2026-02-28T23:59:59Z", "2026-03-01T00:00:00Z", "2029-02-28T00:00:00Z"),
                 _cycles("16", "2029-02-28T23:59:59Z", "2029-03-01T00:00:00Z", "2032-02-28T00:00:00Z")],
    "aurora-postgresql": [_cycles("13", "2026-02-28T23:59:59Z", "2026-03-01T00:00:00Z", "2029-02-28T00:00:00Z")],
    "aurora-mysql": [],
}

INSTANCES = [
    {"DBInstanceIdentifier": "legacy-mysql", "Engine": "mysql", "EngineVersion": "5.7.44", "DBInstanceClass": "db.r6g.large",
     "MultiAZ": True, "DBInstanceArn": "arn:aws:rds:us-east-1:111111111111:db:legacy-mysql",
     "TagList": [{"Key": "team", "Value": "billing"}]},
    {"DBInstanceIdentifier": "old-pg", "Engine": "postgres", "EngineVersion": "11.22", "DBInstanceClass": "db.t3.micro",
     "DBInstanceArn": "arn:aws:rds:us-east-1:111111111111:db:old-pg"},
    {"DBInstanceIdentifier": "app-mysql", "Engine": "mysql", "EngineVersion": "8.0.40", "DBInstanceClass": "db.t3.micro",
     "DBInstanceArn": "arn:aws:rds:us-east-1:111111111111:db:app-mysql"},
    {"DBInstanceIdentifier": "no-ext", "Engine": "postgres", "EngineVersion": "13.15", "DBInstanceClass": "db.t3.micro",
     "EngineLifecycleSupport": "open-source-rds-extended-support-disabled",
     "DBInstanceArn": "arn:aws:rds:us-east-1:111111111111:db:no-ext"},
    {"DBInstanceIdentifier": "current", "Engine": "postgres", "EngineVersion": "16.4", "DBInstanceClass": "db.t3.micro",
     "DBInstanceArn": "arn:aws:rds:us-east-1:111111111111:db:current"},
    {"DBInstanceIdentifier": "aurora-1", "Engine": "aurora-postgresql", "EngineVersion": "13.12",
     "DBInstanceClass": "db.serverless", "DBClusterIdentifier": "orders",
     "DBInstanceArn": "arn:aws:rds:us-east-1:111111111111:db:aurora-1"},
    {"DBInstanceIdentifier": "oracle", "Engine": "oracle-ee", "EngineVersion": "19.0", "DBInstanceClass": "db.r5.large"},
]

VERSIONS = [
    {"clusterVersion": "1.29", "endOfStandardSupportDate": "2025-03-23T00:00:00Z",
     "endOfExtendedSupportDate": "2026-03-23T00:00:00Z", "versionStatus": "UNSUPPORTED"},
    {"clusterVersion": "1.32", "endOfStandardSupportDate": "2026-03-23T00:00:00Z",
     "endOfExtendedSupportDate": "2027-03-23T00:00:00Z", "versionStatus": "EXTENDED_SUPPORT"},
    {"clusterVersion": "1.34", "endOfStandardSupportDate": "2026-12-02T00:00:00Z",
     "endOfExtendedSupportDate": "2027-12-02T00:00:00Z", "versionStatus": "STANDARD_SUPPORT"},
    {"clusterVersion": "1.35", "endOfStandardSupportDate": "2027-03-27T00:00:00Z",
     "endOfExtendedSupportDate": "2028-03-27T00:00:00Z", "versionStatus": "STANDARD_SUPPORT"},
]
CLUSTERS = {
    "ancient": {"version": "1.29", "upgradePolicy": {"supportType": "EXTENDED"}},
    "paying": {"version": "1.32", "upgradePolicy": {"supportType": "EXTENDED"}, "tags": {"env": "prod"}},
    "auto": {"version": "1.32", "upgradePolicy": {"supportType": "STANDARD"}},
    "soon": {"version": "1.34", "upgradePolicy": {"supportType": "EXTENDED"}},
    "fine": {"version": "1.35"},
}

FUNCTIONS = [
    {"FunctionName": "cron", "FunctionArn": "arn:aws:lambda:us-east-1:111111111111:function:cron", "Runtime": "python3.9"},
    {"FunctionName": "api", "FunctionArn": "arn:aws:lambda:us-east-1:111111111111:function:api", "Runtime": "python3.12"},
    {"FunctionName": "image", "FunctionArn": "arn:aws:lambda:us-east-1:111111111111:function:image", "PackageType": "Image"},
]


def _price_list(region, ServiceCode, Filters, **kwargs):
    f = {x["Field"]: x["Value"] for x in Filters}
    prefix = "" if region == "us-east-1" and f["regionCode"] == "us-east-1" else "APS3-"
    if ServiceCode == "AmazonEKS":
        rows = [(f"{prefix}AmazonEKS-Hours:extendedSupport", "0.50"), (f"{prefix}AmazonEKS-Hours:perCluster", "0.10")]
    else:
        yr = "Yr1-Yr2" if f["extendedSupportPricingYear"] == "Year 1, Year 2" else "Yr3"
        major = f["engineMajorVersion"]
        rows = [(f"{prefix}ExtendedSupport:{yr}:MySQL{major}", "0.10" if yr == "Yr1-Yr2" else "0.20"),
                (f"{prefix}ExtendedSupport:{yr}:PostgreSQL{major}", "0.10" if yr == "Yr1-Yr2" else "0.20"),
                (f"{prefix}ExtendedSupport:{yr}:ASv2:AuroraPostgreSQL{major}", "0.085"),
                (f"{prefix}ExtendedSupport:{yr}:AuroraMySQL2:PP", "9.99")]
    return {"PriceList": [json.dumps({"product": {"attributes": {"usagetype": ut}}, "terms": {"OnDemand": {"t": {
        "priceDimensions": {"d": {"pricePerUnit": {"USD": usd}}}}}}}) for ut, usd in rows]}


AWS = {
    ("rds", "describe_db_instances"): {"DBInstances": INSTANCES},
    ("rds", "describe_db_clusters"): {"DBClusters": [
        {"DBClusterIdentifier": "orders", "ServerlessV2ScalingConfiguration": {"MinCapacity": 2, "MaxCapacity": 16}}]},
    ("rds", "describe_db_major_engine_versions"): lambda region, Engine, **k: {"DBMajorEngineVersions": MAJORS[Engine]},
    ("ec2", "describe_instance_types"): lambda region, InstanceTypes: {"InstanceTypes": [
        {"VCpuInfo": {"DefaultVCpus": {"r6g.large": 2, "t3.micro": 2}[InstanceTypes[0]]}}]},
    ("eks", "list_clusters"): {"clusters": list(CLUSTERS)},
    ("eks", "describe_cluster_versions"): {"clusterVersions": VERSIONS},
    ("eks", "describe_cluster"): lambda region, name: {"cluster": {
        "name": name, "arn": f"arn:aws:eks:{region}:111111111111:cluster/{name}", **CLUSTERS[name]}},
    ("lambda", "list_functions"): {"Functions": FUNCTIONS},
    ("pricing", "get_products"): _price_list,
    ("sts", "get_caller_identity"): {"Account": "111111111111"},
}


def _scan(data=AWS, regions=("us-east-1",), **kw):
    session = FakeSession(data)
    return eol.scan(session, list(regions), inv.Prices(session, **QUIET), now=NOW, **QUIET, **kw)


def _by_name(res):
    return {f.address: f for f in res.findings}


def test_rds_statuses_and_costs():
    found = _by_name(_scan())
    mysql = found["legacy-mysql"]
    # 5.7 extended support started 2024-03-01, so November 2026 is year 3: $0.20 x 2 vCPUs x 2 (Multi-AZ) x 730 h.
    assert (mysql.status, mysql.severity, mysql.ends) == (eol.PAID, "medium", "2029-06-30")
    assert mysql.monthly_usd == 0.20 * 2 * 2 * 730 and mysql.price_live
    assert mysql.type == "aws_db_instance" and mysql.tags == {"team": "billing"}
    assert "x 2 for Multi-AZ" in mysql.explanation
    assert found["old-pg"].status == eol.PAST  # extended support ended 2026-03-31
    assert found["no-ext"].status == eol.PAST and "extended support is turned off" in found["no-ext"].explanation
    assert found["no-ext"].monthly_usd is None
    soon = found["app-mysql"]  # standard support ends 2027-01-31, within 90 days
    assert (soon.status, soon.severity) == (eol.SOON, "low")
    assert soon.monthly_usd == 0.10 * 2 * 730  # what it would cost from then, year 1
    aurora = found["aurora-1 (cluster orders)"]
    assert aurora.type == "aws_rds_cluster_instance" and aurora.status == eol.PAID
    assert aurora.monthly_usd == 0.085 * 2 * 730 and "at its minimum 2 ACU" in aurora.explanation
    assert "current" not in found and "oracle" not in found


def test_eks_statuses():
    found = _by_name(_scan())
    assert found["ancient"].status == eol.PAST
    assert found["paying"].status == eol.PAID and found["paying"].monthly_usd == 0.5 * 730
    assert found["paying"].tags == {"env": "prod"}
    assert found["auto"].status == eol.PAST and "upgrade policy is STANDARD" in found["auto"].explanation
    assert found["soon"].status == eol.SOON and found["soon"].monthly_usd == 0.5 * 730
    assert "fine" not in found


def test_lambda_runtimes_and_overrides(tmp_path):
    found = _by_name(_scan())
    assert found["cron"].status == eol.PAST and found["cron"].version == "python3.9"
    assert found["cron"].dates["block_update"] == "2027-08-31"
    assert "api" not in found and "image" not in found
    data = tmp_path / "eol.json"
    data.write_text(json.dumps({"lambda_runtimes": {"python3.12": {"deprecation": "2027-01-15"}}}))
    found = _by_name(_scan(runtimes=eol.load_overrides(str(data))))
    assert found["api"].status == eol.SOON and found["api"].ends == "2027-01-15"


def test_prices_fall_back_to_us_east_1_when_unreadable():
    def denied(region, **kw):
        raise RuntimeError("AccessDeniedException: not authorized to perform pricing:GetProducts")
    res = _scan({**AWS, ("pricing", "get_products"): denied}, regions=("ap-south-1",))
    mysql = _by_name(res)["legacy-mysql"]
    assert mysql.monthly_usd == 0.20 * 2 * 2 * 730 and not mysql.price_live
    assert "us-east-1 list price" in mysql.explanation


def test_missing_permission_is_noted_and_others_still_count():
    def denied(region, **kw):
        raise RuntimeError("AccessDeniedException: User is not authorized to perform: eks:ListClusters")
    res = _scan({**AWS, ("eks", "list_clusters"): denied})
    assert res.notes == ["EKS in us-east-1 not checked (access denied; needs eks:ListClusters, eks:DescribeCluster, "
                         "eks:DescribeClusterVersions)"]
    assert {f.service for f in res.findings} == {"rds", "lambda"}


def _run(tmp_path, monkeypatch, *extra, data=AWS):
    monkeypatch.setattr(dr, "aws_session", lambda profile, region: FakeSession(data))
    monkeypatch.setattr(eol, "datetime", type("D", (datetime,), {"now": staticmethod(lambda tz=None: NOW)}))
    monkeypatch.chdir(tmp_path)
    return dr.main(["scan", "--eol-only", "-r", "us-east-1", *extra])


def test_eol_only_report_formats(tmp_path, monkeypatch, capsys):
    out = [tmp_path / f"r.{x}" for x in ("json", "md", "csv", "html", "sarif")]
    code = _run(tmp_path, monkeypatch, *[a for p in out for a in ("-o", str(p))], "--fail-on-drift")
    assert code == 2
    doc = json.loads(out[0].read_text())
    sec = doc["end_of_life"]
    assert sec["summary"]["total"] == 10 and sec["summary"]["past_end_of_life"] == 5
    assert sec["findings"][0]["severity"] == "high" and doc["findings"] == []
    assert sec["summary"]["monthly_usd"] == round(0.2 * 4 * 730 + 0.085 * 2 * 730 + 0.5 * 730, 2)
    md = out[1].read_text()
    assert md.startswith("# End of life: 111111111111 (us-east-1)") and "| HIGH | past end of life |" in md
    assert "Not in IaC" not in md and eol.LAMBDA_SOURCE in md
    assert "end of life: in paid extended support" in out[2].read_text()
    assert "<h1>End of life:" in out[3].read_text()
    sarif = json.loads(out[4].read_text())
    results = sarif["runs"][0]["results"]
    assert len(results) == 10 and {r["ruleId"] for r in results} == {"drift/end-of-life"}
    assert "resources past or near end of life" in capsys.readouterr().err


def test_driftignore_and_config_apply(tmp_path, monkeypatch):
    (tmp_path / ".driftignore").write_text("aws_lambda_function.cron\ntag:team=billing\n")
    (tmp_path / ".driftreport.yml").write_text("unmanaged:\n  format: json\n")
    out = tmp_path / "r.json"
    assert _run(tmp_path, monkeypatch, "-o", str(out)) == 0
    doc = json.loads(out.read_text())
    names = {f["address"] for f in doc["end_of_life"]["findings"]}
    assert "cron" not in names and "legacy-mysql" not in names and "old-pg" in names
    assert {i["address"] for i in doc["ignored"]} == {"cron", "legacy-mysql"}


def test_unmanaged_scan_includes_eol_unless_turned_off(tmp_path, monkeypatch):
    cc = {("cloudcontrol", "list_resources"): {"ResourceDescriptions": []},
          ("cloudformation", "list_stacks"): {"StackSummaries": []},
          ("ec2", "describe_regions"): {"Regions": [{"RegionName": "us-east-1"}]}}
    data = {**AWS, **cc}
    monkeypatch.setattr(inv, "CLOUDCONTROL_TO_TERRAFORM", {"AWS::SQS::Queue": "aws_sqs_queue"})
    monkeypatch.setattr(dr, "aws_session", lambda profile, region: FakeSession(data))
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "r.json"
    assert dr.main(["scan", "-r", "us-east-1", "--no-cloudformation", "-f", "json", "-o", str(out)]) == 0
    assert json.loads(out.read_text())["end_of_life"]["summary"]["total"] > 0
    assert dr.main(["scan", "-r", "us-east-1", "--no-cloudformation", "--no-eol", "-f", "json", "-o", str(out)]) == 0
    assert "end_of_life" not in json.loads(out.read_text())

"""End-of-life warnings: AWS resources on versions AWS is retiring or already charging extended support for.

Read-only, from the same credentials as the rest of the scan:
  * RDS and Aurora (MySQL, PostgreSQL): rds:DescribeDBInstances, rds:DescribeDBClusters and
    rds:DescribeDBMajorEngineVersions (each major version's standard and extended support dates).
    The extended support cost is priced per vCPU-hour (ACU-hour for Aurora Serverless v2) from the
    Price List API; vCPUs come from ec2:DescribeInstanceTypes.
  * EKS: eks:ListClusters, eks:DescribeCluster and eks:DescribeClusterVersions (end of standard and
    extended support per Kubernetes version); the extra hourly fee from the Price List API.
  * Lambda: lambda:ListFunctions. Runtime deprecation dates are not in any API, so they come from
    LAMBDA_RUNTIMES below (AWS's published table) or from a JSON file given with --eol-data.

A service that can't be read is named in the report; the others still count.
Standard library plus boto3. Licence: Apache-2.0.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable

PAST = "past end of life"
PAID = "in paid extended support"
SOON = "ends within 90 days"
SEVERITY = {PAST: "high", PAID: "medium", SOON: "low"}
ORDER = {PAST: 0, PAID: 1, SOON: 2}
WARN_DAYS = 90
HOURS_PER_MONTH = 730

# --- Lambda runtime deprecation dates ------------------------------------------
# Not in any AWS API. From the "Supported runtimes" and "Deprecated runtimes" tables; override or extend with
# --eol-data FILE: {"lambda_runtimes": {"python3.9": {"deprecation": "2025-12-15", "block_create": "...",
# "block_update": "..."}}}. Container-image functions have no runtime and are not checked.
LAMBDA_SOURCE = "https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html"
LAMBDA_CHECKED = "2026-11-28"
LAMBDA_RUNTIMES: dict[str, tuple[str, str, str]] = {  # runtime: (deprecation, block create, block update)
    "nodejs22.x": ("2027-05-30", "2027-07-29", "2027-08-31"),
    "nodejs24.x": ("2028-04-30", "2028-06-01", "2028-07-01"),
    "python3.11": ("2027-06-30", "2027-07-29", "2027-08-31"),
    "python3.12": ("2028-10-31", "2028-11-30", "2029-01-10"),
    "java17": ("2027-06-30", "2027-07-29", "2027-08-31"),
    "java11": ("2027-06-30", "2027-07-29", "2027-08-31"),
    "java8.al2": ("2027-06-30", "2027-07-29", "2027-08-31"),
    "ruby3.3": ("2027-03-31", "2027-07-29", "2027-08-31"),
    "ruby3.4": ("2028-03-31", "2028-04-30", "2028-05-31"),
    "dotnet10": ("2028-11-14", "2028-12-14", "2029-01-15"),
    "dotnet8": ("2026-11-10", "2027-07-29", "2027-08-31"),
    "python3.10": ("2026-10-31", "2027-07-29", "2027-08-31"),
    "provided.al2": ("2026-07-31", "2027-07-29", "2027-08-31"),
    "nodejs20.x": ("2026-04-30", "2027-07-29", "2027-08-31"),
    "ruby3.2": ("2026-03-31", "2027-07-29", "2027-08-31"),
    "python3.9": ("2025-12-15", "2027-07-29", "2027-08-31"),
    "nodejs18.x": ("2025-09-01", "2027-07-29", "2027-08-31"),
    "dotnet6": ("2024-12-20", "2027-07-29", "2027-08-31"),
    "python3.8": ("2024-10-14", "2027-07-29", "2027-08-31"),
    "nodejs16.x": ("2024-06-12", "2027-07-29", "2027-08-31"),
    "java8": ("2024-01-08", "2024-02-08", "2027-08-31"),
    "go1.x": ("2024-01-08", "2024-02-08", "2027-08-31"),
    "provided": ("2024-01-08", "2024-02-08", "2027-08-31"),
    "ruby2.7": ("2023-12-07", "2024-01-09", "2027-08-31"),
    "nodejs14.x": ("2023-12-04", "2024-01-09", "2027-08-31"),
    "python3.7": ("2023-12-04", "2024-01-09", "2027-08-31"),
    "dotnetcore3.1": ("2023-04-03", "2023-04-03", "2023-05-03"),
    "nodejs12.x": ("2023-03-31", "2023-03-31", "2023-04-30"),
    "python3.6": ("2022-07-18", "2022-07-18", "2022-08-29"),
    "dotnetcore2.1": ("2022-01-05", "2022-01-05", "2022-04-13"),
    "nodejs10.x": ("2021-07-30", "2021-07-30", "2022-02-14"),
    "ruby2.5": ("2021-07-30", "2021-07-30", "2022-03-31"),
    "python2.7": ("2021-07-15", "2021-07-15", "2022-05-30"),
    "nodejs8.10": ("2020-03-06", "2020-02-04", "2020-03-06"),
    "nodejs6.10": ("2019-08-12", "2019-07-12", "2019-08-12"),
    "nodejs4.3": ("2020-03-05", "2020-02-03", "2020-03-05"),
    "nodejs4.3-edge": ("2020-03-05", "2019-03-31", "2019-04-30"),
    "dotnetcore1.0": ("2019-06-27", "2019-06-30", "2019-07-30"),
    "dotnetcore2.0": ("2019-05-30", "2019-04-30", "2019-05-30"),
    "nodejs": ("2016-08-30", "2016-09-30", "2016-10-31"),
}

# us-east-1 list prices, used only when the Price List API can't be read.
FALLBACK_RATES = {"rds:Yr1-Yr2": 0.10, "rds:Yr3": 0.20, "asv2:Yr1-Yr2": 0.085, "asv2:Yr3": 0.17, "eks": 0.50}
RDS_ENGINES = ("mysql", "postgres", "aurora-mysql", "aurora-postgresql")


@dataclass
class EolFinding:
    service: str          # rds, eks, lambda
    type: str             # Terraform type, for .driftignore rules
    address: str          # name
    physical_id: str      # ARN
    location: str         # region
    version: str          # e.g. "postgres 12.19", "Kubernetes 1.30", "python3.9"
    status: str           # PAST, PAID or SOON
    ends: str             # the date that matters next (YYYY-MM-DD)
    explanation: str
    monthly_usd: float | None = None
    price_live: bool = True
    dates: dict[str, str] = field(default_factory=dict)
    tags: dict[str, str] = field(default_factory=dict)
    source: str = "aws"
    kind: str = "eol"
    action: str = "end of life"
    changes: list = field(default_factory=list)  # none; lets .driftignore treat this like any finding

    @property
    def severity(self) -> str:
        return SEVERITY[self.status]

    def as_dict(self) -> dict[str, Any]:
        d = {"severity": self.severity, "status": self.status, "service": self.service, "type": self.type,
             "address": self.address, "physical_id": self.physical_id, "location": self.location,
             "version": self.version, "ends": self.ends, "dates": self.dates, "explanation": self.explanation}
        if self.monthly_usd is not None:
            d["monthly_usd"] = round(self.monthly_usd, 2)
            d["price_live"] = self.price_live
        return d


@dataclass
class EolResult:
    findings: list[EolFinding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)  # what couldn't be checked
    checked: list[str] = field(default_factory=list)  # services/regions read

    def sorted(self) -> list[EolFinding]:
        return sorted(self.findings, key=lambda f: (ORDER[f.status], -(f.monthly_usd or 0), f.location, f.address))

    def monthly_total(self) -> float:
        return sum(f.monthly_usd or 0 for f in self.findings if f.status in (PAID, PAST))


# --- helpers ---------------------------------------------------------------------

def _dt(v: Any) -> datetime | None:
    if v is None or v == "":
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _day(d: datetime | None) -> str:
    return d.astimezone(timezone.utc).strftime("%Y-%m-%d") if d else ""


def _reason(exc: Exception) -> str:
    text = str(exc)
    for marker in ("AccessDenied", "not authorized", "UnauthorizedOperation"):
        if marker in text:
            return "access denied"
    return text.splitlines()[0][:160] if text else type(exc).__name__


def _pages(client: Any, method: str, key: str, token_in: str, token_out: str, **kwargs) -> Iterable[dict]:
    while True:
        page = getattr(client, method)(**kwargs)
        yield from page.get(key, []) or []
        token = page.get(token_out)
        if not token:
            return
        kwargs[token_in] = token


def _tags(raw: Any) -> dict[str, str]:
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    return {str(t.get("Key")): str(t.get("Value", "")) for t in raw or [] if isinstance(t, dict)}


def load_overrides(path: str | None) -> dict[str, tuple[str, str, str]]:
    """LAMBDA_RUNTIMES with a --eol-data file's lambda_runtimes laid over it."""
    table = dict(LAMBDA_RUNTIMES)
    if not path:
        return table
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    for runtime, row in (data.get("lambda_runtimes") or {}).items():
        if not isinstance(row, dict) or not row.get("deprecation"):
            raise ValueError(f"{path}: lambda_runtimes.{runtime} needs a deprecation date")
        table[runtime] = (row["deprecation"], row.get("block_create", ""), row.get("block_update", ""))
    return table


def _cost_text(monthly: float | None, live: bool, region: str, extra: str = "") -> str:
    if monthly is None:
        return ""
    where = f"in {region}" if live else f"(us-east-1 list price; the {region} price could not be read)"
    return f"about ${monthly:,.2f}/month {where}{extra}"


# --- RDS / Aurora ------------------------------------------------------------------

def _major(version: str, majors: Iterable[str]) -> str | None:
    found = [m for m in majors if version == m or version.startswith(m + ".")]
    return max(found, key=len) if found else None


def _usage_name(engine: str, major: str) -> str:
    if engine == "mysql":
        return f"MySQL{major}"
    if engine == "postgres":
        return f"PostgreSQL{major}"
    if engine == "aurora-mysql":
        return "AuroraMySQL2" if major.startswith("5.7") else "AuroraMySQL3"
    return f"AuroraPostgreSQL{major}"


class _Rds:
    def __init__(self, session: Any, region: str, prices: Any):
        self.rds = session.client("rds", region_name=region)
        self.session, self.region, self.prices = session, region, prices
        self._lifecycles: dict[str, dict[str, dict[str, datetime | None]]] = {}
        self._vcpus: dict[str, int | None] = {}

    def lifecycle(self, engine: str) -> dict[str, dict[str, datetime | None]]:
        if engine not in self._lifecycles:
            out: dict[str, dict[str, datetime | None]] = {}
            for row in _pages(self.rds, "describe_db_major_engine_versions", "DBMajorEngineVersions", "Marker", "Marker",
                              Engine=engine):
                dates: dict[str, datetime | None] = {}
                for cycle in row.get("SupportedEngineLifecycles") or []:
                    name = str(cycle.get("LifecycleSupportName", ""))
                    kind = "extended" if "extended" in name else "standard"
                    dates[f"{kind}_start"] = _dt(cycle.get("LifecycleSupportStartDate"))
                    dates[f"{kind}_end"] = _dt(cycle.get("LifecycleSupportEndDate"))
                out[str(row.get("MajorEngineVersion"))] = dates
            self._lifecycles[engine] = out
        return self._lifecycles[engine]

    def vcpus(self, instance_class: str) -> int | None:
        if instance_class not in self._vcpus:
            try:
                ec2 = self.session.client("ec2", region_name=self.region)
                rows = ec2.describe_instance_types(InstanceTypes=[instance_class.removeprefix("db.")])["InstanceTypes"]
                self._vcpus[instance_class] = int(rows[0]["VCpuInfo"]["DefaultVCpus"])
            except Exception:
                self._vcpus[instance_class] = None
        return self._vcpus[instance_class]

    def rate(self, engine: str, major: str, year: str, serverless: bool) -> tuple[float, bool]:
        name = _usage_name(engine, major)
        wanted = (f"ExtendedSupport:{year}:ASv2:{name}", f"ASv2-ExtendedSupport:{year}:{name}") if serverless \
            else (f"ExtendedSupport:{year}:{name}",)

        def matches(ut: str) -> bool:
            return any(ut == w or ut.endswith("-" + w) for w in wanted)

        pricing_year = "Year 1, Year 2" if year == "Yr1-Yr2" else "Year 3"
        live = None
        if self.prices is not None:
            live = self.prices.find(f"rds-ext:{wanted[0]}", "AmazonRDS", self.region,
                                    {"engineMajorVersion": major, "extendedSupportPricingYear": pricing_year}, matches)
        if live:
            return live, True
        return FALLBACK_RATES[f"{'asv2' if serverless else 'rds'}:{year}"], False


def _rds_region(session: Any, region: str, prices: Any, now: datetime) -> list[EolFinding]:
    ctx = _Rds(session, region, prices)
    clusters = {c.get("DBClusterIdentifier"): c for c in _pages(ctx.rds, "describe_db_clusters", "DBClusters",
                                                                  "Marker", "Marker")}
    out = []
    for inst in _pages(ctx.rds, "describe_db_instances", "DBInstances", "Marker", "Marker"):
        engine = str(inst.get("Engine", ""))
        if engine not in RDS_ENGINES:
            continue
        version = str(inst.get("EngineVersion", ""))
        cycles = ctx.lifecycle(engine)
        major = _major(version, cycles)
        if major is None:
            continue
        d = cycles[major]
        std_end, ext_start, ext_end = d.get("standard_end"), d.get("extended_start"), d.get("extended_end")
        cluster = clusters.get(inst.get("DBClusterIdentifier")) or {}
        disabled = (cluster.get("EngineLifecycleSupport") or inst.get("EngineLifecycleSupport")) \
            == "open-source-rds-extended-support-disabled"
        serverless = inst.get("DBInstanceClass") == "db.serverless"
        name = str(inst.get("DBInstanceIdentifier", ""))
        label = "Aurora" if engine.startswith("aurora") else "RDS"

        def cost(at: datetime) -> tuple[float | None, bool, str]:
            year = "Yr1-Yr2" if ext_start is None or at < ext_start + timedelta(days=730) else "Yr3"
            rate, live = ctx.rate(engine, major, year, serverless)
            if serverless:
                acu = float((cluster.get("ServerlessV2ScalingConfiguration") or {}).get("MinCapacity") or 0)
                if not acu:
                    return None, live, ""
                return rate * acu * HOURS_PER_MONTH, live, f" at least, at its minimum {acu:g} ACU"
            vcpus = ctx.vcpus(str(inst.get("DBInstanceClass", "")))
            if vcpus is None:
                return None, live, ""
            copies = 2 if inst.get("MultiAZ") and not engine.startswith("aurora") else 1
            return rate * vcpus * copies * HOURS_PER_MONTH, live, \
                f" ({vcpus} vCPU{'s' if vcpus != 1 else ''}{' x 2 for Multi-AZ' if copies == 2 else ''})"

        status, ends, monthly, live, why = None, None, None, True, ""
        if ext_end and now > ext_end:
            status, ends = PAST, ext_end
            why = (f"{label} extended support for {engine} {major} ended {_day(ext_end)}; AWS upgrades it to a "
                   "supported major version in a maintenance window. Upgrade it yourself first.")
        elif std_end and now > std_end and disabled:
            status, ends = PAST, std_end
            why = (f"Standard support for {engine} {major} ended {_day(std_end)} and extended support is turned off "
                   "for it, so AWS will upgrade it to a newer major version. Upgrade and test it yourself first.")
        elif std_end and now > std_end:
            status, ends = PAID, ext_end or std_end
            monthly, live, extra = cost(now)
            why = (f"Standard support for {engine} {major} ended {_day(std_end)}; {label} Extended Support bills "
                   + (_cost_text(monthly, live, region, extra) or "per vCPU-hour (vCPU count unknown)")
                   + (f" until {_day(ext_end)}" if ext_end else "") + ". Upgrade the major version to stop the charge.")
        elif std_end and std_end - now <= timedelta(days=WARN_DAYS):
            status, ends = SOON, std_end
            if disabled:
                why = (f"Standard support for {engine} {major} ends {_day(std_end)}; extended support is off, so AWS "
                       "will upgrade it then. Upgrade and test it before that.")
            else:
                monthly, live, extra = cost(std_end)
                text = _cost_text(monthly, live, region, extra)
                why = (f"Standard support for {engine} {major} ends {_day(std_end)}; after that {label} Extended "
                       f"Support bills {text or 'per vCPU-hour'}. Upgrade before then to avoid it.")
        if status is None:
            continue
        out.append(EolFinding(
            service="rds", type="aws_rds_cluster_instance" if engine.startswith("aurora") else "aws_db_instance",
            address=name + (f" (cluster {inst['DBClusterIdentifier']})" if inst.get("DBClusterIdentifier") else ""),
            physical_id=str(inst.get("DBInstanceArn", name)), location=region, version=f"{engine} {version}",
            status=status, ends=_day(ends), explanation=why, monthly_usd=monthly,
            price_live=live, tags=_tags(inst.get("TagList")),
            dates={k: _day(v) for k, v in d.items() if v}))
    return out


# --- EKS ---------------------------------------------------------------------------

def _eks_region(session: Any, region: str, prices: Any, now: datetime) -> list[EolFinding]:
    eks = session.client("eks", region_name=region)
    names = list(_pages(eks, "list_clusters", "clusters", "nextToken", "nextToken"))
    if not names:
        return []
    versions = {str(v.get("clusterVersion")): v for v in _pages(
        eks, "describe_cluster_versions", "clusterVersions", "nextToken", "nextToken", includeAll=True)}
    rate, live = None, True
    if prices is not None:
        rate = prices.find("eks-ext", "AmazonEKS", region, {"operation": "ExtendedSupport"},
                           lambda ut: ut.endswith("AmazonEKS-Hours:extendedSupport"))
    if not rate:
        rate, live = FALLBACK_RATES["eks"], False
    monthly_ext = rate * HOURS_PER_MONTH
    out = []
    for name in names:
        c = eks.describe_cluster(name=name)["cluster"]
        ver = str(c.get("version", ""))
        v = versions.get(ver)
        if not v:
            continue
        std_end, ext_end = _dt(v.get("endOfStandardSupportDate")), _dt(v.get("endOfExtendedSupportDate"))
        standard_policy = (c.get("upgradePolicy") or {}).get("supportType") == "STANDARD"
        state = str(v.get("versionStatus") or v.get("status") or "").upper()
        status, ends, monthly, why = None, None, None, ""
        if (ext_end and now > ext_end) or state == "UNSUPPORTED":
            status, ends = PAST, ext_end or std_end
            why = (f"Kubernetes {ver} is past the end of EKS extended support ({_day(ext_end)}); AWS upgrades the "
                   "control plane automatically. Upgrade it and its node groups and add-ons yourself first.")
        elif std_end and now > std_end and standard_policy:
            status, ends = PAST, std_end
            why = (f"Standard support for Kubernetes {ver} ended {_day(std_end)} and the cluster's upgrade policy is "
                   "STANDARD, so AWS will upgrade the control plane automatically. Upgrade and test it yourself first.")
        elif std_end and now > std_end:
            status, ends, monthly = PAID, ext_end, monthly_ext
            why = (f"Standard support for Kubernetes {ver} ended {_day(std_end)}; extended support adds "
                   f"{_cost_text(monthly, live, region)} per cluster until {_day(ext_end)}. Upgrade to stop the charge.")
        elif std_end and std_end - now <= timedelta(days=WARN_DAYS):
            status, ends = SOON, std_end
            if standard_policy:
                why = (f"Standard support for Kubernetes {ver} ends {_day(std_end)}; the upgrade policy is STANDARD, "
                       "so AWS will upgrade the control plane then. Upgrade and test it before that.")
            else:
                monthly = monthly_ext
                why = (f"Standard support for Kubernetes {ver} ends {_day(std_end)}; after that extended support adds "
                       f"{_cost_text(monthly, live, region)}. Upgrade before then to avoid it.")
        if status is None:
            continue
        out.append(EolFinding(
            service="eks", type="aws_eks_cluster", address=name, physical_id=str(c.get("arn", name)), location=region,
            version=f"Kubernetes {ver}", status=status, ends=_day(ends), explanation=why, monthly_usd=monthly,
            price_live=live, tags=_tags(c.get("tags")),
            dates={"standard_end": _day(std_end), "extended_end": _day(ext_end)}))
    return out


# --- Lambda ------------------------------------------------------------------------

def _lambda_region(session: Any, region: str, table: dict[str, tuple[str, str, str]], now: datetime) -> list[EolFinding]:
    lam = session.client("lambda", region_name=region)
    out = []
    for fn in _pages(lam, "list_functions", "Functions", "Marker", "NextMarker"):
        runtime = fn.get("Runtime")
        row = table.get(runtime) if runtime else None
        if not row:
            continue
        dep, block_create, block_update = (_dt(x) for x in row)
        if dep is None:
            continue
        if now >= dep:
            status = PAST
            if block_update and now >= block_update:
                tail = f"updates to it have been blocked since {_day(block_update)}"
            else:
                tail = (f"AWS blocks creating functions on it from {_day(block_create)} and updating them from "
                        f"{_day(block_update)}") if block_update else "it no longer gets security patches"
            why = (f"The {runtime} runtime was deprecated {_day(dep)} and no longer gets security patches; {tail}. "
                   "Move the function to a supported runtime.")
        elif dep - now <= timedelta(days=WARN_DAYS):
            status = SOON
            why = (f"The {runtime} runtime is deprecated {_day(dep)}"
                   + (f"; updates are blocked from {_day(block_update)}" if block_update else "")
                   + ". Move the function to a supported runtime.")
        else:
            continue
        name = str(fn.get("FunctionName", ""))
        out.append(EolFinding(
            service="lambda", type="aws_lambda_function", address=name, physical_id=str(fn.get("FunctionArn", name)),
            location=region, version=runtime, status=status, ends=_day(dep), explanation=why,
            dates={"deprecation": _day(dep), "block_create": _day(block_create), "block_update": _day(block_update)}))
    return out


# --- the scan ----------------------------------------------------------------------

CHECKS = (
    ("RDS/Aurora", "rds:DescribeDBInstances, rds:DescribeDBClusters, rds:DescribeDBMajorEngineVersions",
     lambda s, r, p, t, n: _rds_region(s, r, p, n)),
    ("EKS", "eks:ListClusters, eks:DescribeCluster, eks:DescribeClusterVersions",
     lambda s, r, p, t, n: _eks_region(s, r, p, n)),
    ("Lambda", "lambda:ListFunctions", lambda s, r, p, t, n: _lambda_region(s, r, t, n)),
)


def scan(session: Any, regions: list[str], prices: Any = None, runtimes: dict | None = None,
         now: datetime | None = None, log: Callable[..., None] = print) -> EolResult:
    now = now or datetime.now(timezone.utc)
    table = runtimes if runtimes is not None else LAMBDA_RUNTIMES
    result = EolResult()
    for region in regions:
        for label, needs, check in CHECKS:
            try:
                result.findings += check(session, region, prices, table, now)
                result.checked.append(f"{label} {region}")
            except Exception as exc:
                reason = _reason(exc)
                result.notes.append(f"{label} in {region} not checked ({reason}; needs {needs})")
                log(f"warning: end-of-life check for {label} in {region} skipped: {reason}", file=sys.stderr)
    return result


# --- report sections ----------------------------------------------------------------

TITLE = "End of life"


def counts(findings: list[EolFinding]) -> dict[str, int]:
    return {s: sum(1 for f in findings if f.status == s) for s in (PAST, PAID, SOON)}


def summary_line(res: EolResult) -> str:
    c = counts(res.findings)
    if not res.findings:
        return "End of life: nothing past or near end of life" + (" in what could be checked." if res.notes else ".")
    total = res.monthly_total()
    return (f"End of life: {len(res.findings)} resource{'s' if len(res.findings) != 1 else ''} · {PAST}: {c[PAST]} · "
            f"{PAID}: {c[PAID]} · {SOON}: {c[SOON]}"
            + (f" · extended support about ${total:,.2f}/month" if total else "") + ".")


def _cell(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def _cost(f: EolFinding) -> str:
    if f.monthly_usd is None:
        return ""
    return f"${f.monthly_usd:,.2f}/mo" + ("" if f.price_live else " (us-east-1 price)") + \
        (" from " + f.ends if f.status == SOON else "")


def markdown(res: EolResult) -> list[str]:
    out = ["", f"## {TITLE}", "", summary_line(res)]
    if res.notes:
        out += ["", "Not checked: " + "; ".join(res.notes) + "."]
    if res.findings:
        out += ["", "| Severity | Status | Resource | Region | Version | Ends | Extended support | What to do |",
                "|---|---|---|---|---|---|---|---|"]
        for f in res.sorted():
            out.append("| " + " | ".join(_cell(x) for x in (
                f.severity.upper(), f.status, f"{f.address}<br>{f.type}", f.location, f.version, f.ends, _cost(f),
                f.explanation)) + " |")
    if any(f.service == "lambda" for f in res.findings):
        out += ["", f"Lambda runtime dates from {LAMBDA_SOURCE} (checked {LAMBDA_CHECKED}; override with --eol-data)."]
    return out


def html_section(res: EolResult) -> str:
    import html as h
    e = h.escape
    rows = "".join(
        f"<tr data-sev={f.severity}><td><span class='sev {f.severity}'>{f.severity.upper()}</span></td>"
        f"<td>{e(f.status)}</td><td><code>{e(f.address)}</code><div class=type>{e(f.location)}</div>"
        f"<div class=type>{e(f.type)}</div></td><td>{e(f.version)}<div class=type>ends {e(f.ends)}</div></td>"
        f"<td>{e(_cost(f))}</td><td>{e(f.explanation)}</td></tr>" for f in res.sorted())
    body = f"<h2>{TITLE}</h2><p class=meta>{e(summary_line(res))}</p>"
    if res.notes:
        body += f"<p class=meta>Not checked: {e('; '.join(res.notes))}.</p>"
    if rows:
        body += ("<div class=wrap><table><thead><tr><th>Severity</th><th>Status</th><th>Resource</th><th>Version</th>"
                 "<th>Extended support</th><th>What to do</th></tr></thead><tbody>" + rows + "</tbody></table></div>")
    if any(f.service == "lambda" for f in res.findings):
        body += f"<p class=meta>Lambda runtime dates from {e(LAMBDA_SOURCE)} (checked {LAMBDA_CHECKED}).</p>"
    return body


def json_section(res: EolResult) -> dict[str, Any]:
    c = counts(res.findings)
    return {"summary": {"total": len(res.findings), "past_end_of_life": c[PAST], "in_paid_extended_support": c[PAID],
                        "ends_within_90_days": c[SOON], "monthly_usd": round(res.monthly_total(), 2)},
            "findings": [f.as_dict() for f in res.sorted()], "not_checked": res.notes or None,
            "checked": res.checked, "lambda_runtime_dates": {"source": LAMBDA_SOURCE, "checked": LAMBDA_CHECKED}}


def csv_rows(res: EolResult) -> list[list[Any]]:
    """Rows in drift_report's CSV columns: the version is the attribute, the date it ends is `after`."""
    return [[f.severity, "aws", f.location, f.address, f.type, f"end of life: {f.status}", f.physical_id, "version",
             f.version, f.ends, f.explanation + (f" ({_cost(f)})" if _cost(f) else ""), "", ""] for f in res.sorted()]

"""Read-only AWS inventory: find resources that exist in AWS but no Terraform state or
CloudFormation stack you point at lists ("unmanaged", or "not in IaC").

How it works:
  1. List resources per region, mostly through the Cloud Control API (ListResources), and
     through the service's own list call where Cloud Control lacks the fields needed to tell
     an AWS default (default VPC, service-linked role, AWS-managed key) from a customer's.
  2. Drop what AWS creates in every account or for another service.
  3. Collect identifiers from Terraform state files and CloudFormation stack resources.
  4. Report every listed resource no state or stack accounts for.

Only List/Describe/Get calls are made. Nothing is written to AWS or to state.
Licence: Apache-2.0.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

# --- what is listed --------------------------------------------------------

# Cloud Control type -> Terraform type. Each Terraform type's state id (or name/arn) is
# what Cloud Control returns as the primary identifier, so the two can be matched.
CLOUDCONTROL_TO_TERRAFORM: dict[str, str] = {
    # core services
    "AWS::EC2::VPC": "aws_vpc",
    "AWS::EC2::Subnet": "aws_subnet",
    "AWS::EC2::SecurityGroup": "aws_security_group",
    "AWS::EC2::Instance": "aws_instance",
    "AWS::EC2::InternetGateway": "aws_internet_gateway",
    "AWS::EC2::DHCPOptions": "aws_vpc_dhcp_options",
    "AWS::EC2::RouteTable": "aws_route_table",
    "AWS::EC2::NetworkAcl": "aws_network_acl",
    "AWS::EC2::Volume": "aws_ebs_volume",
    "AWS::EC2::Snapshot": "aws_ebs_snapshot",  # listed natively, and only when it looks abandoned
    "AWS::EC2::VPCEndpoint": "aws_vpc_endpoint",
    "AWS::S3::Bucket": "aws_s3_bucket",
    "AWS::Lambda::Function": "aws_lambda_function",
    "AWS::RDS::DBInstance": "aws_db_instance",
    "AWS::RDS::DBCluster": "aws_rds_cluster",
    "AWS::IAM::Role": "aws_iam_role",
    "AWS::SQS::Queue": "aws_sqs_queue",
    "AWS::SNS::Topic": "aws_sns_topic",
    "AWS::DynamoDB::Table": "aws_dynamodb_table",
    "AWS::ECS::Cluster": "aws_ecs_cluster",
    "AWS::ECS::Service": "aws_ecs_service",
    "AWS::EKS::Cluster": "aws_eks_cluster",
    "AWS::EKS::Nodegroup": "aws_eks_node_group",
    "AWS::ElasticLoadBalancingV2::LoadBalancer": "aws_lb",
    "AWS::ElasticLoadBalancing::LoadBalancer": "aws_elb",
    "AWS::KMS::Key": "aws_kms_key",
    "AWS::Logs::LogGroup": "aws_cloudwatch_log_group",
    "AWS::SecretsManager::Secret": "aws_secretsmanager_secret",
    "AWS::ECR::Repository": "aws_ecr_repository",
    "AWS::Route53::HostedZone": "aws_route53_zone",
    "AWS::CloudFront::Distribution": "aws_cloudfront_distribution",
    "AWS::StepFunctions::StateMachine": "aws_sfn_state_machine",
    "AWS::Events::EventBus": "aws_cloudwatch_event_bus",
    "AWS::Events::Rule": "aws_cloudwatch_event_rule",
    "AWS::ApiGateway::RestApi": "aws_api_gateway_rest_api",
    "AWS::ApiGatewayV2::Api": "aws_apigatewayv2_api",
    "AWS::Kinesis::Stream": "aws_kinesis_stream",
    "AWS::KinesisFirehose::DeliveryStream": "aws_kinesis_firehose_delivery_stream",
    "AWS::Cognito::UserPool": "aws_cognito_user_pool",
    "AWS::EFS::FileSystem": "aws_efs_file_system",
    "AWS::SSM::Parameter": "aws_ssm_parameter",
    "AWS::CodeBuild::Project": "aws_codebuild_project",
    "AWS::CodePipeline::Pipeline": "aws_codepipeline",
    "AWS::Glue::Crawler": "aws_glue_crawler",
    "AWS::OpenSearchService::Domain": "aws_opensearch_domain",
    "AWS::MSK::Cluster": "aws_msk_cluster",
    "AWS::Redshift::Cluster": "aws_redshift_cluster",
    "AWS::ElastiCache::ReplicationGroup": "aws_elasticache_replication_group",
    "AWS::ElastiCache::CacheCluster": "aws_elasticache_cluster",
    "AWS::WAFv2::WebACL": "aws_wafv2_web_acl",
    "AWS::CloudTrail::Trail": "aws_cloudtrail",
    # long tail (copied from OrchesTerra's Cloud Control discovery list)
    "AWS::CertificateManager::Certificate": "aws_acm_certificate",
    "AWS::ACMPCA::CertificateAuthority": "aws_acmpca_certificate_authority",
    "AWS::AmazonMQ::Broker": "aws_mq_broker",
    "AWS::ApiGateway::ApiKey": "aws_api_gateway_api_key",
    "AWS::ApiGateway::DomainName": "aws_api_gateway_domain_name",
    "AWS::ApiGateway::UsagePlan": "aws_api_gateway_usage_plan",
    "AWS::ApiGateway::VpcLink": "aws_api_gateway_vpc_link",
    "AWS::AppConfig::Application": "aws_appconfig_application",
    "AWS::AppConfig::ConfigurationProfile": "aws_appconfig_configuration_profile",
    "AWS::AppConfig::Environment": "aws_appconfig_environment",
    "AWS::AppSync::GraphQLApi": "aws_appsync_graphql_api",
    "AWS::ApplicationAutoScaling::ScalableTarget": "aws_appautoscaling_target",
    "AWS::Athena::DataCatalog": "aws_athena_data_catalog",
    "AWS::Athena::NamedQuery": "aws_athena_named_query",
    "AWS::Athena::WorkGroup": "aws_athena_workgroup",
    "AWS::AutoScaling::AutoScalingGroup": "aws_autoscaling_group",
    "AWS::AutoScaling::LaunchConfiguration": "aws_launch_configuration",
    "AWS::Backup::BackupPlan": "aws_backup_plan",
    "AWS::Backup::BackupVault": "aws_backup_vault",
    "AWS::Batch::ComputeEnvironment": "aws_batch_compute_environment",
    "AWS::Batch::JobQueue": "aws_batch_job_queue",
    "AWS::Budgets::Budget": "aws_budgets_budget",
    "AWS::Cloud9::EnvironmentEC2": "aws_cloud9_environment_ec2",
    "AWS::CloudFront::CachePolicy": "aws_cloudfront_cache_policy",
    "AWS::CloudFront::Function": "aws_cloudfront_function",
    "AWS::CloudFront::OriginAccessControl": "aws_cloudfront_origin_access_control",
    "AWS::CloudFront::OriginRequestPolicy": "aws_cloudfront_origin_request_policy",
    "AWS::CloudFront::ResponseHeadersPolicy": "aws_cloudfront_response_headers_policy",
    "AWS::CloudWatch::Alarm": "aws_cloudwatch_metric_alarm",
    "AWS::CloudWatch::CompositeAlarm": "aws_cloudwatch_composite_alarm",
    "AWS::CloudWatch::Dashboard": "aws_cloudwatch_dashboard",
    "AWS::CodeArtifact::Domain": "aws_codeartifact_domain",
    "AWS::CodeArtifact::Repository": "aws_codeartifact_repository",
    "AWS::CodeCommit::Repository": "aws_codecommit_repository",
    "AWS::CodeStarConnections::Connection": "aws_codestarconnections_connection",
    "AWS::Cognito::IdentityPool": "aws_cognito_identity_pool",
    "AWS::Config::ConfigurationAggregator": "aws_config_configuration_aggregator",
    "AWS::DataSync::Task": "aws_datasync_task",
    "AWS::DMS::ReplicationInstance": "aws_dms_replication_instance",
    "AWS::EC2::CustomerGateway": "aws_customer_gateway",
    "AWS::EC2::EIP": "aws_eip",
    "AWS::EC2::FlowLog": "aws_flow_log",
    "AWS::EC2::LaunchTemplate": "aws_launch_template",
    "AWS::EC2::NatGateway": "aws_nat_gateway",
    "AWS::EC2::PlacementGroup": "aws_placement_group",
    "AWS::EC2::PrefixList": "aws_ec2_managed_prefix_list",
    "AWS::EC2::TransitGateway": "aws_ec2_transit_gateway",
    "AWS::EC2::TransitGatewayAttachment": "aws_ec2_transit_gateway_vpc_attachment",
    "AWS::EC2::VPCPeeringConnection": "aws_vpc_peering_connection",
    "AWS::EC2::VPNGateway": "aws_vpn_gateway",
    "AWS::ECR::PullThroughCacheRule": "aws_ecr_pull_through_cache_rule",
    "AWS::ECS::TaskDefinition": "aws_ecs_task_definition",
    "AWS::EFS::AccessPoint": "aws_efs_access_point",
    "AWS::EKS::Addon": "aws_eks_addon",
    "AWS::EKS::FargateProfile": "aws_eks_fargate_profile",
    "AWS::ElasticLoadBalancingV2::Listener": "aws_lb_listener",
    "AWS::ElasticLoadBalancingV2::TargetGroup": "aws_lb_target_group",
    "AWS::EMR::Studio": "aws_emr_studio",
    "AWS::Events::ApiDestination": "aws_cloudwatch_event_api_destination",
    "AWS::Events::Archive": "aws_cloudwatch_event_archive",
    "AWS::Events::Connection": "aws_cloudwatch_event_connection",
    "AWS::Glue::Job": "aws_glue_job",
    "AWS::Glue::Registry": "aws_glue_registry",
    "AWS::Glue::Trigger": "aws_glue_trigger",
    "AWS::GuardDuty::Detector": "aws_guardduty_detector",
    "AWS::IAM::Group": "aws_iam_group",
    "AWS::IAM::InstanceProfile": "aws_iam_instance_profile",
    "AWS::IAM::ManagedPolicy": "aws_iam_policy",
    "AWS::IAM::OIDCProvider": "aws_iam_openid_connect_provider",
    "AWS::IAM::SAMLProvider": "aws_iam_saml_provider",
    "AWS::IAM::User": "aws_iam_user",
    "AWS::ImageBuilder::Component": "aws_imagebuilder_component",
    "AWS::ImageBuilder::ImagePipeline": "aws_imagebuilder_image_pipeline",
    "AWS::IoT::Thing": "aws_iot_thing",
    "AWS::IoT::TopicRule": "aws_iot_topic_rule",
    "AWS::KinesisAnalyticsV2::Application": "aws_kinesisanalyticsv2_application",
    "AWS::KMS::Alias": "aws_kms_alias",
    "AWS::Lambda::EventSourceMapping": "aws_lambda_event_source_mapping",
    "AWS::Lambda::LayerVersion": "aws_lambda_layer_version",
    "AWS::Logs::Destination": "aws_cloudwatch_log_destination",
    "AWS::Logs::QueryDefinition": "aws_cloudwatch_query_definition",
    "AWS::Logs::ResourcePolicy": "aws_cloudwatch_log_resource_policy",
    "AWS::Logs::SubscriptionFilter": "aws_cloudwatch_log_subscription_filter",
    "AWS::MemoryDB::Cluster": "aws_memorydb_cluster",
    "AWS::MWAA::Environment": "aws_mwaa_environment",
    "AWS::NetworkFirewall::Firewall": "aws_networkfirewall_firewall",
    "AWS::NetworkFirewall::FirewallPolicy": "aws_networkfirewall_firewall_policy",
    "AWS::NetworkFirewall::RuleGroup": "aws_networkfirewall_rule_group",
    "AWS::Pipes::Pipe": "aws_pipes_pipe",
    "AWS::RDS::DBClusterParameterGroup": "aws_rds_cluster_parameter_group",
    "AWS::RDS::DBParameterGroup": "aws_db_parameter_group",
    "AWS::RDS::DBSubnetGroup": "aws_db_subnet_group",
    "AWS::RDS::OptionGroup": "aws_db_option_group",
    "AWS::Route53::HealthCheck": "aws_route53_health_check",
    "AWS::Route53Resolver::ResolverEndpoint": "aws_route53_resolver_endpoint",
    "AWS::Route53Resolver::ResolverRule": "aws_route53_resolver_rule",
    "AWS::S3::AccessPoint": "aws_s3_access_point",
    "AWS::SageMaker::Domain": "aws_sagemaker_domain",
    "AWS::SageMaker::NotebookInstance": "aws_sagemaker_notebook_instance",
    "AWS::Scheduler::Schedule": "aws_scheduler_schedule",
    "AWS::Scheduler::ScheduleGroup": "aws_scheduler_schedule_group",
    "AWS::SecretsManager::RotationSchedule": "aws_secretsmanager_secret_rotation",
    "AWS::SES::ConfigurationSet": "aws_sesv2_configuration_set",
    "AWS::SES::EmailIdentity": "aws_sesv2_email_identity",
    "AWS::SES::Template": "aws_ses_template",
    "AWS::SNS::Subscription": "aws_sns_topic_subscription",
    "AWS::SSM::Document": "aws_ssm_document",
    "AWS::SSM::MaintenanceWindow": "aws_ssm_maintenance_window",
    "AWS::SSM::PatchBaseline": "aws_ssm_patch_baseline",
    "AWS::StepFunctions::Activity": "aws_sfn_activity",
    "AWS::Synthetics::Canary": "aws_synthetics_canary",
    "AWS::Transfer::Server": "aws_transfer_server",
    "AWS::WAFv2::IPSet": "aws_wafv2_ip_set",
    "AWS::WAFv2::RegexPatternSet": "aws_wafv2_regex_pattern_set",
    "AWS::WAFv2::RuleGroup": "aws_wafv2_rule_group",
    "AWS::XRay::Group": "aws_xray_group",
    "AWS::XRay::SamplingRule": "aws_xray_sampling_rule",
}

# Terraform type aliases that name the same AWS resource.
TERRAFORM_TYPE_ALIASES = {
    "aws_alb": "aws_lb",
    "aws_alb_listener": "aws_lb_listener",
    "aws_alb_target_group": "aws_lb_target_group",
    "aws_docdb_cluster": "aws_rds_cluster",
    "aws_neptune_cluster": "aws_rds_cluster",
    "aws_elasticsearch_domain": "aws_opensearch_domain",
}

# Account-wide services: listed once, in the first region scanned.
_GLOBAL_PREFIXES = ("AWS::IAM::", "AWS::CloudFront::", "AWS::Route53::", "AWS::Budgets::", "AWS::S3::Bucket")

MAX_PER_TYPE = 1000

_SKIP_ERRORS = (
    "UnsupportedActionException", "TypeNotFoundException", "InvalidRequestException",
    "GeneralServiceException", "AccessDenied", "UnauthorizedOperation", "not authorized",
    "is not supported", "Could not connect to the endpoint", "OptInRequired",
    "SubscriptionRequiredException", "UnrecognizedClientException",
)

SECURITY_TYPES = ("aws_security_group", "aws_iam_", "aws_kms_", "aws_network_acl", "aws_wafv2_",
                  "aws_networkfirewall_", "aws_secretsmanager_", "aws_acm", "aws_cognito_")


def terraform_type(cc_type: str) -> str:
    return CLOUDCONTROL_TO_TERRAFORM.get(cc_type, "")


def is_global(cc_type: str) -> bool:
    return cc_type.startswith(_GLOBAL_PREFIXES)


# --- live resources --------------------------------------------------------

@dataclass
class LiveResource:
    cc_type: str
    tf_type: str
    identifier: str
    region: str
    name: str = ""
    arn: str = ""
    props: dict[str, Any] = field(default_factory=dict)

    def keys(self) -> list[frozenset[str]]:
        """Alternative ways IaC may record this resource. A key matches when all its parts appear."""
        out = []
        ident = self.identifier
        if "|" in ident:
            out.append(frozenset(p for p in ident.split("|") if p))
        elif ident:
            out.append(frozenset([ident]))
        parts = set(ident.split("|"))
        for extra in (self.arn, self.name):
            # A name that is only one part of a composite id (a parent's id) would match a sibling.
            if extra and extra != ident and extra not in parts:
                out.append(frozenset([extra]))
        for alt in self.props.get("_aliases") or []:
            out.append(frozenset(alt) if isinstance(alt, (list, tuple, set, frozenset)) else frozenset([alt]))
        return [k for k in out if k]


def _props(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _tag_map(raw: Any) -> dict[str, str]:
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    out = {}
    for item in raw or []:
        if isinstance(item, dict) and item.get("Key") is not None:
            out[str(item["Key"])] = str(item.get("Value") or "")
    return out


def _name(identifier: str, props: dict[str, Any]) -> str:
    for key in ("Name", "DomainName", "FunctionName", "GroupName", "RoleName", "UserName", "PolicyName",
                "AliasName", "BucketName", "TableName", "QueueName", "TopicName", "ClusterName",
                "LogGroupName", "RepositoryName", "StateMachineName", "PrefixListName", "RuleName",
                "DBInstanceIdentifier", "LoadBalancerName", "TargetGroupName"):
        value = props.get(key)
        if isinstance(value, str) and value:
            return value
    tags = _tag_map(props.get("Tags"))
    if tags.get("Name"):
        return tags["Name"]
    if identifier.startswith("arn:"):
        return re.split(r"[:/]", identifier)[-1]
    if identifier.startswith("https://"):
        return identifier.rstrip("/").rsplit("/", 1)[-1]
    return identifier.rsplit("|", 1)[-1]


def _arn_region(arn: str) -> str:
    parts = arn.split(":")
    return parts[3] if len(parts) > 5 and arn.startswith("arn:") else ""


def _arn_account(arn: str) -> str:
    parts = arn.split(":")
    account = parts[4] if len(parts) > 5 and arn.startswith("arn:") else ""
    return account if re.fullmatch(r"\d{12}", account) else ""


def _paginate(client: Any, method: str, key: str, **kwargs: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if client.can_paginate(method):
        for page in client.get_paginator(method).paginate(**kwargs):
            out.extend(page.get(key) or [])
        return out
    token = None
    while True:
        page = getattr(client, method)(**({**kwargs, "NextToken": token} if token else kwargs)) or {}
        out.extend(page.get(key) or [])
        token = page.get("NextToken")
        if not token:
            return out


def list_cloudcontrol(client: Any, cc_type: str, model: dict | None = None) -> list[dict[str, Any]]:
    """ResourceDescriptions for one type. Unsupported types and denied calls raise Skipped."""
    out: list[dict[str, Any]] = []
    token = None
    while len(out) < MAX_PER_TYPE:
        kwargs: dict[str, Any] = {"TypeName": cc_type, "MaxResults": 100}
        if model:
            kwargs["ResourceModel"] = json.dumps(model)
        if token:
            kwargs["NextToken"] = token
        try:
            page = client.list_resources(**kwargs)
        except Exception as exc:
            text = f"{type(exc).__name__} {exc}"
            if any(marker in text for marker in _SKIP_ERRORS):
                raise Skipped(text) from exc
            raise
        out.extend(page.get("ResourceDescriptions") or [])
        token = page.get("NextToken")
        if not token:
            break
    return out


class Skipped(Exception):
    """A type that could not be listed (not supported in the region, or access denied)."""


# Native listers: (session, region) -> [{"Identifier": ..., "Properties": {...}}].
# Used where Cloud Control's model lacks what tells an AWS default from a customer's resource,
# or where ListResources needs a parent identifier.

def _vpcs(s, r):
    ec2 = s.client("ec2", region_name=r)
    return [{"Identifier": v["VpcId"], "Properties": {"IsDefault": v.get("IsDefault"), "Tags": v.get("Tags") or []}}
            for v in _paginate(ec2, "describe_vpcs", "Vpcs")]


def _default_vpc_ids(ec2) -> set[str]:
    return {v["VpcId"] for v in _paginate(ec2, "describe_vpcs", "Vpcs", Filters=[{"Name": "is-default", "Values": ["true"]}])}


def _subnets(s, r):
    ec2 = s.client("ec2", region_name=r)
    return [{"Identifier": n["SubnetId"], "Properties": {"DefaultForAz": n.get("DefaultForAz"), "VpcId": n.get("VpcId"),
                                                      "Tags": n.get("Tags") or []}}
            for n in _paginate(ec2, "describe_subnets", "Subnets")]


def _security_groups(s, r):
    ec2 = s.client("ec2", region_name=r)
    return [{"Identifier": g["GroupId"], "Properties": {"GroupName": g.get("GroupName"), "Description": g.get("Description"),
                                                     "VpcId": g.get("VpcId"), "Tags": g.get("Tags") or []}}
            for g in _paginate(ec2, "describe_security_groups", "SecurityGroups")]


def _internet_gateways(s, r):
    ec2 = s.client("ec2", region_name=r)
    defaults = _default_vpc_ids(ec2)
    out = []
    for g in _paginate(ec2, "describe_internet_gateways", "InternetGateways"):
        vpcs = {a.get("VpcId") for a in g.get("Attachments") or []}
        out.append({"Identifier": g["InternetGatewayId"],
                    "Properties": {"IsDefault": bool(vpcs & defaults), "Tags": g.get("Tags") or []}})
    return out


def _dhcp_options(s, r):
    ec2 = s.client("ec2", region_name=r)
    vpcs = _paginate(ec2, "describe_vpcs", "Vpcs")
    in_default = {v.get("DhcpOptionsId") for v in vpcs if v.get("IsDefault")}
    in_custom = {v.get("DhcpOptionsId") for v in vpcs if not v.get("IsDefault")}
    out = []
    for d in _paginate(ec2, "describe_dhcp_options", "DhcpOptions"):
        did = d["DhcpOptionsId"]
        # The default set is created with the default VPC; custom VPCs share it unless told otherwise.
        out.append({"Identifier": did, "Properties": {"IsDefault": did in in_default and not d.get("Tags"),
                                                      "SharedWithCustomVpc": did in in_custom, "Tags": d.get("Tags") or []}})
    return out


def _route_tables(s, r):
    ec2 = s.client("ec2", region_name=r)
    return [{"Identifier": t["RouteTableId"],
             "Properties": {"Main": any(a.get("Main") for a in t.get("Associations") or []), "VpcId": t.get("VpcId"),
                            "Tags": t.get("Tags") or []}}
            for t in _paginate(ec2, "describe_route_tables", "RouteTables")]


def _nat_gateways(s, r):
    ec2 = s.client("ec2", region_name=r)
    routed = {route.get("NatGatewayId") for t in _paginate(ec2, "describe_route_tables", "RouteTables")
              for route in t.get("Routes") or []}
    gateways = _paginate(ec2, "describe_nat_gateways", "NatGateways",
                         Filter=[{"Name": "state", "Values": ["pending", "available"]}])
    traffic = _nat_traffic(s, r, [g for g in gateways if g["NatGatewayId"] in routed])
    out = []
    for g in gateways:
        props = {"VpcId": g.get("VpcId"), "SubnetId": g.get("SubnetId"),
                 "ConnectivityType": g.get("ConnectivityType"), "Routed": g["NatGatewayId"] in routed,
                 "PublicIps": sum(1 for a in g.get("NatGatewayAddresses") or [] if a.get("PublicIp")),
                 "Tags": g.get("Tags") or []}
        if g["NatGatewayId"] in traffic:
            props["BytesLast14Days"] = traffic[g["NatGatewayId"]]
        out.append({"Identifier": g["NatGatewayId"], "Properties": props})
    return out


QUIET_DAYS = 14
QUIET_BYTES = 1_000_000_000  # under 1 GB to and from the destination in 14 days: next to nothing goes through it
_NAT_BYTES = ("BytesOutToDestination", "BytesInFromDestination")


def _nat_traffic(s, r, gateways) -> dict[str, float]:
    """Bytes each gateway moved over the last QUIET_DAYS days, for gateways at least that old.
    Empty when CloudWatch can't be read (cloudwatch:GetMetricData is in ReadOnlyAccess)."""
    from datetime import datetime, timedelta, timezone
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=QUIET_DAYS)
    old = [g["NatGatewayId"] for g in gateways if g.get("CreateTime") and g["CreateTime"] <= start]
    if not old:
        return {}
    queries = [{"Id": f"q{i}_{j}", "ReturnData": True, "MetricStat": {
        "Metric": {"Namespace": "AWS/NATGateway", "MetricName": metric,
                   "Dimensions": [{"Name": "NatGatewayId", "Value": nat}]},
        "Period": 86400, "Stat": "Sum"}} for i, nat in enumerate(old) for j, metric in enumerate(_NAT_BYTES)]
    totals = dict.fromkeys(old, 0.0)
    try:
        cw = s.client("cloudwatch", region_name=r)
        for k in range(0, len(queries), 500):  # GetMetricData takes at most 500 queries
            kwargs: dict[str, Any] = {"MetricDataQueries": queries[k:k + 500], "StartTime": start, "EndTime": end}
            while True:
                page = cw.get_metric_data(**kwargs)
                for row in page.get("MetricDataResults") or []:
                    totals[old[int(row["Id"][1:].split("_")[0])]] += sum(row.get("Values") or [])
                if not page.get("NextToken"):
                    break
                kwargs["NextToken"] = page["NextToken"]
    except Exception:  # no permission or no CloudWatch: say nothing rather than guess
        return {}
    return totals


def _elastic_ips(s, r):
    ec2 = s.client("ec2", region_name=r)
    page = ec2.describe_addresses(Filters=[{"Name": "domain", "Values": ["vpc"]}]) or {}
    return [{"Identifier": a["AllocationId"],
             "Properties": {"PublicIp": a.get("PublicIp"), "ServiceManaged": a.get("ServiceManaged"),
                            "Attached": bool(a.get("AssociationId") or a.get("NetworkInterfaceId") or a.get("InstanceId")),
                            "Tags": a.get("Tags") or []}}
            for a in page.get("Addresses") or [] if a.get("AllocationId")]


def _network_acls(s, r):
    ec2 = s.client("ec2", region_name=r)
    return [{"Identifier": a["NetworkAclId"], "Properties": {"IsDefault": a.get("IsDefault"), "Tags": a.get("Tags") or []}}
            for a in _paginate(ec2, "describe_network_acls", "NetworkAcls")]


def _instances(s, r):
    ec2 = s.client("ec2", region_name=r)
    out = []
    for res in _paginate(ec2, "describe_instances", "Reservations",
                         Filters=[{"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}]):
        for i in res.get("Instances") or []:
            out.append({"Identifier": i["InstanceId"], "Properties": {"Tags": i.get("Tags") or []}})
    return out


def _volumes(s, r):
    ec2 = s.client("ec2", region_name=r)
    out = []
    for v in _paginate(ec2, "describe_volumes", "Volumes"):
        # A volume launched with an instance (root or block-device mapping) is part of that instance.
        with_instance = any(a.get("DeleteOnTermination") for a in v.get("Attachments") or [])
        out.append({"Identifier": v["VolumeId"], "Properties": {
            "LaunchedWithInstance": with_instance, "State": v.get("State"), "Size": v.get("Size"),
            "VolumeType": v.get("VolumeType"), "CreateTime": v.get("CreateTime"), "Tags": v.get("Tags") or []}})
    return out


ABANDONED_SNAPSHOT_DAYS = 90


def _snapshots(s, r):
    """Only snapshots that look abandoned: listing every snapshot would bury the report (most never are in IaC).
    Abandoned: this account's, older than ABANDONED_SNAPSHOT_DAYS, its volume gone, no AMI of this account
    uses it, standard tier, and not made by AWS Backup or Data Lifecycle Manager."""
    from datetime import datetime, timedelta, timezone
    ec2 = s.client("ec2", region_name=r)
    cutoff = datetime.now(timezone.utc) - timedelta(days=ABANDONED_SNAPSHOT_DAYS)
    snapshots = [x for x in _paginate(ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"])
                 if x.get("StartTime") and x["StartTime"] <= cutoff and x.get("StorageTier", "standard") == "standard"]
    if not snapshots:
        return []
    volumes = {v["VolumeId"] for v in _paginate(ec2, "describe_volumes", "Volumes")}
    in_ami = {m["Ebs"]["SnapshotId"] for image in _paginate(ec2, "describe_images", "Images", Owners=["self"])
              for m in image.get("BlockDeviceMappings") or [] if (m.get("Ebs") or {}).get("SnapshotId")}
    out = []
    for x in snapshots:
        tags = {t.get("Key"): t.get("Value") for t in x.get("Tags") or []}
        if x["SnapshotId"] in in_ami or x.get("VolumeId") in volumes or any(
                k.startswith(("aws:backup:", "aws:dlm:")) for k in tags) or "AWS Backup" in str(x.get("Description")):
            continue
        out.append({"Identifier": x["SnapshotId"], "Properties": {
            "Abandoned": True, "VolumeSize": x.get("VolumeSize"), "FullSnapshotSizeInBytes": x.get("FullSnapshotSizeInBytes"),
            "StartTime": x["StartTime"], "VolumeId": x.get("VolumeId"), "Tags": x.get("Tags") or []}})
    return out


def _vpc_endpoints(s, r):
    ec2 = s.client("ec2", region_name=r)
    return [{"Identifier": e["VpcEndpointId"], "Properties": {"RequesterManaged": e.get("RequesterManaged"),
                                                           "VpcEndpointType": e.get("VpcEndpointType"), "Tags": e.get("Tags") or []}}
            for e in _paginate(ec2, "describe_vpc_endpoints", "VpcEndpoints")]


def _buckets(s, r):
    s3 = s.client("s3", region_name=r)
    out = []
    for b in s3.list_buckets().get("Buckets") or []:
        region = b.get("BucketRegion")
        if not region:
            try:
                region = s3.get_bucket_location(Bucket=b["Name"]).get("LocationConstraint") or "us-east-1"
            except Exception:
                region = ""
        out.append({"Identifier": b["Name"], "Properties": {"BucketName": b["Name"], "_region": region}})
    return out


def _iam_roles(s, r):
    iam = s.client("iam", region_name=r)
    return [{"Identifier": x["RoleName"], "Properties": {"RoleName": x["RoleName"], "Path": x.get("Path"), "Arn": x.get("Arn")}}
            for x in _paginate(iam, "list_roles", "Roles")]


def _iam_policies(s, r):
    iam = s.client("iam", region_name=r)  # Scope=Local skips ~1,600 AWS managed policies
    return [{"Identifier": x["Arn"], "Properties": {"PolicyName": x.get("PolicyName"), "Arn": x["Arn"]}}
            for x in _paginate(iam, "list_policies", "Policies", Scope="Local")]


def _instance_profiles(s, r):
    iam = s.client("iam", region_name=r)
    return [{"Identifier": x["InstanceProfileName"], "Properties": {"Arn": x.get("Arn"), "Path": x.get("Path")}}
            for x in _paginate(iam, "list_instance_profiles", "InstanceProfiles")]


def _kms_keys(s, r):
    kms = s.client("kms", region_name=r)
    out = []
    for k in _paginate(kms, "list_keys", "Keys"):
        try:
            meta = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
        except Exception:
            continue
        if meta.get("KeyState") in ("PendingDeletion", "PendingReplicaDeletion"):
            continue
        out.append({"Identifier": k["KeyId"], "Properties": {"KeyManager": meta.get("KeyManager"), "Arn": meta.get("Arn")}})
    return out


def _ecs_services(s, r):
    ecs = s.client("ecs", region_name=r)
    out = []
    for cluster in _paginate(ecs, "list_clusters", "clusterArns"):
        for arn in _paginate(ecs, "list_services", "serviceArns", cluster=cluster):
            out.append({"Identifier": arn, "Properties": {"Arn": arn, "_aliases": [[cluster.rsplit("/", 1)[-1], arn.rsplit("/", 1)[-1]]]}})
    return out


def _eks_nodegroups(s, r):
    eks = s.client("eks", region_name=r)
    out = []
    for cluster in _paginate(eks, "list_clusters", "clusters"):
        for ng in _paginate(eks, "list_nodegroups", "nodegroups", clusterName=cluster):
            out.append({"Identifier": f"{cluster}:{ng}", "Properties": {"Name": ng, "_aliases": [[cluster, ng]]}})
    return out


def _rds_clusters(s, r):
    rds = s.client("rds", region_name=r)
    return [{"Identifier": c["DBClusterIdentifier"], "Properties": {"Engine": c.get("Engine"), "Arn": c.get("DBClusterArn")}}
            for c in _paginate(rds, "describe_db_clusters", "DBClusters")]


def _event_rules(s, r):
    ev = s.client("events", region_name=r)
    out = []
    for bus in _paginate(ev, "list_event_buses", "EventBuses"):
        for rule in _paginate(ev, "list_rules", "Rules", EventBusName=bus["Name"]):
            ident = rule["Name"] if bus["Name"] == "default" else f"{bus['Name']}/{rule['Name']}"
            out.append({"Identifier": ident, "Properties": {"Name": rule["Name"], "Arn": rule.get("Arn"),
                                                            "ManagedBy": rule.get("ManagedBy")}})
    return out


def _elasticache_groups(s, r):
    ec = s.client("elasticache", region_name=r)
    return [{"Identifier": g["ReplicationGroupId"], "Properties": {"Arn": g.get("ARN")}}
            for g in _paginate(ec, "describe_replication_groups", "ReplicationGroups")]


def _elasticache_clusters(s, r):
    ec = s.client("elasticache", region_name=r)  # members of a replication group belong to the group
    return [{"Identifier": c["CacheClusterId"], "Properties": {"Arn": c.get("ARN")}}
            for c in _paginate(ec, "describe_cache_clusters", "CacheClusters") if not c.get("ReplicationGroupId")]


def _classic_elbs(s, r):
    elb = s.client("elb", region_name=r)
    return [{"Identifier": x["LoadBalancerName"], "Properties": {
        "Instances": len(x.get("Instances") or []), "CreateTime": x.get("CreatedTime")}}
            for x in _paginate(elb, "describe_load_balancers", "LoadBalancerDescriptions")]


def _cloudfront_policies(method, list_key, item_key):
    # Type=custom leaves out CloudFront's managed policies, which every account sees.
    def _list(s, r):
        cf = s.client("cloudfront", region_name="us-east-1")
        out, marker = [], None
        while True:
            page = getattr(cf, method)(Type="custom", **({"Marker": marker} if marker else {})).get(list_key) or {}
            for item in page.get("Items") or []:
                pol = item.get(item_key) or {}
                conf = next((v for k, v in pol.items() if k.endswith("Config")), {}) or {}
                out.append({"Identifier": pol["Id"], "Properties": {"Name": conf.get("Name")}})
            marker = page.get("NextMarker")
            if not marker:
                return out
    return _list


# Cloud Control lists ELBv2 resources without tags, so tag: ignore rules (such as the
# AWS Load Balancer Controller's elbv2.k8s.aws/cluster) could not match them.

def _elbv2_tags(elb, arns: list[str]) -> dict[str, list[dict[str, str]]]:
    out: dict[str, list[dict[str, str]]] = {}
    for i in range(0, len(arns), 20):  # DescribeTags takes at most 20 ARNs
        for d in elb.describe_tags(ResourceArns=arns[i:i + 20]).get("TagDescriptions") or []:
            out[d["ResourceArn"]] = d.get("Tags") or []
    return out


def _load_balancers(s, r):
    elb = s.client("elbv2", region_name=r)
    lbs = _paginate(elb, "describe_load_balancers", "LoadBalancers")
    tags = _elbv2_tags(elb, [lb["LoadBalancerArn"] for lb in lbs])
    usage = _lb_usage(elb, lbs)
    return [{"Identifier": lb["LoadBalancerArn"], "Properties": {
        "LoadBalancerArn": lb["LoadBalancerArn"], "LoadBalancerName": lb.get("LoadBalancerName"),
        "Type": lb.get("Type"), "CreateTime": lb.get("CreatedTime"), **usage.get(lb["LoadBalancerArn"], {}),
        "Tags": tags.get(lb["LoadBalancerArn"], [])}} for lb in lbs]


def _lb_usage(elb, lbs) -> dict[str, dict[str, int]]:
    """Listeners and registered targets per load balancer; empty when they can't be read (then say nothing)."""
    try:
        out = {lb["LoadBalancerArn"]: {"Listeners": len(_paginate(elb, "describe_listeners", "Listeners",
                                                                   LoadBalancerArn=lb["LoadBalancerArn"])), "Targets": 0}
               for lb in lbs if lb.get("Type") in ("application", "network")}
        if not out:
            return {}
        for group in _paginate(elb, "describe_target_groups", "TargetGroups"):
            arns = [a for a in group.get("LoadBalancerArns") or [] if a in out]
            if arns:
                n = len(elb.describe_target_health(TargetGroupArn=group["TargetGroupArn"]).get("TargetHealthDescriptions") or [])
                for a in arns:
                    out[a]["Targets"] += n
        return out
    except Exception:
        return {}


def _target_groups(s, r):
    elb = s.client("elbv2", region_name=r)
    groups = _paginate(elb, "describe_target_groups", "TargetGroups")
    tags = _elbv2_tags(elb, [g["TargetGroupArn"] for g in groups])
    return [{"Identifier": g["TargetGroupArn"], "Properties": {
        "TargetGroupArn": g["TargetGroupArn"], "TargetGroupName": g.get("TargetGroupName"),
        "Tags": tags.get(g["TargetGroupArn"], [])}} for g in groups]


def _lb_listeners(s, r):
    elb = s.client("elbv2", region_name=r)
    lbs = _paginate(elb, "describe_load_balancers", "LoadBalancers")
    lb_tags = _elbv2_tags(elb, [lb["LoadBalancerArn"] for lb in lbs])
    rows = []
    for lb in lbs:
        for ln in _paginate(elb, "describe_listeners", "Listeners", LoadBalancerArn=lb["LoadBalancerArn"]):
            rows.append((lb, ln))
    own = _elbv2_tags(elb, [ln["ListenerArn"] for _, ln in rows])
    out = []
    for lb, ln in rows:
        # A listener goes with its load balancer: it carries the LB's tags unless it sets its own.
        tags = {t["Key"]: t for t in lb_tags.get(lb["LoadBalancerArn"], [])}
        tags.update({t["Key"]: t for t in own.get(ln["ListenerArn"], [])})
        out.append({"Identifier": ln["ListenerArn"], "Properties": {
            "Name": f"{lb.get('LoadBalancerName')}:{ln.get('Port')}", "Tags": list(tags.values())}})
    return out


def _eks_children(kind):
    method, key, arg = {"addon": ("list_addons", "addons", "addonName"),
                        "fargate": ("list_fargate_profiles", "fargateProfileNames", "fargateProfileName")}[kind]

    def _list(s, r):
        eks = s.client("eks", region_name=r)
        out = []
        for cluster in _paginate(eks, "list_clusters", "clusters"):
            for name in _paginate(eks, method, key, clusterName=cluster):
                out.append({"Identifier": f"{cluster}:{name}", "Properties": {"Name": name, "_aliases": [[cluster, name]]}})
        return out
    return _list


_SCALING_NAMESPACES = ("ecs", "dynamodb", "rds", "elasticmapreduce", "ec2", "appstream", "sagemaker", "lambda",
                       "cassandra", "kafka", "elasticache", "neptune", "comprehend", "custom-resource", "workspaces")


def _scalable_targets(s, r):
    # Cloud Control can't list these without a namespace; the ID is Cloud Control's
    # (ResourceId|ScalableDimension|ServiceNamespace), so state and import IDs match as for other types.
    aas = s.client("application-autoscaling", region_name=r)
    out = []
    for ns in _SCALING_NAMESPACES:
        try:
            targets = _paginate(aas, "describe_scalable_targets", "ScalableTargets", ServiceNamespace=ns)
        except Exception as exc:
            if "ValidationException" in f"{type(exc).__name__} {exc}":  # a namespace this region doesn't have
                continue
            raise
        for t in targets:
            out.append({"Identifier": f"{t['ResourceId']}|{t['ScalableDimension']}|{ns}",
                        "Properties": {"ResourceId": t["ResourceId"], "Arn": t.get("ScalableTargetARN") or "",
                                       # "orch-imp-table read capacity": what it scales, and which dimension
                                       "Name": f"{t['ResourceId'].rsplit('/', 1)[-1]} "
                                               f"{t['ScalableDimension'].rsplit(':', 1)[-1]}"}})
    return out


def _opensearch_domains(s, r):
    client = s.client("opensearch", region_name=r)
    return [{"Identifier": d["DomainName"], "Properties": {"DomainName": d["DomainName"]}}
            for d in client.list_domain_names().get("DomainNames") or []]


def _appconfig_children(kind):
    method, id_key = {"environment": ("list_environments", "EnvironmentId"),
                      "profile": ("list_configuration_profiles", "ConfigurationProfileId")}[kind]

    def _list(s, r):
        ac = s.client("appconfig", region_name=r)
        out = []
        for app in _paginate(ac, "list_applications", "Items"):
            for item in _paginate(ac, method, "Items", ApplicationId=app["Id"]):
                # Terraform's id is "<child id>:<application id>"
                out.append({"Identifier": f"{app['Id']}|{item['Id']}", "Properties": {"Name": item.get("Name")}})
        return out
    return _list


def _ssm_documents(s, r):
    ssm = s.client("ssm", region_name=r)
    return [{"Identifier": d["Name"], "Properties": {"Name": d["Name"]}}
            for d in _paginate(ssm, "list_documents", "DocumentIdentifiers", Filters=[{"Key": "Owner", "Values": ["Self"]}])]


NATIVE_LISTERS: dict[str, Callable[[Any, str], list[dict[str, Any]]]] = {
    "AWS::EC2::VPC": _vpcs,
    "AWS::EC2::Subnet": _subnets,
    "AWS::EC2::SecurityGroup": _security_groups,
    "AWS::EC2::InternetGateway": _internet_gateways,
    "AWS::EC2::DHCPOptions": _dhcp_options,
    "AWS::EC2::RouteTable": _route_tables,
    "AWS::EC2::NetworkAcl": _network_acls,
    "AWS::EC2::NatGateway": _nat_gateways,
    "AWS::EC2::EIP": _elastic_ips,
    "AWS::EC2::Instance": _instances,
    "AWS::EC2::Volume": _volumes,
    "AWS::ApplicationAutoScaling::ScalableTarget": _scalable_targets,
    "AWS::EC2::Snapshot": _snapshots,
    "AWS::EC2::VPCEndpoint": _vpc_endpoints,
    "AWS::S3::Bucket": _buckets,
    "AWS::IAM::Role": _iam_roles,
    "AWS::IAM::ManagedPolicy": _iam_policies,
    "AWS::IAM::InstanceProfile": _instance_profiles,
    "AWS::KMS::Key": _kms_keys,
    "AWS::ECS::Service": _ecs_services,
    "AWS::EKS::Nodegroup": _eks_nodegroups,
    "AWS::RDS::DBCluster": _rds_clusters,
    "AWS::Events::Rule": _event_rules,
    "AWS::ElastiCache::ReplicationGroup": _elasticache_groups,
    "AWS::ElastiCache::CacheCluster": _elasticache_clusters,
    "AWS::ElasticLoadBalancing::LoadBalancer": _classic_elbs,
    "AWS::SSM::Document": _ssm_documents,
    "AWS::CloudFront::CachePolicy": _cloudfront_policies("list_cache_policies", "CachePolicyList", "CachePolicy"),
    "AWS::CloudFront::OriginRequestPolicy": _cloudfront_policies(
        "list_origin_request_policies", "OriginRequestPolicyList", "OriginRequestPolicy"),
    "AWS::CloudFront::ResponseHeadersPolicy": _cloudfront_policies(
        "list_response_headers_policies", "ResponseHeadersPolicyList", "ResponseHeadersPolicy"),
    "AWS::ElasticLoadBalancingV2::LoadBalancer": _load_balancers,
    "AWS::ElasticLoadBalancingV2::TargetGroup": _target_groups,
    "AWS::ElasticLoadBalancingV2::Listener": _lb_listeners,
    "AWS::EKS::Addon": _eks_children("addon"),
    "AWS::EKS::FargateProfile": _eks_children("fargate"),
    "AWS::OpenSearchService::Domain": _opensearch_domains,
    "AWS::AppConfig::Environment": _appconfig_children("environment"),
    "AWS::AppConfig::ConfigurationProfile": _appconfig_children("profile"),
}

# Cloud Control types that need a ResourceModel to be listed.
_MODELS = {
    "AWS::WAFv2::WebACL": {"Scope": "REGIONAL"},
    "AWS::WAFv2::IPSet": {"Scope": "REGIONAL"},
    "AWS::WAFv2::RegexPatternSet": {"Scope": "REGIONAL"},
    "AWS::WAFv2::RuleGroup": {"Scope": "REGIONAL"},
}

# RDS's cluster API also returns DocumentDB and Neptune clusters.
_CLUSTER_ENGINE_TYPES = {"docdb": "aws_docdb_cluster", "neptune": "aws_neptune_cluster"}


# --- resources AWS owns ----------------------------------------------------
# Copied from OrchesTerra's rules. Each uses evidence a customer cannot reproduce.

_CLOUDFRONT_MANAGED_IDS = frozenset({
    "658327ea-f89d-4fab-a63d-7e88639e58f6", "4135ea2d-6df8-44a3-9df3-4b5a84be39ad", "b2884449-e4de-46a7-ac36-70bc7f1ddd6d",
    "08627262-05a9-4f76-9ded-b50ca2e3a84f", "83da9c7e-98b4-4e11-a168-04f0df8e2c65", "216adef6-5c7f-47e4-b989-5492eafa07d3",
    "88a5eaf4-2fd4-4709-b370-b4c650ea3fcf", "acba4595-bd28-49b8-b9fe-13317c0390fa", "59781a5b-3903-41f3-afcb-af62929ccde1",
    "775133bc-15f2-49f9-abea-afb2e0bf67d2", "b689b0a8-53d0-40ab-baf2-68738e2966ac", "33f36d7e-f396-46d9-90e0-52428a34d9dc",
    "5cc3b908-e619-4b99-88e5-2cf7f45965bd", "60669652-455b-4ae9-85a4-c4c02393f86c", "67f7725c-6f97-4210-82d7-5512b31e9d03",
    "e61eb60c-9c35-4d20-a928-2b84e02af89c", "eaab4381-ed33-4a86-88ca-d9558dc6cd63",
})
_EKS_CLUSTER_SG = re.compile(r"^eks-cluster-sg-.+-\d+$")
_CLOUDHSM_SG = re.compile(r"^cloudhsm-cluster-[a-z0-9-]+-sg$")
_DIRECTORY_SG = re.compile(r"^d-[0-9a-f]{10}_(controllers|workspacesMembers)$")
_EMR_SG_NAMES = {"ElasticMapReduce-master", "ElasticMapReduce-slave", "ElasticMapReduce-ServiceAccess"}


def aws_owned_reason(res: LiveResource) -> str:
    """Why AWS owns this resource (so it is never "not in IaC"), or "" when it is the customer's."""
    p, t, n, ident = res.props, res.tf_type, res.name, res.identifier
    tags = _tag_map(p.get("Tags"))
    arn = res.arn or (ident if ident.startswith("arn:") else "")
    if t in ("aws_vpc", "aws_network_acl", "aws_internet_gateway") and p.get("IsDefault"):
        return "default VPC resource"
    if t == "aws_subnet" and p.get("DefaultForAz"):
        return "default subnet"
    if t == "aws_route_table" and p.get("Main"):
        return "VPC main route table"
    if t == "aws_vpc_dhcp_options" and p.get("IsDefault"):
        return "default DHCP options"
    if t == "aws_security_group":
        g, d = str(p.get("GroupName") or n), str(p.get("Description") or "")
        if g == "default":
            return "VPC default security group"
        if tags.get("aws:eks:cluster-name") or (_EKS_CLUSTER_SG.match(g) and d.startswith("EKS created")):
            return "created by Amazon EKS"
        if _CLOUDHSM_SG.match(g):
            return "created by AWS CloudHSM"
        if _DIRECTORY_SG.match(g) and d.startswith("AWS created"):
            return "created by AWS Directory Service"
        if g in _EMR_SG_NAMES:
            return "created by Amazon EMR"
    if t == "aws_instance" and (tags.get("aws:autoscaling:groupName") or tags.get("eks:nodegroup-name")):
        return "launched by an Auto Scaling group"
    if t == "aws_ebs_volume" and p.get("LaunchedWithInstance"):
        return "launched with an EC2 instance"
    if t == "aws_vpc_endpoint" and p.get("RequesterManaged"):
        return "requester-managed endpoint (created by an AWS service)"
    if t == "aws_iam_role" and str(p.get("Path") or "").startswith(("/aws-service-role/", "/aws-reserved/")):
        return "service-linked or AWS SSO role"
    if t == "aws_iam_role" and n == "OrganizationAccountAccessRole":
        return "created by AWS Organizations when the account joined"
    if t == "aws_iam_role" and (n.startswith("stacksets-exec-") or n == "AWSCloudFormationStackSetExecutionRole"):
        return "CloudFormation StackSets execution role"
    if n.startswith(("AWSControlTower", "aws-controltower")) or ident.startswith("aws-controltower"):
        return "created by AWS Control Tower"
    if t == "aws_iam_policy" and ":aws:policy/" in arn:
        return "AWS managed policy"
    if t == "aws_kms_key" and p.get("KeyManager") == "AWS":
        return "AWS managed key"
    if t == "aws_kms_alias" and (n.startswith("alias/aws/") or ident.startswith("alias/aws/")):
        return "AWS managed key alias"
    if t == "aws_cloudwatch_event_bus" and (n == "default" or ident.endswith("/default") or ident == "default"):
        return "default event bus"
    if t == "aws_cloudwatch_event_rule" and p.get("ManagedBy"):
        return f"managed by {p['ManagedBy']}"
    if t == "aws_cloudwatch_metric_alarm" and n.startswith(("TargetTracking-", "AutoScaling-")):
        return "created by Application Auto Scaling"
    if t == "aws_secretsmanager_secret" and ("!" in n or "!" in ident or tags.get("aws:secretsmanager:owningService")):
        return "created by an AWS service (managed secret)"
    if t == "aws_ssm_document" and n.lower().startswith(("aws", "amazon", "amzn")) and "/" not in n:
        return "Amazon-owned SSM document"
    if t == "aws_ssm_patch_baseline" and (n.startswith("AWS-") or ident.startswith("arn:")):
        return "AWS patch baseline"
    if t == "aws_ec2_managed_prefix_list" and (n.startswith("com.amazonaws.") or ":aws:" in arn):
        return "AWS managed prefix list"
    if t.startswith("aws_cloudfront_") and t.endswith("_policy"):
        if ident in _CLOUDFRONT_MANAGED_IDS or n.startswith("Managed-") or n.lower().startswith("useorigincachecontrolheaders"):
            return "CloudFront managed policy"
    if t in ("aws_xray_group", "aws_xray_sampling_rule") and (n == "Default" or ident.endswith("/Default")):
        return "X-Ray default"
    if t in ("aws_db_option_group", "aws_db_parameter_group", "aws_rds_cluster_parameter_group") and \
            (n.lower().startswith(("default.", "default:")) or ident.lower().startswith(("default.", "default:"))):
        return "RDS default group"
    if t == "aws_db_subnet_group" and n.lower() == "default":
        return "RDS default subnet group"
    if t == "aws_athena_data_catalog" and ident == "AwsDataCatalog":
        return "Athena default catalog"
    if t == "aws_athena_workgroup" and ident == "primary":
        return "Athena primary workgroup"
    if t == "aws_scheduler_schedule_group" and ident == "default":
        return "default schedule group"
    if t == "aws_backup_vault" and (ident == "Default" or ident.startswith("aws/")):
        return "AWS Backup default vault"
    if t == "aws_route53_resolver_rule" and "rslvr-autodefined" in (ident + arn):
        return "Route 53 Resolver default rule"
    if t == "aws_launch_template" and (tags.get("eks:nodegroup-name") or n.startswith("eks-")):
        return "created by Amazon EKS"
    return ""


# --- listing ---------------------------------------------------------------

@dataclass
class Inventory:
    resources: list[LiveResource] = field(default_factory=list)
    owned: list[tuple[LiveResource, str]] = field(default_factory=list)
    not_listed: dict[str, str] = field(default_factory=dict)   # "type (region)" -> reason


def _list_one(session: Any, region: str, cc_type: str) -> list[dict[str, Any]]:
    lister = NATIVE_LISTERS.get(cc_type)
    if lister is not None:
        try:
            return lister(session, region)
        except Exception as exc:
            text = f"{type(exc).__name__} {exc}"
            if any(marker in text for marker in _SKIP_ERRORS):
                raise Skipped(text) from exc
            raise
    client = session.client("cloudcontrol", region_name=region)
    return list_cloudcontrol(client, cc_type, _MODELS.get(cc_type))


def _to_live(cc_type: str, region: str, row: dict[str, Any]) -> LiveResource | None:
    ident = str(row.get("Identifier") or "").strip()
    if not ident:
        return None
    props = _props(row.get("Properties"))
    tf = terraform_type(cc_type)
    if cc_type == "AWS::RDS::DBCluster":
        tf = _CLUSTER_ENGINE_TYPES.get(str(props.get("Engine") or "").lower(), tf)
    if tf == "aws_eip" and "|" in ident:  # Cloud Control keys an EIP as "<ip>|<allocation id>"
        ident = next((p for p in ident.split("|") if p.startswith("eipalloc-")), ident)
    arn = str(props.get("Arn") or props.get("ARN") or "") or (ident if ident.startswith("arn:") else "")
    res_region = props.pop("_region", None) or ("" if cc_type.startswith(("AWS::IAM::", "AWS::CloudFront::", "AWS::Route53::", "AWS::Budgets::")) else region)
    return LiveResource(cc_type, tf, ident, res_region, _name(ident, props), arn, props)


class _RetrySession:
    """Session whose clients retry throttled calls with backoff (Cloud Control throttles parallel listing)."""

    def __init__(self, session: Any):
        self._session = session
        self.region_name = getattr(session, "region_name", None)
        try:
            from botocore.config import Config
            self._config = Config(retries={"mode": "adaptive", "max_attempts": 12})
        except ImportError:  # fake sessions in tests
            self._config = None

    def client(self, service: str, region_name: str | None = None):
        if self._config is None:
            return self._session.client(service, region_name=region_name)
        return self._session.client(service, region_name=region_name, config=self._config)


def list_inventory(session: Any, regions: list[str], types: Iterable[str] | None = None,
                   workers: int = 4, log: Callable[..., None] = print) -> Inventory:
    """List every chosen type in every region (global types once)."""
    session = _RetrySession(session)
    wanted = [t for t in (types or CLOUDCONTROL_TO_TERRAFORM)]
    jobs: list[tuple[str, str]] = []
    for i, region in enumerate(regions):
        for cc_type in wanted:
            if is_global(cc_type) and i > 0:
                continue
            jobs.append((region, cc_type))
    inv = Inventory()
    seen: set[tuple[str, str, str]] = set()
    started = time.monotonic()

    def run(job):
        region, cc_type = job
        try:
            return job, _list_one(session, region, cc_type), ""
        except Skipped as exc:
            return job, [], _short_reason(str(exc))
        except Exception as exc:  # keep going; one bad type shouldn't sink the scan
            return job, [], _short_reason(f"{type(exc).__name__}: {exc}")

    log(f"listing {len(jobs)} resource types across {len(regions)} region(s) …", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for (region, cc_type), rows, reason in pool.map(run, jobs):
            if reason:
                inv.not_listed[f"{cc_type} ({'global' if is_global(cc_type) else region})"] = reason
                continue
            for row in rows:
                res = _to_live(cc_type, region, row)
                if res is None or (res.tf_type, res.identifier, res.region) in seen:
                    continue
                seen.add((res.tf_type, res.identifier, res.region))
                if res.region and res.region not in regions and cc_type == "AWS::S3::Bucket":
                    continue  # a bucket in a region the scan did not cover
                why = aws_owned_reason(res)
                if why:
                    inv.owned.append((res, why))
                else:
                    inv.resources.append(res)
    log(f"listed {len(inv.resources)} resources ({len(inv.owned)} AWS-owned skipped) in "
        f"{time.monotonic() - started:.0f}s", file=sys.stderr)
    return inv


# Reasons a type is never listed whatever the permissions: listed in the JSON, but they don't make a scan
# incomplete (otherwise every scan would say so).
KNOWN_LIMITS = frozenset({"needs a parent resource to list; not checked", "the service returned an error",
                          "type not available", "listing not supported", "region or service not enabled",
                          "service not in region", "service not enabled"})


def _short_reason(text: str) -> str:
    # Access denied first: Cloud Control wraps it in "Handler returned status FAILED".
    for marker, label in (("AccessDenied", "access denied"), ("not authorized", "access denied"),
                          ("UnauthorizedOperation", "access denied"),
                          ("Throttling", "throttled by AWS; rerun with fewer --workers"),
                          ("Rate exceeded", "throttled by AWS; rerun with fewer --workers"),
                          ("ResourceModel", "needs a parent resource to list; not checked"),
                          ("Handler returned", "the service returned an error"),
                          ("TypeNotFound", "type not available"),
                          ("UnsupportedAction", "listing not supported"), ("is not supported", "listing not supported"),
                          ("OptInRequired", "region or service not enabled"), ("Could not connect", "service not in region"),
                          ("SubscriptionRequired", "service not enabled")):
        if marker in text:
            return label
    return text.splitlines()[0][:160]


# --- import blocks -----------------------------------------------------------

# Where the listed identifier isn't what Terraform imports by. Each was checked against the Import section of
# the resource's page in the Terraform AWS provider docs (2026-11-24). (res, account) -> import ID, or "".

def _parts(res: LiveResource, n: int) -> list[str]:
    parts = res.identifier.split("|")
    return parts if len(parts) == n and all(parts) else []


def _wafv2(res: LiveResource, account: str) -> str:  # Cloud Control: Name|Id|Scope; Terraform: ID/NAME/SCOPE
    p = _parts(res, 3)
    return f"{p[1]}/{p[0]}/{p[2]}" if p else ""


def _scalable_target(res: LiveResource, account: str) -> str:
    # Cloud Control: ResourceId|ScalableDimension|ServiceNamespace; Terraform: namespace/resource-id/dimension
    p = _parts(res, 3)
    return f"{p[2]}/{p[0]}/{p[1]}" if p else ""


def _arn_tail(marker: str) -> Callable[[LiveResource, str], str]:
    """Terraform takes the name or ID that follows `marker` in the listed ARN."""
    def convert(res: LiveResource, account: str) -> str:
        arn = res.arn or res.identifier
        return arn.split(marker, 1)[1] if marker in arn else ("" if arn.startswith("arn:") else res.identifier)
    return convert


def _arn_of(service: str, path: str) -> Callable[[LiveResource, str], str]:
    """Terraform takes the ARN; build it from the name when the listing only gave the name."""
    def convert(res: LiveResource, account: str) -> str:
        if res.arn.startswith("arn:"):
            return res.arn
        if not account or not res.region:
            return ""
        return f"arn:aws:{service}:{res.region}:{account}:{path}{res.identifier}"
    return convert


def _account_name(res: LiveResource, account: str) -> str:
    return f"{account}:{res.identifier}" if account else ""


def _prop(*keys: str) -> Callable[[LiveResource, str], str]:
    def convert(res: LiveResource, account: str) -> str:
        return next((str(res.props[k]) for k in keys if res.props.get(k)), "")
    return convert


_IMPORT_IDS: dict[str, Callable[[LiveResource, str], str]] = {
    **{t: _wafv2 for t in ("aws_wafv2_web_acl", "aws_wafv2_ip_set", "aws_wafv2_regex_pattern_set",
                           "aws_wafv2_rule_group")},
    "aws_appautoscaling_target": _scalable_target,
    # FilterName|LogGroupName -> "group|filter"
    "aws_cloudwatch_log_subscription_filter": lambda res, account: "|".join(reversed(_parts(res, 2))),
    # app|child (this tool's listing) -> "child:app"
    **{t: (lambda res, account: ":".join(reversed(_parts(res, 2))))
       for t in ("aws_appconfig_environment", "aws_appconfig_configuration_profile")},
    # service ARN -> "cluster/service"
    "aws_ecs_service": lambda res, account: "/".join((res.props.get("_aliases") or [[]])[0][:2])
    if len((res.props.get("_aliases") or [[]])[0]) >= 2 else "",
    "aws_kinesis_firehose_delivery_stream": _arn_of("firehose", "deliverystream/"),
    "aws_cloudtrail": _arn_of("cloudtrail", "trail/"),
    "aws_kinesisanalyticsv2_application": _arn_of("kinesisanalytics", "application/"),
    "aws_cloudwatch_query_definition": _arn_of("logs", "query-definition:"),
    "aws_budgets_budget": _account_name,
    "aws_s3_access_point": _account_name,
    "aws_appsync_graphql_api": _arn_tail(":apis/"),
    "aws_batch_compute_environment": _arn_tail(":compute-environment/"),
    "aws_cloudfront_function": _arn_tail(":function/"),
    "aws_sagemaker_notebook_instance": _arn_tail(":notebook-instance/"),
    "aws_transfer_server": _arn_tail(":server/"),
    "aws_xray_sampling_rule": _arn_tail(":sampling-rule/"),
    "aws_dms_replication_instance": _prop("ReplicationInstanceIdentifier"),
    "aws_codecommit_repository": _prop("RepositoryName", "Name"),
    "aws_scheduler_schedule": lambda res, account: f"{res.props.get('GroupName') or 'default'}/{res.identifier}",
}


def import_id(res: LiveResource, account: str = "") -> str:
    """The ID `terraform import` / an `import {}` block takes for this resource, or "" when not known.
    Anything else with a "|" in it is a composite Cloud Control key Terraform won't take."""
    convert = _IMPORT_IDS.get(res.tf_type)
    if convert:
        return convert(res, account)
    return "" if "|" in res.identifier else res.identifier


# --- idle and still billing ------------------------------------------------
# Hourly on-demand rates come from the AWS Price List API for the resource's region. When that can't be
# read (no pricing:GetProducts, no network), the us-east-1 list prices below are used and the text says so.

HOURS_PER_MONTH = 730
# Per hour, except EBS volumes and snapshots: per GB-month.
_US_EAST_1_RATES = {"nat": 0.045, "ipv4_in_use": 0.005, "ipv4_idle": 0.005, "alb": 0.0225, "nlb": 0.0225, "clb": 0.025,
                    "snapshot": 0.05, "ebs:gp3": 0.08, "ebs:gp2": 0.10, "ebs:io1": 0.125, "ebs:io2": 0.125,
                    "ebs:st1": 0.045, "ebs:sc1": 0.015, "ebs:standard": 0.05}
_EBS_USAGE = {"gp3": "EBS:VolumeUsage.gp3", "gp2": "EBS:VolumeUsage.gp2", "io1": "EBS:VolumeUsage.piops",
              "io2": "EBS:VolumeUsage.io2", "st1": "EBS:VolumeUsage.st1", "sc1": "EBS:VolumeUsage.sc1",
              "standard": "EBS:VolumeUsage"}
_PRICE_QUERIES = {  # kind -> (service code, usage type without its region prefix, extra filters)
    "nat": ("AmazonEC2", "NatGateway-Hours", {"productFamily": "NAT Gateway", "operation": "NatGateway"}),
    "ipv4_in_use": ("AmazonVPC", "PublicIPv4:InUseAddress", {"group": "VPCPublicIPv4Address"}),
    "ipv4_idle": ("AmazonVPC", "PublicIPv4:IdleAddress", {"group": "VPCPublicIPv4Address"}),
    "alb": ("AWSELB", "LoadBalancerUsage", {"productFamily": "Load Balancer-Application"}),
    "nlb": ("AWSELB", "LoadBalancerUsage", {"productFamily": "Load Balancer-Network"}),
    "clb": ("AWSELB", "LoadBalancerUsage", {"productFamily": "Load Balancer"}),
    "snapshot": ("AmazonEC2", "EBS:SnapshotUsage", {"productFamily": "Storage Snapshot"}),
    **{f"ebs:{t}": ("AmazonEC2", u, {"productFamily": "Storage", "volumeApiName": t}) for t, u in _EBS_USAGE.items()},
}


def _usage_matches(usagetype: str, base: str) -> bool:
    """"NatGateway-Hours" matches itself and "EU-NatGateway-Hours", not "RegionalNatGateway-Hours"."""
    return usagetype == base or usagetype.partition("-")[2] == base


class Prices:
    """Hourly list prices per region, read from the Price List API the first time an idle resource needs one."""

    def __init__(self, session: Any = None, log: Callable[..., None] = print):
        self._session, self._log = session, log
        self._client: Any = None
        self._cache: dict[tuple[str, str], float | None] = {}
        self.failed = session is None

    def _read(self, kind: str, region: str) -> float | None:
        service, usage, extra = _PRICE_QUERIES[kind]
        return self._query(service, region, extra, lambda ut: _usage_matches(ut, usage))

    def find(self, key: str, service: str, region: str, extra: dict[str, str],
             matches: Callable[[str], bool]) -> float | None:
        """A live price other modules ask for (e.g. extended support), cached under `key`; None when unreadable."""
        if not self.failed and (key, region) not in self._cache:
            try:
                self._cache[(key, region)] = self._query(service, region, extra, matches)
            except Exception as exc:
                self.failed = True
                self._log(f"note: could not read AWS prices ({_short_reason(str(exc))}); costs use us-east-1 list prices. "
                          "Live prices need pricing:GetProducts (in ReadOnlyAccess).", file=sys.stderr)
        return self._cache.get((key, region))

    def _query(self, service: str, region: str, extra: dict[str, str], matches: Callable[[str], bool]) -> float | None:
        if self._client is None:
            try:
                from botocore.config import Config
                config = Config(connect_timeout=3, read_timeout=6, retries={"max_attempts": 2})
            except ImportError:  # fake sessions in tests
                config = None
            # The Price List API only has endpoints in us-east-1 (and two others); prices cover every region.
            kwargs = {"config": config} if config else {}
            self._client = self._session.client("pricing", region_name="us-east-1", **kwargs)
        filters = [{"Type": "TERM_MATCH", "Field": "regionCode", "Value": region}]
        filters += [{"Type": "TERM_MATCH", "Field": k, "Value": v} for k, v in extra.items()]
        for raw in self._client.get_products(ServiceCode=service, Filters=filters, MaxResults=100).get("PriceList", []):
            product = json.loads(raw) if isinstance(raw, str) else raw
            if not matches(str(product.get("product", {}).get("attributes", {}).get("usagetype", ""))):
                continue
            for term in product.get("terms", {}).get("OnDemand", {}).values():
                for dim in term.get("priceDimensions", {}).values():
                    usd = float(dim.get("pricePerUnit", {}).get("USD") or 0)
                    if usd > 0:
                        return usd
        return None

    def rate(self, kind: str, region: str) -> tuple[float, bool]:
        """(rate, True) from the Price List API, or (us-east-1 rate, False) when it couldn't be read."""
        if not self.failed and (kind, region) not in self._cache:
            try:
                self._cache[(kind, region)] = self._read(kind, region)
            except Exception as exc:  # stop asking after the first failure: it would fail the same way
                self.failed = True
                self._log(f"note: could not read AWS prices ({_short_reason(str(exc))}); idle costs use us-east-1 list prices. "
                          "Live prices need pricing:GetProducts (in ReadOnlyAccess).", file=sys.stderr)
        rate = self._cache.get((kind, region))
        return (rate, True) if rate else (_US_EAST_1_RATES[kind], False)


def _nat_monthly(p: dict, region: str, prices: Prices) -> tuple[float, str, bool]:
    """(monthly USD, the gateway/address split or "", whether every price was live) for a NAT gateway."""
    nat, live = prices.rate("nat", region)
    ips = int(p.get("PublicIps") or 0)
    ip, ip_live = prices.rate("ipv4_in_use", region) if ips else (0.0, live)
    gateway, addresses = nat * HOURS_PER_MONTH, ip * HOURS_PER_MONTH * ips
    split = ""
    if ips:  # each public IPv4 address on it is billed too (since February 2024)
        split = f" (${gateway:.2f} for the gateway, ${addresses:.2f} for {ips} public IPv4 address{'es' if ips > 1 else ''})"
    return gateway + addresses, split, live and ip_live


def _size(n: float) -> str:
    for unit, scale in (("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if n >= scale:
            return f"{n / scale:.1f} {unit}"
    return f"{int(n)} bytes"


def idle_cost(res: LiveResource, prices: Prices | None = None) -> tuple[str, float] | None:
    """(why it looks idle while it still costs money, monthly USD), or None."""
    p, prices = res.props, prices or Prices()
    region = res.region or "us-east-1"
    if res.tf_type == "aws_nat_gateway" and p.get("Routed") is False:
        monthly, split, live = _nat_monthly(p, region, prices)
        why = f"no route table in this account sends traffic to it; an idle NAT gateway still bills about ${monthly:.2f}/month"
        return why + split + _price_note(region, live), monthly
    if res.tf_type == "aws_nat_gateway" and p.get("Routed") and (moved := p.get("BytesLast14Days")) is not None \
            and moved < QUIET_BYTES:
        monthly, split, live = _nat_monthly(p, region, prices)
        why = (f"a route table points at it, but it moved {f'only {_size(moved)}' if moved else 'nothing'} in the last {QUIET_DAYS} days; "
               f"a NAT gateway that quiet still bills about ${monthly:.2f}/month")
        return why + split + _price_note(region, live), monthly
    if res.tf_type == "aws_eip" and p.get("Attached") is False and not p.get("ServiceManaged"):
        ip, live = prices.rate("ipv4_idle", region)
        monthly = ip * HOURS_PER_MONTH
        return f"attached to nothing; an Elastic IP still bills about ${monthly:.2f}/month" + _price_note(region, live), monthly
    if _young(p.get("CreateTime")):
        return None  # a new volume or load balancer may simply not be in use yet
    if res.tf_type == "aws_ebs_volume" and p.get("State") == "available" and p.get("Size"):
        kind = f"ebs:{p.get('VolumeType')}" if f"ebs:{p.get('VolumeType')}" in _US_EAST_1_RATES else "ebs:gp2"
        gb_month, live = prices.rate(kind, region)
        monthly = gb_month * float(p["Size"])
        return (f"attached to nothing; this {p['Size']} GB {p.get('VolumeType') or ''} volume still bills about "
                f"${monthly:.2f}/month for storage" + _price_note(region, live), monthly)
    if res.tf_type in ("aws_lb", "aws_alb") and p.get("Targets") == 0 and p.get("Type") in ("application", "network"):
        hourly, live = prices.rate("alb" if p["Type"] == "application" else "nlb", region)
        monthly = hourly * HOURS_PER_MONTH
        n = int(p.get("Listeners") or 0)
        what = (f"it has {n} listener{'s' if n != 1 else ''} but no registered targets, so it can only redirect or "
                "return fixed responses" if n else "no listeners and no registered targets")
        return f"{what}; a load balancer still bills about ${monthly:.2f}/month" + _price_note(region, live), monthly
    if res.tf_type == "aws_elb" and p.get("Instances") == 0:
        hourly, live = prices.rate("clb", region)
        monthly = hourly * HOURS_PER_MONTH
        return (f"no instances registered; a Classic Load Balancer still bills about ${monthly:.2f}/month"
                + _price_note(region, live), monthly)
    if res.tf_type == "aws_ebs_snapshot" and p.get("Abandoned"):
        gb_month, live = prices.rate("snapshot", region)
        full = p.get("FullSnapshotSizeInBytes")
        gb = float(full) / 2**30 if full else float(p.get("VolumeSize") or 0)
        monthly = gb_month * gb
        days = _age_days(p.get("StartTime"))
        return (f"{days} days old, its volume {p.get('VolumeId') or ''} is gone and no AMI uses it; it bills up to about "
                f"${monthly:.2f}/month for {gb:.0f} GB (less if it shares blocks with other snapshots)"
                + _price_note(region, live), monthly)
    return None


IDLE_MIN_AGE_DAYS = 7


def _age_days(created: Any) -> int:
    from datetime import datetime, timezone
    if not isinstance(created, datetime):
        return 0
    return (datetime.now(timezone.utc) - (created if created.tzinfo else created.replace(tzinfo=timezone.utc))).days


def _young(created: Any) -> bool:
    return created is not None and _age_days(created) < IDLE_MIN_AGE_DAYS


def idle_label(res: LiveResource) -> str:
    """"idle" when it certainly does nothing; a softer word when it probably doesn't (found at medium severity)."""
    p = res.props
    if res.tf_type == "aws_nat_gateway" and p.get("Routed"):
        return "nearly unused"
    if res.tf_type in ("aws_lb", "aws_alb") and p.get("Listeners"):
        return "probably unused"
    if res.tf_type == "aws_ebs_snapshot":
        return "probably abandoned"
    return "idle"


def _price_note(region: str, live: bool) -> str:
    return f" in {region}" if live else f" (us-east-1 list price used where the live {region} price could not be read)"


def idle_reason(res: LiveResource, prices: Prices | None = None) -> str:
    """Why this resource looks idle while it still costs money, or ""."""
    found = idle_cost(res, prices)
    return found[0] if found else ""


# --- what IaC knows about --------------------------------------------------

_STATE_KEYS = ("id", "arn", "name", "identifier", "bucket", "url", "key_id", "function_name")


@dataclass
class IacEntry:
    tf_type: str          # Terraform type (normalized), or "" for a CloudFormation resource
    cc_type: str          # CloudFormation type, or "" for Terraform
    tokens: frozenset[str]
    region: str
    where: str            # state file or stack
    address: str = ""     # Terraform address (module.x.aws_s3_bucket.logs["a"]), or the stack's logical id
    ident: str = ""       # the state's `id` attribute
    account: str = ""     # AWS account the state recorded, when its ARN or owner says
    module: str = ""      # Terraform module path (module.x.module.y), "" for the root module


def _state_tokens(attrs: dict[str, Any]) -> tuple[frozenset[str], str]:
    tokens: set[str] = set()
    region = ""
    for key, value in attrs.items():
        if not isinstance(value, str) or not value:
            continue
        if key in _STATE_KEYS or (key.endswith(("_name", "_identifier", "_arn"))
                                  and key not in ("display_name", "role_arn", "kms_key_arn", "execution_role_arn")):
            tokens.add(value)
            if value.startswith("arn:"):
                region = region or _arn_region(value)
                tokens.add(re.split(r"[:/]", value)[-1])
    ident = attrs.get("id")
    if isinstance(ident, str):
        for sep in ("|", ":", ",", "/"):
            if sep in ident and not ident.startswith(("arn:", "https://")):
                tokens.update(p for p in ident.split(sep) if p)
    return frozenset(tokens), region


def _state_account(attrs: dict[str, Any]) -> str:
    # Only the resource's own ARN or owner: other *_arn attributes may point into another account, and
    # account_id names the other side on member and sharing types (aws_guardduty_member,
    # aws_ami_launch_permission, aws_cloudformation_stack_set_instance).
    for key in ("arn", "id"):
        if isinstance(attrs.get(key), str) and (account := _arn_account(attrs[key])):
            return account
    owner = attrs.get("owner_id")
    return owner if isinstance(owner, str) and re.fullmatch(r"\d{12}", owner) else ""


def parse_state(doc: dict[str, Any], where: str) -> list[IacEntry]:
    """Managed resources in a Terraform state file (format version 4)."""
    out = []
    for res in doc.get("resources") or []:
        if res.get("mode") != "managed":
            continue
        tf_type = TERRAFORM_TYPE_ALIASES.get(res.get("type", ""), res.get("type", ""))
        base = ".".join(p for p in (res.get("module", ""), res.get("type", ""), res.get("name", "")) if p)
        for inst in res.get("instances") or []:
            attrs = inst.get("attributes") or {}
            tokens, region = _state_tokens(attrs)
            if tokens:
                key = inst.get("index_key")
                address = base + (f"[{json.dumps(key)}]" if key is not None else "")
                out.append(IacEntry(tf_type, "", tokens, region, where, address, str(attrs.get("id") or ""),
                                    _state_account(attrs), res.get("module", "")))
    return out


def duplicate_imports(iac: list[IacEntry]) -> list[dict[str, Any]]:
    """One cloud resource at two or more Terraform addresses: two applies would fight over it."""
    seen: dict[tuple[str, str, str, str], list[IacEntry]] = {}
    for e in iac:
        if e.tf_type and e.ident:
            seen.setdefault((e.tf_type, e.ident, e.region, e.account), []).append(e)
    return [{"type": t, "id": i, "addresses": [f"{e.address} ({e.where})" for e in entries]}
            for (t, i, _, _), entries in sorted(seen.items()) if len(entries) > 1]


def _optional_s3(s3: Any, bucket: str, key: str, problems: list[str]) -> list[tuple[str, dict[str, Any]]]:
    """The default workspace's state; missing is fine when only named workspaces were ever applied."""
    label = f"s3://{bucket}/{key}"
    try:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    except Exception as exc:
        if "NoSuchKey" in f"{type(exc).__name__} {exc}":
            return []
        raise
    doc = _state_doc(label, body, problems)
    return [(label, doc)] if doc is not None else []


def _state_doc(label: str, raw: bytes | str, problems: list[str] | None) -> dict[str, Any] | None:
    """The parsed state, or None (noted in problems) when it isn't a state file this tool reads."""
    if not (raw.strip() if isinstance(raw, str) else raw.strip()):
        return None  # an empty object, e.g. a workspace that was never applied: nothing to compare
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        reason = f"not JSON: {exc}"
    else:
        if isinstance(doc, dict) and int(doc.get("version") or 4) >= 4:
            return doc
        reason = "an old state format (version 3 or earlier); run terraform state pull with a current Terraform"
    if problems is None:
        raise ValueError(f"{label} is {reason}")
    problems.append(f"state {label} could not be read ({reason})")
    return None


def read_state_source(source: str, session: Any = None, binary: str | None = None,
                      runner=subprocess.run, problems: list[str] | None = None) -> list[tuple[str, dict[str, Any]]]:
    """(label, state doc) for a local file, s3://bucket/key, s3://bucket/prefix/, a Terraform directory, or a
    folder of .tfstate files. With `problems`, a file in a prefix or folder that can't be read is noted there
    and the others are still returned."""
    if source.startswith("s3://"):
        bucket, _, key = source[5:].partition("/")
        s3 = session.client("s3")
        keys = [key] if key.endswith(".tfstate") else [
            o["Key"] for o in _paginate(s3, "list_objects_v2", "Contents", Bucket=bucket, Prefix=key)
            if o["Key"].endswith(".tfstate")]
        docs, failed = [], []
        for k in keys:
            label = f"s3://{bucket}/{k}"
            try:
                body = s3.get_object(Bucket=bucket, Key=k)["Body"].read()
            except Exception as exc:
                if problems is None or len(keys) == 1:
                    raise
                failed.append((label, exc))
                continue
            if (doc := _state_doc(label, body, problems)) is not None:
                docs.append((label, doc))
        if failed and len(failed) == len(keys):  # nothing readable: let the caller try other credentials
            raise failed[0][1]
        problems = problems if problems is not None else []
        problems += [f"state {label} could not be read ({_short_reason(str(exc))})" for label, exc in failed]
        return docs
    if os.path.isdir(source) and not any(name.endswith(".tf") for name in os.listdir(source)):
        files = sorted(os.path.join(root, name) for root, _, names in os.walk(source)
                       for name in names if name.endswith(".tfstate"))
        if not files:
            raise RuntimeError(f"{source} has no .tf files and no .tfstate files.")
        docs = []
        for path in files:
            with open(path, "rb") as fh:
                if (doc := _state_doc(path, fh.read(), problems)) is not None:
                    docs.append((path, doc))
        return docs
    if os.path.isdir(source) and (backend := terraform_backend(source)) is not None:
        noted = problems if problems is not None else []
        if backend["type"] == "s3" and backend.get("bucket") and backend.get("key"):
            s3 = session.client("s3", region_name=backend.get("region") or None)
            keys = _s3_workspace_keys(s3, backend)
            docs, failed = [], []
            for key in keys:
                try:
                    docs += _optional_s3(s3, backend["bucket"], key, noted)
                except Exception as exc:
                    failed.append((f"s3://{backend['bucket']}/{key}", exc))
            if failed and len(failed) == len(keys):  # nothing readable: let the caller try other credentials
                raise failed[0][1]
            noted += [f"state {label} could not be read ({_short_reason(str(exc))})" for label, exc in failed]
            return docs
        if backend["type"] == "local":
            files = _local_state_files(source, backend)
            if not files:
                raise RuntimeError(f"{source} uses local state, but there is no terraform.tfstate yet.")
            docs = []
            for path in files:
                with open(path, "rb") as fh:
                    if (doc := _state_doc(path, fh.read(), noted)) is not None:
                        docs.append((path, doc))
            return docs
        if backend["type"] in ("cloud", "remote"):
            return tfc_states(backend, noted)
    if os.path.isdir(source):  # another backend type: let Terraform read it
        tf = binary or next((b for b in ("tofu", "terraform") if _which(b)), None)
        if not tf:
            raise RuntimeError("Neither `tofu` nor `terraform` was found on PATH to read state from a directory.")
        proc = runner([tf, f"-chdir={source}", "state", "pull"], capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"`{tf} state pull` in {source} failed:\n{proc.stderr or proc.stdout}")
        return [(source, json.loads(proc.stdout or "{}"))]
    with open(source, "rb") as fh:
        doc = _state_doc(source, fh.read(), None)
    return [(source, doc)] if doc is not None else []


# --- finding state from Terraform code --------------------------------------

def _hcl_block(text: str, start: int) -> str:
    """The body of the {...} block whose opening brace is at or after `start`."""
    i = text.index("{", start)
    depth = 0
    for j in range(i, len(text)):
        depth += {"{": 1, "}": -1}.get(text[j], 0)
        if depth == 0:
            return text[i + 1:j]
    return text[i + 1:]


def _hcl_attrs(body: str) -> dict[str, Any]:
    """Top-level `name = "value"` and `name = [..]` attributes (nested blocks are skipped)."""
    flat, depth, out = [], 0, {}
    for ch in body:
        depth += {"{": 1, "}": -1}.get(ch, 0)
        flat.append(ch if depth == 0 or ch == "}" else " ")
    for name, value, items in re.findall(r'(\w+)\s*=\s*(?:"([^"]*)"|\[([^\]]*)\])', "".join(flat)):
        out[name] = re.findall(r'"([^"]*)"', items) if items else value
    return out


def terraform_backend(directory: str) -> dict[str, Any] | None:
    """The backend of the Terraform code in `directory`: {"type": ..., settings...}, or None without code.
    After `terraform init` the resolved settings (with -backend-config values) are read from .terraform/."""
    tf_files = [os.path.join(directory, n) for n in sorted(os.listdir(directory)) if n.endswith(".tf")]
    if not tf_files:
        return None
    init = os.path.join(directory, ".terraform", "terraform.tfstate")
    if os.path.isfile(init):
        try:
            with open(init, encoding="utf-8") as fh:
                backend = (json.load(fh) or {}).get("backend") or {}
            if backend.get("type"):
                return {"type": backend["type"], **(backend.get("config") or {})}
        except (OSError, ValueError):
            pass
    code = ""
    for path in tf_files:
        with open(path, encoding="utf-8") as fh:
            code += re.sub(r"(?m)^\s*(#|//).*$", "", fh.read()) + "\n"
    # Only terraform {} blocks say where state lives.
    text = "\n".join(_hcl_block(code, m.start()) for m in re.finditer(r'(?m)^\s*terraform\s*\{', code))
    if (m := re.search(r'\bcloud\s*\{', text)):
        body = _hcl_block(text, m.start())
        ws = re.search(r'\bworkspaces\s*\{', body)
        return {"type": "cloud", **_hcl_attrs(body), "workspaces": _hcl_attrs(_hcl_block(body, ws.start())) if ws else {}}
    if (m := re.search(r'\bbackend\s+"([\w-]+)"\s*\{', text)):
        body = _hcl_block(text, m.start())
        ws = re.search(r'\bworkspaces\s*\{', body)
        out = {"type": m.group(1), **_hcl_attrs(body)}
        if ws:
            out["workspaces"] = _hcl_attrs(_hcl_block(body, ws.start()))
        return out
    return {"type": "local"}


def _local_state_files(directory: str, backend: dict[str, Any]) -> list[str]:
    path = backend.get("path") or "terraform.tfstate"
    base = os.path.join(directory, path)
    files = [base] if os.path.isfile(base) else []
    ws_dir = os.path.join(directory, backend.get("workspace_dir") or "terraform.tfstate.d")
    if os.path.isdir(ws_dir):
        files += sorted(os.path.join(ws_dir, ws, os.path.basename(path)) for ws in os.listdir(ws_dir)
                        if os.path.isfile(os.path.join(ws_dir, ws, os.path.basename(path))))
    return files


def _s3_workspace_keys(s3: Any, backend: dict[str, Any]) -> list[str]:
    """The default workspace's key and every other workspace's (<workspace_key_prefix>/<name>/<key>)."""
    bucket, key = backend["bucket"], backend["key"]
    prefix = (backend.get("workspace_key_prefix") or "env:").strip("/")
    keys = [key]
    for o in _paginate(s3, "list_objects_v2", "Contents", Bucket=bucket, Prefix=f"{prefix}/"):
        rest = o["Key"][len(prefix) + 1:]
        if "/" in rest and rest.split("/", 1)[1] == key:
            keys.append(o["Key"])
    return keys


def _tfc_token(host: str) -> str:
    env = os.environ.get("TF_TOKEN_" + re.sub(r"[.-]", "_", host)) or os.environ.get("TFE_TOKEN")
    if env:
        return env
    path = os.path.expanduser("~/.terraform.d/credentials.tfrc.json")
    try:
        with open(path, encoding="utf-8") as fh:
            return str(((json.load(fh) or {}).get("credentials") or {}).get(host, {}).get("token") or "")
    except (OSError, ValueError):
        return ""


def _tfc_get(url: str, token: str, opener=None) -> Any:
    import urllib.request
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}",
                                               "Content-Type": "application/vnd.api+json"})
    with (opener or urllib.request.urlopen)(req, timeout=30) as resp:
        return json.loads(resp.read())


def tfc_states(backend: dict[str, Any], problems: list[str], opener=None) -> list[tuple[str, dict[str, Any]]]:
    """Current state of each HCP Terraform / Terraform Enterprise workspace the code's cloud or remote block names."""
    host = backend.get("hostname") or "app.terraform.io"
    org = backend.get("organization") or os.environ.get("TF_CLOUD_ORGANIZATION") or ""
    ws = backend.get("workspaces") or {}
    token = _tfc_token(host)
    if not org or not token:
        raise RuntimeError(f"Reading state from {host} needs the organization and an API token "
                           f"(TF_TOKEN_{re.sub(r'[.-]', '_', host)} or `terraform login`).")
    api = f"https://{host}/api/v2"
    from urllib.parse import quote
    if ws.get("name"):
        found = [_tfc_get(f"{api}/organizations/{quote(org)}/workspaces/{quote(ws['name'])}", token, opener)["data"]]
    else:
        query = (f"search[tags]={quote(','.join(ws['tags']))}" if ws.get("tags") else
                 f"search[name]={quote(ws.get('prefix') or '')}")
        found, page = [], 1
        while page:
            doc = _tfc_get(f"{api}/organizations/{quote(org)}/workspaces?page[size]=100&page[number]={page}&{query}",
                           token, opener)
            found += [w for w in doc.get("data") or []
                      if not ws.get("prefix") or w["attributes"]["name"].startswith(ws["prefix"])]
            page = ((doc.get("meta") or {}).get("pagination") or {}).get("next-page")
    out = []
    for w in found:
        name = w["attributes"]["name"]
        try:
            version = _tfc_get(f"{api}/workspaces/{w['id']}/current-state-version", token, opener)["data"]
            url = version["attributes"]["hosted-state-download-url"]
            out.append((f"{host}/{org}/{name}", _tfc_get(url, token, opener)))
        except Exception as exc:  # e.g. a workspace with no state yet
            problems.append(f"state of workspace {org}/{name} could not be read ({_short_reason(str(exc))})")
    return out


def _which(name: str) -> bool:
    import shutil
    return shutil.which(name) is not None


def stack_entries(session: Any, region: str, log: Callable[..., None] = print,
                  problems: list[str] | None = None) -> list[IacEntry]:
    """Every resource in every CloudFormation stack in a region. What can't be read goes in problems."""
    problems = [] if problems is None else problems
    cfn = session.client("cloudformation", region_name=region)
    out = []
    statuses = ["CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "IMPORT_COMPLETE",
                "IMPORT_ROLLBACK_COMPLETE", "ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
                "CREATE_IN_PROGRESS", "UPDATE_IN_PROGRESS", "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS"]
    try:
        stacks = [s["StackName"] for s in _paginate(cfn, "list_stacks", "StackSummaries", StackStatusFilter=statuses)]
    except Exception as exc:
        problems.append(f"CloudFormation stacks in {region} could not be listed ({_short_reason(str(exc))})")
        log(f"warning: could not list CloudFormation stacks in {region}: {_short_reason(str(exc))}", file=sys.stderr)
        return out
    for name in stacks:
        try:
            rows = _paginate(cfn, "list_stack_resources", "StackResourceSummaries", StackName=name)
        except Exception as exc:
            problems.append(f"stack {name} in {region} could not be read ({_short_reason(str(exc))})")
            log(f"warning: could not read stack {name}: {_short_reason(str(exc))}", file=sys.stderr)
            continue
        for row in rows:
            phys = str(row.get("PhysicalResourceId") or "")
            if not phys:
                continue
            tokens = {phys}
            if phys.startswith("arn:"):
                tokens.add(re.split(r"[:/]", phys)[-1])
            elif phys.startswith("https://"):
                tokens.add(phys.rstrip("/").rsplit("/", 1)[-1])
            if "|" in phys:
                tokens.update(p for p in phys.split("|") if p)
            out.append(IacEntry("", row.get("ResourceType", ""), frozenset(tokens), region, f"stack {name} ({region})",
                                str(row.get("LogicalResourceId") or "")))
    return out


# --- matching --------------------------------------------------------------

@dataclass
class Match:
    unmanaged: list[LiveResource]
    managed: list[tuple[LiveResource, str]]
    entries: dict[int, IacEntry] = field(default_factory=dict)  # id(resource) -> the state entry it matched


def match(inventory: Inventory, iac: list[IacEntry], account: str = "") -> Match:
    """`account` is the scanned account: a state entry recorded for another account never matches."""
    by_tf: dict[str, list[IacEntry]] = {}
    by_cc: dict[str, list[IacEntry]] = {}
    for e in iac:
        if e.tf_type:
            by_tf.setdefault(e.tf_type, []).append(e)
        if e.cc_type:
            by_cc.setdefault(e.cc_type, []).append(e)
    unmanaged, managed, entries = [], [], {}
    for res in inventory.resources:
        tf = TERRAFORM_TYPE_ALIASES.get(res.tf_type, res.tf_type)
        candidates = by_tf.get(tf, []) + by_cc.get(res.cc_type, [])
        hit = _find(res, candidates, account)
        if hit:
            managed.append((res, hit.where))
            entries[id(res)] = hit
        else:
            unmanaged.append(res)
    return Match(unmanaged, managed, entries)


def _other_account(entry: IacEntry, res: LiveResource, account: str) -> str:
    """The account a state entry was recorded for, when that is not the live resource's account."""
    live = _arn_account(res.arn) or account
    return entry.account if entry.account and live and entry.account != live else ""


def _find(res: LiveResource, candidates: list[IacEntry], account: str = "") -> IacEntry | None:
    keys = res.keys()
    for entry in candidates:
        if entry.region and res.region and entry.region != res.region:
            continue
        if _other_account(entry, res, account):
            continue
        if any(key <= entry.tokens for key in keys):
            return entry
    return None


def explain(inventory: Inventory, iac: list[IacEntry], needle: str, account: str = "") -> list[str]:
    """Why each listed resource whose id, name or ARN contains `needle` did or didn't match IaC."""
    lines: list[str] = []
    found = [(r, "") for r in inventory.resources] + list(inventory.owned)
    hits = [(r, why) for r, why in found if any(needle in v for v in (r.identifier, r.name, r.arn) if v)]
    if not hits:
        lines.append(f"{needle}: not among the {len(found)} listed resources. Check --region/--type; "
                     f"{len(inventory.not_listed)} type/region pairs could not be listed.")
        return lines
    for res, why in hits:
        label = f"{res.tf_type} {res.name or res.identifier} ({res.region or 'global'})"
        if why:
            lines.append(f"{label}: skipped as AWS-owned ({why}); --strict reports it.")
            continue
        tf = TERRAFORM_TYPE_ALIASES.get(res.tf_type, res.tf_type)
        same_type = [e for e in iac if e.tf_type == tf or (e.cc_type and e.cc_type == res.cc_type)]
        hit = _find(res, same_type, account)
        keys = sorted("+".join(sorted(k)) for k in res.keys())
        if hit:
            where = f"{hit.address} in {hit.where}" if hit.address else hit.where
            lines.append(f"{label}: in IaC, matched {where}.")
            continue
        lines.append(f"{label}: NOT in IaC. Looked for any of: {', '.join(keys)}.")
        if not same_type:
            lines.append(f"  No {tf} or {res.cc_type} entries in the state files or stacks compared.")
            continue
        wanted = set().union(*res.keys()) if res.keys() else set()
        near = [e for e in same_type if e.tokens & wanted]
        for e in near[:5]:
            other = _other_account(e, res, account)
            why_not = (f"recorded for region {e.region}" if e.region and res.region and e.region != res.region
                       else f"recorded for account {other}" if other
                       else "shares only part of a composite id")
            lines.append(f"  Close: {e.address or e.where} in {e.where} ({why_not}).")
        if not near:
            lines.append(f"  {len(same_type)} {tf} entries compared; none has these values.")
    return lines


def _regions_client(session: Any) -> Any:
    # Asked from us-east-1 with a short timeout: a call to a region the account hasn't enabled hangs for minutes.
    try:
        from botocore.config import Config
        config = Config(connect_timeout=10, read_timeout=20, retries={"max_attempts": 2})
    except ImportError:  # fake sessions in tests
        config = None
    return session.client("ec2", region_name="us-east-1", config=config)


def enabled_regions(session: Any) -> list[str]:
    rows = _regions_client(session).describe_regions(
        Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}])
    return sorted(r["RegionName"] for r in rows.get("Regions") or [])


def check_regions(session: Any, regions: list[str], log: Callable[..., None] = print) -> None:
    """Stop before scanning a region the account hasn't enabled (or that doesn't exist)."""
    try:
        rows = _regions_client(session).describe_regions(AllRegions=True).get("Regions") or []
    except Exception as exc:  # can't tell; scan as asked
        log(f"note: could not check which regions are enabled ({_short_reason(str(exc))})", file=sys.stderr)
        return
    status = {r["RegionName"]: r.get("OptInStatus", "") for r in rows}
    off = [r for r in regions if status.get(r) == "not-opted-in"]
    unknown = [r for r in regions if r not in status]
    if off:
        raise RuntimeError(f"{', '.join(off)} {'is' if len(off) == 1 else 'are'} not enabled for this account, so "
                           "AWS won't answer there. Enable it under Account > AWS Regions, or leave it out.")
    if unknown:
        raise RuntimeError(f"Unknown region {', '.join(unknown)}. Check the spelling (e.g. us-east-1).")

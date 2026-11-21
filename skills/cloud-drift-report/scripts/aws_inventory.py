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
                "DBInstanceIdentifier", "LoadBalancerName"):
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
        out.append({"Identifier": v["VolumeId"], "Properties": {"LaunchedWithInstance": with_instance, "Tags": v.get("Tags") or []}})
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
    return [{"Identifier": x["LoadBalancerName"], "Properties": {}}
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


def _lb_listeners(s, r):
    elb = s.client("elbv2", region_name=r)
    out = []
    for lb in _paginate(elb, "describe_load_balancers", "LoadBalancers"):
        for ln in _paginate(elb, "describe_listeners", "Listeners", LoadBalancerArn=lb["LoadBalancerArn"]):
            out.append({"Identifier": ln["ListenerArn"], "Properties": {"Name": f"{lb.get('LoadBalancerName')}:{ln.get('Port')}"}})
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
    "AWS::EC2::Instance": _instances,
    "AWS::EC2::Volume": _volumes,
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


def _short_reason(text: str) -> str:
    for marker, label in (("Throttling", "throttled by AWS; rerun with fewer --workers"),
                          ("Rate exceeded", "throttled by AWS; rerun with fewer --workers"),
                          ("ResourceModel", "needs a parent resource to list; not checked"),
                          ("Handler returned", "the service returned an error"),
                          ("AccessDenied", "access denied"), ("not authorized", "access denied"),
                          ("UnauthorizedOperation", "access denied"), ("TypeNotFound", "type not available"),
                          ("UnsupportedAction", "listing not supported"), ("is not supported", "listing not supported"),
                          ("OptInRequired", "region or service not enabled"), ("Could not connect", "service not in region"),
                          ("SubscriptionRequired", "service not enabled")):
        if marker in text:
            return label
    return text.splitlines()[0][:160]


# --- what IaC knows about --------------------------------------------------

_STATE_KEYS = ("id", "arn", "name", "identifier", "bucket", "url", "key_id", "function_name")


@dataclass
class IacEntry:
    tf_type: str          # Terraform type (normalized), or "" for a CloudFormation resource
    cc_type: str          # CloudFormation type, or "" for Terraform
    tokens: frozenset[str]
    region: str
    where: str            # state file or stack


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


def parse_state(doc: dict[str, Any], where: str) -> list[IacEntry]:
    """Managed resources in a Terraform state file (format version 4)."""
    out = []
    for res in doc.get("resources") or []:
        if res.get("mode") != "managed":
            continue
        tf_type = TERRAFORM_TYPE_ALIASES.get(res.get("type", ""), res.get("type", ""))
        for inst in res.get("instances") or []:
            tokens, region = _state_tokens(inst.get("attributes") or {})
            if tokens:
                out.append(IacEntry(tf_type, "", tokens, region, where))
    return out


def read_state_source(source: str, session: Any = None, binary: str | None = None,
                      runner=subprocess.run) -> list[tuple[str, dict[str, Any]]]:
    """(label, state doc) for a local file, s3://bucket/key, s3://bucket/prefix/, or a Terraform directory."""
    if source.startswith("s3://"):
        bucket, _, key = source[5:].partition("/")
        s3 = session.client("s3")
        keys = [key] if key.endswith(".tfstate") else [
            o["Key"] for o in _paginate(s3, "list_objects_v2", "Contents", Bucket=bucket, Prefix=key)
            if o["Key"].endswith(".tfstate")]
        docs = []
        for k in keys:
            body = s3.get_object(Bucket=bucket, Key=k)["Body"].read()
            docs.append((f"s3://{bucket}/{k}", json.loads(body)))
        return docs
    if os.path.isdir(source):
        tf = binary or next((b for b in ("tofu", "terraform") if _which(b)), None)
        if not tf:
            raise RuntimeError("Neither `tofu` nor `terraform` was found on PATH to read state from a directory.")
        proc = runner([tf, f"-chdir={source}", "state", "pull"], capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"`{tf} state pull` in {source} failed:\n{proc.stderr or proc.stdout}")
        return [(source, json.loads(proc.stdout or "{}"))]
    with open(source, encoding="utf-8") as fh:
        return [(source, json.load(fh))]


def _which(name: str) -> bool:
    import shutil
    return shutil.which(name) is not None


def stack_entries(session: Any, region: str, log: Callable[..., None] = print) -> list[IacEntry]:
    """Every resource in every CloudFormation stack in a region."""
    cfn = session.client("cloudformation", region_name=region)
    out = []
    statuses = ["CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "IMPORT_COMPLETE",
                "IMPORT_ROLLBACK_COMPLETE", "ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
                "CREATE_IN_PROGRESS", "UPDATE_IN_PROGRESS", "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS"]
    try:
        stacks = [s["StackName"] for s in _paginate(cfn, "list_stacks", "StackSummaries", StackStatusFilter=statuses)]
    except Exception as exc:
        log(f"warning: could not list CloudFormation stacks in {region}: {_short_reason(str(exc))}", file=sys.stderr)
        return out
    for name in stacks:
        try:
            rows = _paginate(cfn, "list_stack_resources", "StackResourceSummaries", StackName=name)
        except Exception as exc:
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
            out.append(IacEntry("", row.get("ResourceType", ""), frozenset(tokens), region, f"stack {name} ({region})"))
    return out


# --- matching --------------------------------------------------------------

@dataclass
class Match:
    unmanaged: list[LiveResource]
    managed: list[tuple[LiveResource, str]]


def match(inventory: Inventory, iac: list[IacEntry]) -> Match:
    by_tf: dict[str, list[IacEntry]] = {}
    by_cc: dict[str, list[IacEntry]] = {}
    for e in iac:
        if e.tf_type:
            by_tf.setdefault(e.tf_type, []).append(e)
        if e.cc_type:
            by_cc.setdefault(e.cc_type, []).append(e)
    unmanaged, managed = [], []
    for res in inventory.resources:
        tf = TERRAFORM_TYPE_ALIASES.get(res.tf_type, res.tf_type)
        candidates = by_tf.get(tf, []) + by_cc.get(res.cc_type, [])
        hit = _find(res, candidates)
        if hit:
            managed.append((res, hit.where))
        else:
            unmanaged.append(res)
    return Match(unmanaged, managed)


def _find(res: LiveResource, candidates: list[IacEntry]) -> IacEntry | None:
    keys = res.keys()
    for entry in candidates:
        if entry.region and res.region and entry.region != res.region:
            continue
        if any(key <= entry.tokens for key in keys):
            return entry
    return None


def enabled_regions(session: Any) -> list[str]:
    ec2 = session.client("ec2", region_name=session.region_name or "us-east-1")
    rows = ec2.describe_regions(Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}])
    return sorted(r["RegionName"] for r in rows.get("Regions") or [])

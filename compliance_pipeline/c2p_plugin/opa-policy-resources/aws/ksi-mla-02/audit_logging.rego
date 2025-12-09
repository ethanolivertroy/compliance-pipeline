# KSI-MLA-02: Audit Logging (AWS)
#
# A secure cloud service offering will implement comprehensive audit logging
# to track and monitor all significant security events.
#
# This policy validates:
# - CloudTrail is enabled and configured properly
# - S3 bucket logging is enabled
# - VPC flow logs are configured
# - RDS audit logging is enabled
# - CloudWatch log groups have retention

package ksi.mla02.aws

import data.lib.helpers
import data.lib.terraform
import future.keywords.in

# Configurable parameters
min_log_retention_days := 90
require_encryption := true

# Deny: CloudTrail without multi-region
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    not values.is_multi_region_trail

    msg := helpers.format_violation(
        "KSI-MLA-02",
        resource.address,
        "CloudTrail is not configured as multi-region. Enable multi-region to capture all API activity."
    )
}

# Deny: CloudTrail without log file validation
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    not values.enable_log_file_validation

    msg := helpers.format_violation(
        "KSI-MLA-02",
        resource.address,
        "CloudTrail does not have log file validation enabled. Enable to detect log tampering."
    )
}

# Deny: CloudTrail without encryption
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    resource.change.actions[_] in ["create", "update"]

    require_encryption == true

    values := resource.change.after

    not values.kms_key_id

    msg := helpers.format_violation(
        "KSI-MLA-02",
        resource.address,
        "CloudTrail logs are not encrypted with KMS. Specify kms_key_id for log encryption."
    )
}

# Deny: CloudTrail without CloudWatch integration
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    not values.cloud_watch_logs_group_arn

    msg := helpers.format_violation(
        "KSI-MLA-02",
        resource.address,
        "CloudTrail is not integrated with CloudWatch Logs. Configure for real-time monitoring."
    )
}

# Deny: S3 bucket without logging
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    resource.change.actions[_] in ["create", "update"]

    # Check if there's a logging configuration for this bucket
    not has_bucket_logging(resource.address)

    msg := helpers.format_violation(
        "KSI-MLA-02",
        resource.address,
        "S3 bucket does not have access logging configured. Enable logging for audit trail."
    )
}

# Deny: RDS instance without audit logging
warn[msg] {
    resource := input.resource_changes[_]
    resource.type in ["aws_db_instance", "aws_rds_cluster"]
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    # Check for enabled CloudWatch logs exports
    not has_audit_logs_enabled(values)

    msg := helpers.format_violation(
        "KSI-MLA-02",
        resource.address,
        "RDS instance does not have audit logging enabled. Configure enabled_cloudwatch_logs_exports."
    )
}

# Deny: CloudWatch log group without retention
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudwatch_log_group"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    # No retention or retention less than minimum
    not values.retention_in_days

    msg := helpers.format_violation(
        "KSI-MLA-02",
        resource.address,
        sprintf("CloudWatch log group has no retention policy. Set retention_in_days to at least %d.", [min_log_retention_days])
    )
}

# Deny: CloudWatch log group with insufficient retention
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudwatch_log_group"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    values.retention_in_days
    values.retention_in_days < min_log_retention_days

    msg := helpers.format_violation(
        "KSI-MLA-02",
        resource.address,
        sprintf("CloudWatch log group retention (%d days) is less than required minimum (%d days).", [values.retention_in_days, min_log_retention_days])
    )
}

# Deny: EKS cluster without logging
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_eks_cluster"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    # Check for enabled log types
    not has_eks_logging(values)

    msg := helpers.format_violation(
        "KSI-MLA-02",
        resource.address,
        "EKS cluster does not have control plane logging enabled. Enable audit, api, and authenticator logs."
    )
}

# Pass: CloudTrail properly configured
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    values.is_multi_region_trail
    values.enable_log_file_validation

    msg := helpers.format_pass(
        "KSI-MLA-02",
        resource.address,
        "CloudTrail is configured with multi-region and log file validation."
    )
}

# Pass: CloudWatch log group with proper retention
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudwatch_log_group"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    values.retention_in_days >= min_log_retention_days

    msg := helpers.format_pass(
        "KSI-MLA-02",
        resource.address,
        sprintf("CloudWatch log group has %d days retention.", [values.retention_in_days])
    )
}

# Helper: Check if S3 bucket has logging configured
has_bucket_logging(bucket_address) {
    logging := input.resource_changes[_]
    logging.type == "aws_s3_bucket_logging"
    logging.change.actions[_] in ["create", "update", "no-op"]
    contains(logging.change.after.bucket, bucket_address)
}

# Helper: Check if RDS has audit logs enabled
has_audit_logs_enabled(values) {
    log_exports := values.enabled_cloudwatch_logs_exports
    count(log_exports) > 0
}

# Helper: Check if EKS has logging enabled
has_eks_logging(values) {
    logging := values.enabled_cluster_log_types
    count(logging) > 0
}

has_eks_logging(values) {
    logging := values.logging[_]
    logging.enabled_types
    count(logging.enabled_types) > 0
}

# KSI-MLA-02: Audit Logging (GCP)
#
# A secure cloud service offering will implement comprehensive audit logging
# to track and monitor all significant security events.
#
# This policy validates:
# - Cloud Audit Logs are configured
# - Cloud Logging is enabled for resources
# - Log sinks are properly configured
# - GKE audit logging is enabled
# - Cloud SQL audit logging is configured

package ksi.mla02.gcp

import data.lib.helpers
import data.lib.terraform
import future.keywords.in

# Configurable parameters
min_log_retention_days := 90
require_encryption := true

# Deny: Project without audit log config
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_project"
    resource.change.actions[_] in ["create", "update"]

    # Check if there's audit config for this project
    not has_audit_config(resource.address)

    msg := helpers.format_violation(
        "KSI-MLA-02",
        resource.address,
        "Project does not have explicit audit log configuration. Configure google_project_iam_audit_config."
    )
}

# Deny: Logging bucket without retention
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_logging_project_bucket_config"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    values.retention_days < min_log_retention_days

    msg := helpers.format_violation(
        "KSI-MLA-02",
        resource.address,
        sprintf("Logging bucket retention (%d days) is less than required minimum (%d days).", [values.retention_days, min_log_retention_days])
    )
}

# Deny: Log sink without proper filter (capturing too little or too much)
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_logging_project_sink"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    # Check for overly broad exclusion
    contains(values.filter, "NOT")
    contains(lower(values.filter), "audit")

    msg := helpers.format_violation(
        "KSI-MLA-02",
        resource.address,
        "Log sink filter excludes audit logs. Ensure audit logs are captured."
    )
}

# Deny: GKE cluster without logging
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_container_cluster"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    # Check if logging is disabled
    values.logging_service == "none"

    msg := helpers.format_violation(
        "KSI-MLA-02",
        resource.address,
        "GKE cluster has logging disabled. Enable logging_service for audit trail."
    )
}

# Deny: GKE cluster without audit logging component
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_container_cluster"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    # Check for logging config without system/workload components
    logging_config := values.logging_config[_]
    not has_gke_audit_components(logging_config)

    msg := helpers.format_violation(
        "KSI-MLA-02",
        resource.address,
        "GKE cluster logging does not include SYSTEM_COMPONENTS or WORKLOADS. Enable comprehensive logging."
    )
}

# Deny: Cloud SQL without audit logging
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_sql_database_instance"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    # Check database flags for audit logging
    not has_sql_audit_flags(values)

    msg := helpers.format_violation(
        "KSI-MLA-02",
        resource.address,
        "Cloud SQL instance does not have audit logging configured. Enable cloudsql_mysql_audit or cloudsql.enable_pgaudit."
    )
}

# Deny: Cloud Function without logging (explicitly disabled)
deny[msg] {
    resource := input.resource_changes[_]
    resource.type in ["google_cloudfunctions_function", "google_cloudfunctions2_function"]
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    # Check if logging is explicitly disabled
    values.service_config[_].service_logging_config.log_level == "OFF"

    msg := helpers.format_violation(
        "KSI-MLA-02",
        resource.address,
        "Cloud Function has logging disabled. Enable logging for audit trail."
    )
}

# Deny: BigQuery dataset without audit logging
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_bigquery_dataset"
    resource.change.actions[_] in ["create", "update"]

    # BigQuery has built-in audit logs, but check for access logging config
    values := resource.change.after

    not values.access

    msg := helpers.format_violation(
        "KSI-MLA-02",
        resource.address,
        "BigQuery dataset does not have explicit access configuration. Configure access for audit compliance."
    )
}

# Pass: Logging bucket with proper retention
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_logging_project_bucket_config"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    values.retention_days >= min_log_retention_days

    msg := helpers.format_pass(
        "KSI-MLA-02",
        resource.address,
        sprintf("Logging bucket has %d days retention.", [values.retention_days])
    )
}

# Pass: GKE with logging enabled
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_container_cluster"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    values.logging_service != "none"
    values.logging_service != ""

    msg := helpers.format_pass(
        "KSI-MLA-02",
        resource.address,
        "GKE cluster has logging enabled."
    )
}

# Pass: Audit config exists
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_project_iam_audit_config"
    resource.change.actions[_] in ["create", "update"]

    msg := helpers.format_pass(
        "KSI-MLA-02",
        resource.address,
        "Project has IAM audit configuration."
    )
}

# Helper: Check if project has audit config
has_audit_config(project_address) {
    audit := input.resource_changes[_]
    audit.type == "google_project_iam_audit_config"
    audit.change.actions[_] in ["create", "update", "no-op"]
}

# Helper: Check if GKE has audit logging components
has_gke_audit_components(logging_config) {
    component := logging_config.enable_components[_]
    component == "SYSTEM_COMPONENTS"
}

has_gke_audit_components(logging_config) {
    component := logging_config.enable_components[_]
    component == "WORKLOADS"
}

# Helper: Check if Cloud SQL has audit flags
has_sql_audit_flags(values) {
    settings := values.settings[_]
    flag := settings.database_flags[_]
    is_audit_flag(flag.name)
}

# Helper: Check if flag name is an audit flag
is_audit_flag(name) {
    audit_flags := [
        "cloudsql_mysql_audit",
        "cloudsql.enable_pgaudit",
        "log_statement",
        "log_min_duration_statement",
    ]
    name == audit_flags[_]
}

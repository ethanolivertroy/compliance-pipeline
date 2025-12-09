# KSI-MLA-02: Audit Logging (Azure)
#
# A secure cloud service offering will implement comprehensive audit logging
# to track and monitor all significant security events.
#
# This policy validates:
# - Activity Log is configured with proper retention
# - Diagnostic settings are enabled for key resources
# - Storage account logging is enabled
# - Key Vault diagnostic logging is configured
# - AKS diagnostic logging is enabled

package ksi.mla02.azure

import data.lib.helpers
import data.lib.terraform
import future.keywords.in

# Configurable parameters
min_log_retention_days := 90
require_encryption := true

# Deny: Log Analytics workspace without sufficient retention
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_log_analytics_workspace"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    values.retention_in_days < min_log_retention_days

    msg := helpers.format_violation(
        "KSI-MLA-02",
        resource.address,
        sprintf("Log Analytics workspace retention (%d days) is less than required minimum (%d days).", [values.retention_in_days, min_log_retention_days])
    )
}

# Deny: Key Vault without diagnostic settings
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_key_vault"
    resource.change.actions[_] in ["create", "update"]

    # Check if there's diagnostic settings for this Key Vault
    not has_diagnostic_settings(resource.address)

    msg := helpers.format_violation(
        "KSI-MLA-02",
        resource.address,
        "Key Vault does not have diagnostic settings configured. Enable AuditEvent logging."
    )
}

# Deny: Storage account without diagnostic settings
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    resource.change.actions[_] in ["create", "update"]

    # Check if there's diagnostic settings for storage
    not has_storage_diagnostics(resource.address)

    msg := helpers.format_violation(
        "KSI-MLA-02",
        resource.address,
        "Storage account does not have diagnostic settings configured. Enable blob/queue/table/file logging."
    )
}

# Deny: SQL Server without auditing
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_mssql_server"
    resource.change.actions[_] in ["create", "update"]

    # Check if there's audit policy for this server
    not has_sql_auditing(resource.address)

    msg := helpers.format_violation(
        "KSI-MLA-02",
        resource.address,
        "SQL Server does not have auditing configured. Enable SQL audit policy."
    )
}

# Deny: AKS cluster without diagnostic settings
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_kubernetes_cluster"
    resource.change.actions[_] in ["create", "update"]

    # Check if there's diagnostic settings for AKS
    not has_diagnostic_settings(resource.address)

    msg := helpers.format_violation(
        "KSI-MLA-02",
        resource.address,
        "AKS cluster does not have diagnostic settings configured. Enable kube-audit and kube-audit-admin logs."
    )
}

# Deny: Monitor diagnostic setting without required logs
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_monitor_diagnostic_setting"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    # Check if audit logs are enabled
    not has_audit_logs(values)

    msg := helpers.format_violation(
        "KSI-MLA-02",
        resource.address,
        "Diagnostic setting does not have audit logs enabled. Enable AuditEvent or equivalent logs."
    )
}

# Deny: Activity log alert without proper configuration
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_monitor_activity_log_alert"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    not values.enabled

    msg := helpers.format_violation(
        "KSI-MLA-02",
        resource.address,
        "Activity log alert is not enabled. Enable to receive security notifications."
    )
}

# Deny: App Service without diagnostic logs
warn[msg] {
    resource := input.resource_changes[_]
    resource.type in ["azurerm_linux_web_app", "azurerm_windows_web_app"]
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    not has_app_service_logging(values)

    msg := helpers.format_violation(
        "KSI-MLA-02",
        resource.address,
        "App Service does not have diagnostic logging configured. Enable HTTP and application logs."
    )
}

# Pass: Log Analytics with proper retention
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_log_analytics_workspace"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    values.retention_in_days >= min_log_retention_days

    msg := helpers.format_pass(
        "KSI-MLA-02",
        resource.address,
        sprintf("Log Analytics workspace has %d days retention.", [values.retention_in_days])
    )
}

# Pass: Diagnostic setting with audit logs
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_monitor_diagnostic_setting"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    has_audit_logs(values)

    msg := helpers.format_pass(
        "KSI-MLA-02",
        resource.address,
        "Diagnostic setting has audit logging enabled."
    )
}

# Helper: Check if resource has diagnostic settings
has_diagnostic_settings(resource_address) {
    diag := input.resource_changes[_]
    diag.type == "azurerm_monitor_diagnostic_setting"
    diag.change.actions[_] in ["create", "update", "no-op"]
    contains(diag.change.after.target_resource_id, resource_address)
}

# Helper: Check if storage has diagnostic settings
has_storage_diagnostics(storage_address) {
    diag := input.resource_changes[_]
    diag.type in ["azurerm_monitor_diagnostic_setting", "azurerm_storage_account_blob_container_sas"]
    diag.change.actions[_] in ["create", "update", "no-op"]
}

# Helper: Check if SQL Server has auditing
has_sql_auditing(server_address) {
    audit := input.resource_changes[_]
    audit.type in ["azurerm_mssql_server_extended_auditing_policy", "azurerm_mssql_database_extended_auditing_policy"]
    audit.change.actions[_] in ["create", "update", "no-op"]
}

# Helper: Check if diagnostic setting has audit logs
has_audit_logs(values) {
    log := values.enabled_log[_]
    log.category == "AuditEvent"
    log.enabled == true
}

has_audit_logs(values) {
    log := values.log[_]
    log.category == "AuditEvent"
    log.enabled == true
}

has_audit_logs(values) {
    log := values.enabled_log[_]
    contains(log.category, "audit")
    log.enabled == true
}

# Helper: Check if App Service has logging
has_app_service_logging(values) {
    logs := values.logs[_]
    logs.http_logs
}

has_app_service_logging(values) {
    logs := values.logs[_]
    logs.application_logs
}

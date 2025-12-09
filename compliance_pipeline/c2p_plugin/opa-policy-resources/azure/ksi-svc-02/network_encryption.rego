# KSI-SVC-02: Network Encryption (Azure)
#
# A secure cloud service offering will protect data in transit using encryption.
# All network communications should use TLS 1.2 or higher.
#
# This policy validates:
# - Application Gateway uses HTTPS
# - Azure Front Door enforces HTTPS
# - Storage accounts require secure transfer
# - SQL servers enforce TLS 1.2
# - App Services use HTTPS only

package ksi.svc02.azure

import data.lib.helpers
import data.lib.terraform
import future.keywords.in

# Configurable parameters (injected via Jinja2)
minimum_tls_version := "{{ minimum_tls_version | default('TLS1_2') }}"

# Deny: Application Gateway HTTP listener without redirect
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_application_gateway"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    listener := values.http_listener[_]

    listener.protocol == "Http"

    # Check if there's a redirect for this listener
    not has_https_redirect(values, listener.name)

    msg := helpers.format_violation(
        "KSI-SVC-02",
        resource.address,
        sprintf("Application Gateway listener '%s' uses HTTP without redirect to HTTPS.", [listener.name])
    )
}

# Deny: Application Gateway with weak SSL policy
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_application_gateway"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    ssl_policy := values.ssl_policy[_]

    is_weak_ssl_policy(ssl_policy.policy_type, ssl_policy.policy_name, ssl_policy.min_protocol_version)

    msg := helpers.format_violation(
        "KSI-SVC-02",
        resource.address,
        "Application Gateway uses weak SSL policy. Use TLS 1.2+ with strong cipher suites."
    )
}

# Deny: Storage account without secure transfer
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    not values.enable_https_traffic_only
    values.https_traffic_only_enabled != true

    msg := helpers.format_violation(
        "KSI-SVC-02",
        resource.address,
        "Storage account does not enforce HTTPS. Set enable_https_traffic_only to true."
    )
}

# Deny: Storage account with weak TLS
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    is_weak_tls_version(values.min_tls_version)

    msg := helpers.format_violation(
        "KSI-SVC-02",
        resource.address,
        sprintf("Storage account uses weak TLS version '%s'. Use TLS1_2 or higher.", [values.min_tls_version])
    )
}

# Deny: SQL Server with weak TLS
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_mssql_server"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    is_weak_tls_version(values.minimum_tls_version)

    msg := helpers.format_violation(
        "KSI-SVC-02",
        resource.address,
        sprintf("SQL Server uses weak TLS version '%s'. Use 1.2 or higher.", [values.minimum_tls_version])
    )
}

# Deny: App Service without HTTPS only
deny[msg] {
    resource := input.resource_changes[_]
    resource.type in ["azurerm_app_service", "azurerm_linux_web_app", "azurerm_windows_web_app"]
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    not values.https_only

    msg := helpers.format_violation(
        "KSI-SVC-02",
        resource.address,
        "App Service does not enforce HTTPS only. Set https_only to true."
    )
}

# Deny: App Service with weak TLS
deny[msg] {
    resource := input.resource_changes[_]
    resource.type in ["azurerm_app_service", "azurerm_linux_web_app", "azurerm_windows_web_app"]
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    site_config := values.site_config[_]

    is_weak_tls_version(site_config.minimum_tls_version)

    msg := helpers.format_violation(
        "KSI-SVC-02",
        resource.address,
        sprintf("App Service uses weak TLS version '%s'. Use 1.2 or higher.", [site_config.minimum_tls_version])
    )
}

# Deny: Azure Front Door without HTTPS redirect
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_frontdoor"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    routing_rule := values.routing_rule[_]

    not routing_rule.redirect_configuration
    routing_rule.accepted_protocols[_] == "Http"

    msg := helpers.format_violation(
        "KSI-SVC-02",
        resource.address,
        sprintf("Front Door routing rule '%s' accepts HTTP without redirect. Enforce HTTPS.", [routing_rule.name])
    )
}

# Deny: Redis Cache without TLS
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_redis_cache"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    values.enable_non_ssl_port == true

    msg := helpers.format_violation(
        "KSI-SVC-02",
        resource.address,
        "Redis Cache has non-SSL port enabled. Disable non-SSL port for secure connections."
    )
}

# Pass: Storage account with HTTPS enforced
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    values.enable_https_traffic_only == true
    not is_weak_tls_version(values.min_tls_version)

    msg := helpers.format_pass(
        "KSI-SVC-02",
        resource.address,
        "Storage account enforces HTTPS with TLS 1.2+."
    )
}

# Helper: Check if App Gateway has HTTPS redirect for listener
has_https_redirect(gateway, listener_name) {
    rule := gateway.request_routing_rule[_]
    rule.http_listener_name == listener_name
    rule.redirect_configuration_name
}

# Helper: Check if SSL policy is weak
is_weak_ssl_policy(policy_type, policy_name, min_version) {
    policy_type == "Predefined"
    weak_policies := [
        "AppGwSslPolicy20150501",
        "AppGwSslPolicy20170401",
    ]
    policy_name == weak_policies[_]
}

is_weak_ssl_policy(policy_type, policy_name, min_version) {
    policy_type == "Custom"
    is_weak_tls_version(min_version)
}

# Helper: Check if TLS version is weak
is_weak_tls_version(version) {
    weak_versions := [
        "TLS1_0",
        "TLS1_1",
        "1.0",
        "1.1",
        "TLSv1",
        "TLSv1.1",
    ]
    version == weak_versions[_]
}

is_weak_tls_version(version) {
    not version
}

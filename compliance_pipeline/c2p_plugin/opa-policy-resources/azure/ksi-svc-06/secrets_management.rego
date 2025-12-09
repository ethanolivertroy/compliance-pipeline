# KSI-SVC-06: Secrets Management (Azure)
#
# A secure cloud service offering will manage and protect secrets using
# a dedicated secrets management solution.
#
# This policy validates:
# - Key Vault is used for secrets
# - Key Vault has soft delete and purge protection
# - Secrets have expiration dates
# - No hardcoded secrets in configurations

package ksi.svc06.azure

import data.lib.helpers
import data.lib.terraform
import future.keywords.in

# Configurable parameters (injected via Jinja2)
require_rotation := true
max_rotation_days := 90

# Deny: Key Vault without soft delete
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_key_vault"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    values.soft_delete_retention_days < 7

    msg := helpers.format_violation(
        "KSI-SVC-06",
        resource.address,
        "Key Vault soft delete retention is less than 7 days. Increase retention for recovery purposes."
    )
}

# Deny: Key Vault without purge protection
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_key_vault"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    not values.purge_protection_enabled

    msg := helpers.format_violation(
        "KSI-SVC-06",
        resource.address,
        "Key Vault does not have purge protection enabled. Enable to prevent permanent deletion."
    )
}

# Deny: Key Vault key without expiration
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_key_vault_key"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    not values.expiration_date

    msg := helpers.format_violation(
        "KSI-SVC-06",
        resource.address,
        "Key Vault key does not have an expiration date. Set expiration for key rotation compliance."
    )
}

# Deny: Key Vault secret without expiration
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_key_vault_secret"
    resource.change.actions[_] in ["create", "update"]

    require_rotation == true

    values := resource.change.after

    not values.expiration_date

    msg := helpers.format_violation(
        "KSI-SVC-06",
        resource.address,
        "Key Vault secret does not have an expiration date. Set expiration for secret rotation compliance."
    )
}

# Warn: App Service with connection string in config (should use Key Vault)
warn[msg] {
    resource := input.resource_changes[_]
    resource.type in ["azurerm_app_service", "azurerm_linux_web_app", "azurerm_windows_web_app"]
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    conn_string := values.connection_string[_]

    # Connection string defined directly
    conn_string.value

    msg := helpers.format_violation(
        "KSI-SVC-06",
        resource.address,
        sprintf("App Service has connection string '%s' defined directly. Use Key Vault references instead.", [conn_string.name])
    )
}

# Warn: Function App with secrets in app settings
warn[msg] {
    resource := input.resource_changes[_]
    resource.type in ["azurerm_function_app", "azurerm_linux_function_app", "azurerm_windows_function_app"]
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    app_settings := values.app_settings

    some key
    looks_like_secret_key(key)
    app_settings[key]

    # Not a Key Vault reference
    not startswith(app_settings[key], "@Microsoft.KeyVault")

    msg := helpers.format_violation(
        "KSI-SVC-06",
        resource.address,
        sprintf("Function App has app setting '%s' that may contain secrets. Use Key Vault references (@Microsoft.KeyVault).", [key])
    )
}

# Deny: Storage account key used directly (should use SAS or Azure AD)
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    # Check if shared key access is enabled (default)
    values.shared_access_key_enabled != false

    msg := helpers.format_violation(
        "KSI-SVC-06",
        resource.address,
        "Storage account has shared key access enabled. Consider disabling and using Azure AD authentication."
    )
}

# Deny: SQL Server with admin password in Terraform
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_mssql_server"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    # Has administrator login password defined
    values.administrator_login_password

    msg := helpers.format_violation(
        "KSI-SVC-06",
        resource.address,
        "SQL Server admin password defined in Terraform. Use Azure AD authentication or Key Vault for password management."
    )
}

# Pass: Key Vault with proper protection
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_key_vault"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    values.purge_protection_enabled == true
    values.soft_delete_retention_days >= 7

    msg := helpers.format_pass(
        "KSI-SVC-06",
        resource.address,
        "Key Vault has soft delete and purge protection enabled."
    )
}

# Pass: Using Key Vault reference in App Service
pass[msg] {
    resource := input.resource_changes[_]
    resource.type in ["azurerm_app_service", "azurerm_linux_web_app", "azurerm_windows_web_app"]
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    app_settings := values.app_settings

    some key
    startswith(app_settings[key], "@Microsoft.KeyVault")

    msg := helpers.format_pass(
        "KSI-SVC-06",
        resource.address,
        sprintf("App Service uses Key Vault reference for setting '%s'.", [key])
    )
}

# Helper: Check if key name looks like a secret
looks_like_secret_key(key) {
    secret_patterns := [
        "PASSWORD",
        "SECRET",
        "API_KEY",
        "APIKEY",
        "TOKEN",
        "CREDENTIAL",
        "PRIVATE_KEY",
        "CONNECTION_STRING",
        "CONN_STR",
    ]
    pattern := secret_patterns[_]
    contains(upper(key), pattern)
}

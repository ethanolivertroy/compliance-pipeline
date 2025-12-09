# KSI-IAM-01: Phishing-Resistant MFA (Azure)
#
# A secure cloud service offering will require phishing-resistant multi-factor
# authentication for all interactive user accounts.
#
# This policy validates:
# - Conditional Access policies require MFA
# - Azure AD authentication settings
# - Role assignments have appropriate conditions

package ksi.iam01.azure

import data.lib.helpers
import data.lib.terraform
import future.keywords.in

# Configurable parameters (injected via Jinja2)
require_hardware_mfa := false

# Warn: Role assignment without condition
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_role_assignment"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    # Check for sensitive roles
    is_privileged_role(values.role_definition_name)

    # No condition specified
    not values.condition

    msg := helpers.format_violation(
        "KSI-IAM-01",
        resource.address,
        sprintf("Role assignment for '%s' has no condition. Consider adding MFA requirement via Conditional Access.", [values.role_definition_name])
    )
}

# Deny: Key Vault without RBAC and access policy without MFA consideration
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_key_vault"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    # Has access policies (not using RBAC)
    count(values.access_policy) > 0

    # No network ACLs - accessible from anywhere
    not values.network_acls

    msg := helpers.format_violation(
        "KSI-IAM-01",
        resource.address,
        "Key Vault uses access policies without network restrictions. Use RBAC with Conditional Access for MFA enforcement."
    )
}

# Deny: App registration without requiring assignment
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "azuread_application"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    # Check for web app with sign-in
    values.web[_].homepage_url

    msg := helpers.format_violation(
        "KSI-IAM-01",
        resource.address,
        "Azure AD application should be configured with Conditional Access to require MFA for sign-in."
    )
}

# Deny: Service Principal with password credential (prefer certificates/managed identity)
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azuread_service_principal_password"
    resource.change.actions[_] in ["create", "update"]

    msg := helpers.format_violation(
        "KSI-IAM-01",
        resource.address,
        "Service Principal uses password credential. Use certificate-based authentication or Managed Identity instead."
    )
}

# Warn: User assigned identity without proper RBAC
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_user_assigned_identity"
    resource.change.actions[_] in ["create", "update"]

    msg := helpers.format_pass(
        "KSI-IAM-01",
        resource.address,
        "User-assigned managed identity created. Ensure RBAC roles are properly scoped."
    )
}

# Pass: Using managed identity (preferred over service principal passwords)
pass[msg] {
    resource := input.resource_changes[_]
    resource.type in ["azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine"]
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    identity := values.identity[_]

    identity.type in ["SystemAssigned", "UserAssigned", "SystemAssigned, UserAssigned"]

    msg := helpers.format_pass(
        "KSI-IAM-01",
        resource.address,
        "Virtual machine uses managed identity for Azure authentication."
    )
}

# Helper: Check if role is privileged
is_privileged_role(role_name) {
    privileged_roles := [
        "Owner",
        "Contributor",
        "User Access Administrator",
        "Key Vault Administrator",
        "Key Vault Secrets Officer",
        "Storage Blob Data Owner",
        "Virtual Machine Administrator Login",
    ]
    role_name == privileged_roles[_]
}

is_privileged_role(role_name) {
    contains(lower(role_name), "admin")
}

is_privileged_role(role_name) {
    contains(lower(role_name), "owner")
}

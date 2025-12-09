# KSI-IAM-01: Phishing-Resistant MFA (GCP)
#
# A secure cloud service offering will require phishing-resistant multi-factor
# authentication for all interactive user accounts.
#
# This policy validates:
# - Service accounts use workload identity
# - IAM bindings have appropriate conditions
# - Service account keys are avoided (prefer workload identity)

package ksi.iam01.gcp

import data.lib.helpers
import data.lib.terraform
import future.keywords.in

# Configurable parameters
require_hardware_mfa := false

# Deny: Service account key creation (prefer workload identity)
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_service_account_key"
    resource.change.actions[_] in ["create", "update"]

    msg := helpers.format_violation(
        "KSI-IAM-01",
        resource.address,
        "Service account key created. Use Workload Identity Federation or attached service accounts instead of keys."
    )
}

# Warn: IAM binding for privileged role without condition
warn[msg] {
    resource := input.resource_changes[_]
    resource.type in ["google_project_iam_binding", "google_project_iam_member"]
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    is_privileged_role(values.role)

    # No condition specified
    not values.condition

    msg := helpers.format_violation(
        "KSI-IAM-01",
        resource.address,
        sprintf("IAM binding for privileged role '%s' has no condition. Add conditions for time-bound or context-aware access.", [values.role])
    )
}

# Warn: Organization-level IAM binding (high risk)
warn[msg] {
    resource := input.resource_changes[_]
    resource.type in ["google_organization_iam_binding", "google_organization_iam_member"]
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    msg := helpers.format_violation(
        "KSI-IAM-01",
        resource.address,
        sprintf("Organization-level IAM binding for '%s'. Ensure MFA is enforced via Identity Platform or Cloud Identity.", [values.role])
    )
}

# Deny: GKE cluster without workload identity
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_container_cluster"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    # Check for workload identity config
    not has_workload_identity(values)

    msg := helpers.format_violation(
        "KSI-IAM-01",
        resource.address,
        "GKE cluster does not have Workload Identity enabled. Enable for secure pod authentication."
    )
}

# Deny: Cloud Function without proper service account
warn[msg] {
    resource := input.resource_changes[_]
    resource.type in ["google_cloudfunctions_function", "google_cloudfunctions2_function"]
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    # Using default compute service account
    not values.service_account_email

    msg := helpers.format_violation(
        "KSI-IAM-01",
        resource.address,
        "Cloud Function uses default service account. Specify a dedicated service account with least privilege."
    )
}

# Pass: Using workload identity federation
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_iam_workload_identity_pool"
    resource.change.actions[_] in ["create", "update"]

    msg := helpers.format_pass(
        "KSI-IAM-01",
        resource.address,
        "Workload Identity Federation pool created for secure external identity authentication."
    )
}

# Pass: GKE with workload identity
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_container_cluster"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    has_workload_identity(values)

    msg := helpers.format_pass(
        "KSI-IAM-01",
        resource.address,
        "GKE cluster has Workload Identity enabled."
    )
}

# Pass: IAM binding with condition
pass[msg] {
    resource := input.resource_changes[_]
    resource.type in ["google_project_iam_binding", "google_project_iam_member"]
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    values.condition

    msg := helpers.format_pass(
        "KSI-IAM-01",
        resource.address,
        "IAM binding has condition for context-aware access control."
    )
}

# Helper: Check if role is privileged
is_privileged_role(role) {
    privileged_roles := [
        "roles/owner",
        "roles/editor",
        "roles/iam.securityAdmin",
        "roles/iam.serviceAccountAdmin",
        "roles/iam.serviceAccountKeyAdmin",
        "roles/compute.admin",
        "roles/container.admin",
        "roles/cloudsql.admin",
    ]
    role == privileged_roles[_]
}

is_privileged_role(role) {
    contains(role, "Admin")
}

is_privileged_role(role) {
    role == "roles/owner"
}

# Helper: Check if GKE has workload identity
has_workload_identity(cluster) {
    cluster.workload_identity_config[_]
}

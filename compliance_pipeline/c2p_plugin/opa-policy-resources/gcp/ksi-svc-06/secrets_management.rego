# KSI-SVC-06: Secrets Management (GCP)
#
# A secure cloud service offering will manage and protect secrets using
# a dedicated secrets management solution.
#
# This policy validates:
# - Secret Manager is used for secrets
# - Secrets have rotation configured
# - No hardcoded secrets in configurations
# - KMS keys have proper rotation

package ksi.svc06.gcp

import data.lib.helpers
import data.lib.terraform
import future.keywords.in

# Configurable parameters
require_rotation := true
max_rotation_days := 90

# Deny: KMS key without rotation
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_kms_crypto_key"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    # No rotation period set
    not values.rotation_period

    msg := helpers.format_violation(
        "KSI-SVC-06",
        resource.address,
        "KMS crypto key does not have rotation configured. Set rotation_period for automatic key rotation."
    )
}

# Warn: KMS key with long rotation period
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_kms_crypto_key"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    values.rotation_period
    rotation_too_long(values.rotation_period)

    msg := helpers.format_violation(
        "KSI-SVC-06",
        resource.address,
        sprintf("KMS crypto key rotation period '%s' exceeds %d days. Reduce rotation period.", [values.rotation_period, max_rotation_days])
    )
}

# Deny: Secret Manager secret without rotation
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_secret_manager_secret"
    resource.change.actions[_] in ["create", "update"]

    require_rotation == true

    values := resource.change.after

    # Check for rotation configuration
    not values.rotation

    msg := helpers.format_violation(
        "KSI-SVC-06",
        resource.address,
        "Secret Manager secret does not have rotation configured. Configure automatic rotation."
    )
}

# Warn: Cloud Function with inline environment secrets
warn[msg] {
    resource := input.resource_changes[_]
    resource.type in ["google_cloudfunctions_function", "google_cloudfunctions2_function"]
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    env_vars := values.environment_variables

    some key
    looks_like_secret_key(key)
    env_vars[key]

    # Not a Secret Manager reference
    not is_secret_manager_ref(env_vars[key])

    msg := helpers.format_violation(
        "KSI-SVC-06",
        resource.address,
        sprintf("Cloud Function has environment variable '%s' that may contain secrets. Use Secret Manager references.", [key])
    )
}

# Warn: Cloud Run with inline secrets
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_cloud_run_service"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    template := values.template[_]
    container := template.spec[_].containers[_]
    env := container.env[_]

    looks_like_secret_key(env.name)
    env.value

    msg := helpers.format_violation(
        "KSI-SVC-06",
        resource.address,
        sprintf("Cloud Run service has environment variable '%s' with inline value. Use Secret Manager.", [env.name])
    )
}

# Deny: Cloud SQL with inline password
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_sql_user"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    # Has password defined directly
    values.password

    msg := helpers.format_violation(
        "KSI-SVC-06",
        resource.address,
        "Cloud SQL user has password defined in Terraform. Use Secret Manager or Cloud SQL IAM authentication."
    )
}

# Deny: Compute instance with startup script secrets
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_instance"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    metadata := values.metadata

    # Check for common secret patterns in startup script
    metadata["startup-script"]
    contains_secret_pattern(metadata["startup-script"])

    msg := helpers.format_violation(
        "KSI-SVC-06",
        resource.address,
        "Compute instance startup script may contain secrets. Use Secret Manager or instance metadata from Secret Manager."
    )
}

# Pass: KMS key with rotation
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_kms_crypto_key"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    values.rotation_period
    not rotation_too_long(values.rotation_period)

    msg := helpers.format_pass(
        "KSI-SVC-06",
        resource.address,
        "KMS crypto key has rotation configured within policy limits."
    )
}

# Pass: Secret Manager secret with rotation
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_secret_manager_secret"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    values.rotation

    msg := helpers.format_pass(
        "KSI-SVC-06",
        resource.address,
        "Secret Manager secret has rotation configured."
    )
}

# Pass: Cloud Run using Secret Manager
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_cloud_run_service"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    template := values.template[_]
    container := template.spec[_].containers[_]
    env := container.env[_]

    env.value_from[_].secret_key_ref

    msg := helpers.format_pass(
        "KSI-SVC-06",
        resource.address,
        sprintf("Cloud Run service uses Secret Manager for '%s'.", [env.name])
    )
}

# Helper: Check if rotation period is too long (90 days default)
rotation_too_long(period) {
    # Period is in seconds like "7776000s" (90 days)
    contains(period, "s")
    seconds := to_number(trim_suffix(period, "s"))
    max_seconds := max_rotation_days * 24 * 60 * 60
    seconds > max_seconds
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
    ]
    pattern := secret_patterns[_]
    contains(upper(key), pattern)
}

# Helper: Check if value is a Secret Manager reference
is_secret_manager_ref(value) {
    startswith(value, "projects/")
    contains(value, "/secrets/")
}

# Helper: Check for secret patterns in text
contains_secret_pattern(text) {
    patterns := ["password=", "api_key=", "secret=", "token="]
    pattern := patterns[_]
    contains(lower(text), pattern)
}

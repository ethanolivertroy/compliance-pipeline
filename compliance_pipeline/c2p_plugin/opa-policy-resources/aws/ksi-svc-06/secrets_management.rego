# KSI-SVC-06: Secrets Management (AWS)
#
# A secure cloud service offering will manage and protect secrets using
# a dedicated secrets management solution.
#
# This policy validates:
# - Secrets Manager secrets have encryption enabled
# - KMS keys are configured for secret encryption
# - Secrets have rotation enabled
# - No hardcoded secrets in resource configurations
# - Parameter Store SecureStrings are encrypted

package ksi.svc06.aws

import data.lib.helpers
import data.lib.terraform
import future.keywords.in

# Configurable parameters (injected via Jinja2)
require_rotation := true
max_rotation_days := 90

# Deny: Secrets Manager secret without KMS encryption
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_secretsmanager_secret"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    # No KMS key specified (will use AWS managed key)
    not values.kms_key_id

    msg := helpers.format_violation(
        "KSI-SVC-06",
        resource.address,
        "Secrets Manager secret does not specify a customer-managed KMS key. Use a CMK for encryption."
    )
}

# Deny: Secrets Manager secret without rotation
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_secretsmanager_secret"
    resource.change.actions[_] in ["create", "update"]

    require_rotation == true

    secret_id := resource.change.after.id
    secret_address := resource.address

    not has_rotation_configured(secret_id, secret_address)

    msg := helpers.format_violation(
        "KSI-SVC-06",
        resource.address,
        "Secrets Manager secret does not have automatic rotation configured."
    )
}

# Deny: Secret rotation with interval > max_rotation_days
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_secretsmanager_secret_rotation"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    rotation_days := values.rotation_rules[0].automatically_after_days

    rotation_days > to_number(max_rotation_days)

    msg := helpers.format_violation(
        "KSI-SVC-06",
        resource.address,
        sprintf("Secret rotation interval (%d days) exceeds maximum allowed (%s days).", [rotation_days, max_rotation_days])
    )
}

# Deny: SSM Parameter with SecureString not using KMS
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_ssm_parameter"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    values.type == "SecureString"

    not values.key_id

    msg := helpers.format_violation(
        "KSI-SVC-06",
        resource.address,
        "SSM SecureString parameter does not specify a KMS key. Use a CMK for encryption."
    )
}

# Deny: SSM Parameter storing secret as String instead of SecureString
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_ssm_parameter"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    values.type == "String"

    is_secret_parameter_name(values.name)

    msg := helpers.format_violation(
        "KSI-SVC-06",
        resource.address,
        sprintf("SSM parameter '%s' appears to contain secrets but uses String type. Use SecureString.", [values.name])
    )
}

# Deny: KMS key without rotation enabled
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_kms_key"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    not values.enable_key_rotation

    msg := helpers.format_violation(
        "KSI-SVC-06",
        resource.address,
        "KMS key does not have automatic key rotation enabled."
    )
}

# Deny: KMS key scheduled for deletion with short window
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_kms_key"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    values.deletion_window_in_days < 14

    msg := helpers.format_violation(
        "KSI-SVC-06",
        resource.address,
        sprintf("KMS key deletion window (%d days) is less than 14 days. Consider a longer window for recovery.", [values.deletion_window_in_days])
    )
}

# Warn: Lambda environment variables may contain secrets
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_lambda_function"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    env_vars := values.environment[0].variables

    var_name := env_vars[key]
    looks_like_secret_key(key)

    msg := helpers.format_violation(
        "KSI-SVC-06",
        resource.address,
        sprintf("Lambda environment variable '%s' may contain secrets. Use Secrets Manager or Parameter Store instead.", [key])
    )
}

# Warn: ECS task definition environment variables may contain secrets
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_ecs_task_definition"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    container_defs := json.unmarshal(values.container_definitions)
    container := container_defs[_]
    env_var := container.environment[_]

    looks_like_secret_key(env_var.name)

    msg := helpers.format_violation(
        "KSI-SVC-06",
        resource.address,
        sprintf("ECS task definition has environment variable '%s' that may contain secrets. Use secrets from Secrets Manager.", [env_var.name])
    )
}

# Pass: Secrets Manager secret with CMK encryption
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_secretsmanager_secret"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    values.kms_key_id

    msg := helpers.format_pass(
        "KSI-SVC-06",
        resource.address,
        "Secrets Manager secret is encrypted with a customer-managed KMS key."
    )
}

# Pass: KMS key with rotation enabled
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_kms_key"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    values.enable_key_rotation == true

    msg := helpers.format_pass(
        "KSI-SVC-06",
        resource.address,
        "KMS key has automatic rotation enabled."
    )
}

# Helper: Check if secret has rotation configured
has_rotation_configured(secret_id, secret_address) {
    rotation := input.resource_changes[_]
    rotation.type == "aws_secretsmanager_secret_rotation"
    rotation.change.actions[_] in ["create", "update", "no-op"]
}

# Helper: Check if parameter name suggests it contains secrets
is_secret_parameter_name(name) {
    secret_patterns := [
        "password",
        "secret",
        "api_key",
        "apikey",
        "api-key",
        "token",
        "credential",
        "private_key",
        "private-key",
    ]
    pattern := secret_patterns[_]
    contains(lower(name), pattern)
}

# Helper: Check if environment variable key looks like a secret
looks_like_secret_key(key) {
    secret_patterns := [
        "PASSWORD",
        "SECRET",
        "API_KEY",
        "APIKEY",
        "TOKEN",
        "CREDENTIAL",
        "PRIVATE_KEY",
        "DB_PASS",
        "DATABASE_PASSWORD",
        "AWS_SECRET",
    ]
    pattern := secret_patterns[_]
    contains(upper(key), pattern)
}

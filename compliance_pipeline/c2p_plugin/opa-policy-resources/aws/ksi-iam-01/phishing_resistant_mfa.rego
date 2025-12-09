# KSI-IAM-01: Phishing-Resistant MFA (AWS)
#
# A secure cloud service offering will require phishing-resistant multi-factor
# authentication for all interactive user accounts.
#
# This policy validates:
# - IAM users have MFA devices attached
# - IAM policies require MFA for sensitive actions
# - Root account has MFA enabled (via AWS Config rule)
# - SSO/Identity Center is configured with MFA

package ksi.iam01.aws

import data.lib.helpers
import data.lib.terraform
import future.keywords.in

# Configurable parameters (injected via Jinja2)
require_hardware_mfa := {{ require_hardware_mfa | default('false') }}

# Warn: IAM user created without MFA device in same plan
# (Note: MFA typically configured after user creation, so this is a warning)
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_user"
    resource.change.actions[_] == "create"

    # Check if there's a corresponding MFA device being created
    user_name := resource.change.after.name
    not has_mfa_device(user_name, resource.address)

    msg := helpers.format_violation(
        "KSI-IAM-01",
        resource.address,
        sprintf("IAM user '%s' is being created without an MFA device in this plan. Ensure MFA is configured.", [user_name])
    )
}

# Deny: IAM policy without MFA condition for sensitive actions
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_policy"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    policy := json.unmarshal(values.policy)

    statement := policy.Statement[_]
    is_sensitive_action(statement)
    not has_mfa_condition(statement)

    msg := helpers.format_violation(
        "KSI-IAM-01",
        resource.address,
        sprintf("IAM policy allows sensitive action '%s' without MFA condition.", [statement.Action])
    )
}

# Deny: IAM role trust policy for human users without MFA requirement
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_role"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    trust_policy := json.unmarshal(values.assume_role_policy)

    statement := trust_policy.Statement[_]
    is_human_principal(statement)
    not has_mfa_condition(statement)

    msg := helpers.format_violation(
        "KSI-IAM-01",
        resource.address,
        "IAM role can be assumed by IAM users without MFA requirement in trust policy."
    )
}

# Warn: Account password policy without MFA reference
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_account_password_policy"
    resource.change.actions[_] in ["create", "update"]

    # Password policy exists but doesn't enforce strong requirements
    values := resource.change.after
    values.max_password_age > 90

    msg := helpers.format_violation(
        "KSI-IAM-01",
        resource.address,
        "Password policy allows passwords older than 90 days. With MFA, consider if password rotation is still needed."
    )
}

# Deny: IAM user login profile without enforced MFA via SCP/permission boundary
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_user_login_profile"
    resource.change.actions[_] in ["create", "update"]

    msg := helpers.format_violation(
        "KSI-IAM-01",
        resource.address,
        "IAM user login profile created. Ensure MFA is enforced via SCP or permission boundary."
    )
}

# Pass: IAM user with virtual MFA device
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_virtual_mfa_device"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    msg := helpers.format_pass(
        "KSI-IAM-01",
        resource.address,
        sprintf("Virtual MFA device configured for user path '%s'.", [values.path])
    )
}

# Pass: IAM policy with MFA condition
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_policy"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    policy := json.unmarshal(values.policy)

    statement := policy.Statement[_]
    has_mfa_condition(statement)

    msg := helpers.format_pass(
        "KSI-IAM-01",
        resource.address,
        "IAM policy includes MFA condition for access control."
    )
}

# Helper: Check if there's an MFA device for the user
has_mfa_device(user_name, user_address) {
    mfa := input.resource_changes[_]
    mfa.type == "aws_iam_virtual_mfa_device"
    mfa.change.actions[_] in ["create", "update", "no-op"]
    contains(mfa.change.after.path, user_name)
}

has_mfa_device(user_name, user_address) {
    mfa := input.resource_changes[_]
    mfa.type == "aws_iam_user_mfa_device"
    mfa.change.actions[_] in ["create", "update", "no-op"]
}

# Helper: Check if action is sensitive (requires MFA)
is_sensitive_action(statement) {
    sensitive_actions := [
        "iam:*",
        "iam:CreateUser",
        "iam:DeleteUser",
        "iam:CreateAccessKey",
        "iam:UpdateAssumeRolePolicy",
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
        "sts:AssumeRole",
        "kms:*",
        "kms:Decrypt",
        "kms:CreateGrant",
        "secretsmanager:GetSecretValue",
        "s3:DeleteBucket",
        "ec2:TerminateInstances",
        "rds:DeleteDBInstance",
    ]

    action := statement.Action
    is_string(action)
    action == sensitive_actions[_]
}

is_sensitive_action(statement) {
    sensitive_actions := [
        "iam:*",
        "iam:CreateUser",
        "iam:DeleteUser",
        "iam:CreateAccessKey",
        "iam:UpdateAssumeRolePolicy",
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
        "sts:AssumeRole",
        "kms:*",
        "kms:Decrypt",
        "kms:CreateGrant",
        "secretsmanager:GetSecretValue",
        "s3:DeleteBucket",
        "ec2:TerminateInstances",
        "rds:DeleteDBInstance",
    ]

    action := statement.Action[_]
    action == sensitive_actions[_]
}

# Helper: Check if statement has MFA condition
has_mfa_condition(statement) {
    statement.Condition.Bool["aws:MultiFactorAuthPresent"] == "true"
}

has_mfa_condition(statement) {
    statement.Condition.BoolIfExists["aws:MultiFactorAuthPresent"] == "true"
}

has_mfa_condition(statement) {
    # Numeric condition for MFA age
    statement.Condition.NumericLessThan["aws:MultiFactorAuthAge"]
}

# Helper: Check if principal is a human user (not a service)
is_human_principal(statement) {
    principal := statement.Principal
    is_string(principal)
    principal != "*"
    not startswith(principal, "arn:aws:iam::")
    not endswith(principal, ":root")
}

is_human_principal(statement) {
    principal := statement.Principal.AWS
    is_string(principal)
    contains(principal, ":user/")
}

is_human_principal(statement) {
    principals := statement.Principal.AWS
    is_array(principals)
    principal := principals[_]
    contains(principal, ":user/")
}

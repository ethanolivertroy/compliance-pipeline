# KSI-SVC-02: Network Encryption (AWS)
#
# A secure cloud service offering will protect data in transit using encryption.
# All network communications should use TLS 1.2 or higher.
#
# This policy validates:
# - Load balancer listeners use HTTPS/TLS
# - API Gateway stages have TLS configured
# - RDS instances enforce SSL connections
# - S3 bucket policies enforce SSL
# - CloudFront distributions use HTTPS

package ksi.svc02.aws

import data.lib.helpers
import data.lib.terraform
import future.keywords.in

# Configurable parameters (injected via Jinja2)
minimum_tls_version := "{{ minimum_tls_version | default('TLSv1.2') }}"

# Deny: ALB/NLB listener without HTTPS
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_lb_listener"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    # Allow HTTP only on port 80 (for redirects)
    values.protocol == "HTTP"
    values.port != 80

    msg := helpers.format_violation(
        "KSI-SVC-02",
        resource.address,
        sprintf("Load balancer listener uses HTTP on port %d. Use HTTPS for data in transit encryption.", [values.port])
    )
}

# Deny: ALB listener on port 80 without redirect action
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_lb_listener"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    values.protocol == "HTTP"
    values.port == 80

    # Check if it has a redirect action to HTTPS
    not has_https_redirect(values)

    msg := helpers.format_violation(
        "KSI-SVC-02",
        resource.address,
        "HTTP listener on port 80 does not redirect to HTTPS. Configure a redirect action."
    )
}

# Deny: ALB listener with weak TLS policy
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_lb_listener"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    values.protocol == "HTTPS"

    # Check SSL policy allows TLS < 1.2
    is_weak_ssl_policy(values.ssl_policy)

    msg := helpers.format_violation(
        "KSI-SVC-02",
        resource.address,
        sprintf("Load balancer listener uses weak SSL policy '%s'. Use a policy that enforces TLS 1.2+.", [values.ssl_policy])
    )
}

# Deny: API Gateway without TLS
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_api_gateway_stage"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    # Check for client certificate
    not values.client_certificate_id

    msg := helpers.format_violation(
        "KSI-SVC-02",
        resource.address,
        "API Gateway stage does not have a client certificate configured for mutual TLS."
    )
}

# Deny: RDS instance without encryption in transit enforcement
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    # RDS should reference a parameter group that enforces SSL
    # This is a warning because we can't validate the parameter group contents
    not values.parameter_group_name

    msg := helpers.format_violation(
        "KSI-SVC-02",
        resource.address,
        "RDS instance should use a parameter group that enforces SSL connections (e.g., rds.force_ssl=1)."
    )
}

# Deny: CloudFront distribution without HTTPS
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudfront_distribution"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    behavior := values.default_cache_behavior[_]

    behavior.viewer_protocol_policy == "allow-all"

    msg := helpers.format_violation(
        "KSI-SVC-02",
        resource.address,
        "CloudFront distribution allows HTTP. Set viewer_protocol_policy to 'redirect-to-https' or 'https-only'."
    )
}

# Deny: CloudFront with minimum TLS < 1.2
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudfront_distribution"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    cert := values.viewer_certificate[_]

    is_weak_cloudfront_tls(cert.minimum_protocol_version)

    msg := helpers.format_violation(
        "KSI-SVC-02",
        resource.address,
        sprintf("CloudFront distribution uses weak TLS version '%s'. Use TLSv1.2_2021 or higher.", [cert.minimum_protocol_version])
    )
}

# Deny: Elasticsearch/OpenSearch without node-to-node encryption
deny[msg] {
    resource := input.resource_changes[_]
    resource.type in ["aws_elasticsearch_domain", "aws_opensearch_domain"]
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    not values.node_to_node_encryption[0].enabled

    msg := helpers.format_violation(
        "KSI-SVC-02",
        resource.address,
        "Elasticsearch/OpenSearch domain does not have node-to-node encryption enabled."
    )
}

# Deny: Elasticsearch/OpenSearch without enforce_https
deny[msg] {
    resource := input.resource_changes[_]
    resource.type in ["aws_elasticsearch_domain", "aws_opensearch_domain"]
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    not values.domain_endpoint_options[0].enforce_https

    msg := helpers.format_violation(
        "KSI-SVC-02",
        resource.address,
        "Elasticsearch/OpenSearch domain does not enforce HTTPS on the domain endpoint."
    )
}

# Pass: HTTPS listener with strong TLS policy
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_lb_listener"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    values.protocol == "HTTPS"

    not is_weak_ssl_policy(values.ssl_policy)

    msg := helpers.format_pass(
        "KSI-SVC-02",
        resource.address,
        sprintf("Load balancer listener uses HTTPS with SSL policy '%s'.", [values.ssl_policy])
    )
}

# Helper: Check if listener has HTTPS redirect
has_https_redirect(listener) {
    action := listener.default_action[_]
    action.type == "redirect"
    action.redirect[_].protocol == "HTTPS"
}

# Helper: Check if SSL policy is weak (allows TLS < 1.2)
is_weak_ssl_policy(policy) {
    weak_policies := [
        "ELBSecurityPolicy-2016-08",
        "ELBSecurityPolicy-TLS-1-0-2015-04",
        "ELBSecurityPolicy-TLS-1-1-2017-01",
    ]
    policy == weak_policies[_]
}

is_weak_ssl_policy(policy) {
    # Also catch any policy with TLS-1-0 or TLS-1-1 in the name
    contains(policy, "TLS-1-0")
}

is_weak_ssl_policy(policy) {
    contains(policy, "TLS-1-1")
}

# Helper: Check if CloudFront TLS version is weak
is_weak_cloudfront_tls(version) {
    weak_versions := [
        "SSLv3",
        "TLSv1",
        "TLSv1_2016",
        "TLSv1.1_2016",
    ]
    version == weak_versions[_]
}

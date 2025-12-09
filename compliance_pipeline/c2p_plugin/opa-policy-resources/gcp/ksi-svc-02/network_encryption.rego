# KSI-SVC-02: Network Encryption (GCP)
#
# A secure cloud service offering will protect data in transit using encryption.
# All network communications should use TLS 1.2 or higher.
#
# This policy validates:
# - Load balancers use HTTPS
# - Cloud SQL requires SSL
# - App Engine enforces HTTPS
# - Cloud Run enforces HTTPS

package ksi.svc02.gcp

import data.lib.helpers
import data.lib.terraform
import future.keywords.in

# Configurable parameters
minimum_tls_version := "TLS_1_2"

# Deny: HTTPS Load Balancer with weak SSL policy
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_ssl_policy"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    is_weak_tls_version(values.min_tls_version)

    msg := helpers.format_violation(
        "KSI-SVC-02",
        resource.address,
        sprintf("SSL policy uses weak TLS version '%s'. Use TLS_1_2 or higher.", [values.min_tls_version])
    )
}

# Deny: SSL policy with weak cipher suites
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_ssl_policy"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    values.profile == "COMPATIBLE"

    msg := helpers.format_violation(
        "KSI-SVC-02",
        resource.address,
        "SSL policy uses COMPATIBLE profile which includes weak ciphers. Use MODERN or RESTRICTED profile."
    )
}

# Deny: Cloud SQL without SSL requirement
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_sql_database_instance"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    settings := values.settings[_]
    ip_config := settings.ip_configuration[_]

    not ip_config.require_ssl

    msg := helpers.format_violation(
        "KSI-SVC-02",
        resource.address,
        "Cloud SQL instance does not require SSL connections. Enable require_ssl in ip_configuration."
    )
}

# Deny: Cloud Storage bucket without HTTPS-only access
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_storage_bucket"
    resource.change.actions[_] in ["create", "update"]

    # Note: GCS always uses HTTPS, but check for uniform bucket-level access
    values := resource.change.after

    not values.uniform_bucket_level_access

    msg := helpers.format_violation(
        "KSI-SVC-02",
        resource.address,
        "Storage bucket does not use uniform bucket-level access. Enable for consistent access control."
    )
}

# Deny: Cloud Run service without HTTPS enforcement
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_cloud_run_service"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    metadata := values.metadata[_]
    annotations := metadata.annotations

    # Check if ingress allows HTTP
    annotations["run.googleapis.com/ingress"] == "all"

    msg := helpers.format_violation(
        "KSI-SVC-02",
        resource.address,
        "Cloud Run service allows all ingress including HTTP. Use 'internal-and-cloud-load-balancing' or 'internal' for secure access."
    )
}

# Deny: App Engine without HTTPS redirect
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_app_engine_application_url_dispatch_rules"
    resource.change.actions[_] in ["create", "update"]

    # Check dispatch rules for HTTP handling
    values := resource.change.after
    rule := values.dispatch_rules[_]

    not contains(rule.path, "https")

    msg := helpers.format_violation(
        "KSI-SVC-02",
        resource.address,
        "App Engine dispatch rules should enforce HTTPS. Configure URL redirects appropriately."
    )
}

# Deny: GKE cluster without private endpoint
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_container_cluster"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    private_cluster := values.private_cluster_config[_]

    not private_cluster.enable_private_endpoint

    msg := helpers.format_violation(
        "KSI-SVC-02",
        resource.address,
        "GKE cluster does not use private endpoint. Consider enabling for secure API server access."
    )
}

# Pass: SSL policy with strong TLS
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_ssl_policy"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    not is_weak_tls_version(values.min_tls_version)
    values.profile != "COMPATIBLE"

    msg := helpers.format_pass(
        "KSI-SVC-02",
        resource.address,
        "SSL policy uses TLS 1.2+ with strong cipher profile."
    )
}

# Pass: Cloud SQL with SSL required
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_sql_database_instance"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    settings := values.settings[_]
    ip_config := settings.ip_configuration[_]

    ip_config.require_ssl == true

    msg := helpers.format_pass(
        "KSI-SVC-02",
        resource.address,
        "Cloud SQL instance requires SSL connections."
    )
}

# Helper: Check if TLS version is weak
is_weak_tls_version(version) {
    weak_versions := [
        "TLS_1_0",
        "TLS_1_1",
    ]
    version == weak_versions[_]
}

is_weak_tls_version(version) {
    not version
}

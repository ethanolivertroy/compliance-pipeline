# KSI-CNA-01: Restrict Network Traffic (GCP)
#
# A secure cloud service offering will use network controls to limit traffic
# to only traffic from vetted locations or resources.
#
# This policy validates:
# - Firewall rules do not allow unrestricted ingress (0.0.0.0/0)
# - VPC flow logs are enabled
# - Subnets have appropriate logging

package ksi.cna01.gcp

import data.lib.helpers
import data.lib.terraform
import future.keywords.in

# Configurable parameters
allowed_ingress_cidrs := ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
allowed_public_ports := [443]

# Deny: Firewall rule allowing all ingress from 0.0.0.0/0
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_firewall"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    values.direction == "INGRESS"

    # Check for unrestricted source
    source_range := values.source_ranges[_]
    source_range == "0.0.0.0/0"

    # Check if any allowed ports are not in allowed_public_ports
    not all_ports_allowed(values)

    msg := helpers.format_violation(
        "KSI-CNA-01",
        resource.address,
        "Firewall rule allows unrestricted ingress from 0.0.0.0/0. Restrict source ranges to vetted IPs."
    )
}

# Deny: Firewall rule allowing SSH/RDP from anywhere
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_firewall"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    values.direction == "INGRESS"

    source_range := values.source_ranges[_]
    source_range == "0.0.0.0/0"

    # Check for management ports
    allow_rule := values.allow[_]
    is_management_port(allow_rule.ports)

    msg := helpers.format_violation(
        "KSI-CNA-01",
        resource.address,
        sprintf("Firewall rule allows management access (SSH/RDP) from 0.0.0.0/0. Use IAP or VPN instead.", [])
    )
}

# Deny: Subnet without flow logs
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_subnetwork"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    # Check for flow logs configuration
    not has_flow_logs(values)

    msg := helpers.format_violation(
        "KSI-CNA-01",
        resource.address,
        "Subnet does not have VPC flow logs enabled. Enable flow logs for network monitoring."
    )
}

# Warn: VPC without private Google access
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_subnetwork"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    not values.private_ip_google_access

    msg := helpers.format_violation(
        "KSI-CNA-01",
        resource.address,
        "Subnet does not have private Google access enabled. Consider enabling for secure GCP API access."
    )
}

# Deny: Cloud SQL with public IP
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_sql_database_instance"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    settings := values.settings[_]
    ip_config := settings.ip_configuration[_]

    ip_config.ipv4_enabled == true

    # Check for authorized networks allowing 0.0.0.0/0
    auth_network := ip_config.authorized_networks[_]
    auth_network.value == "0.0.0.0/0"

    msg := helpers.format_violation(
        "KSI-CNA-01",
        resource.address,
        "Cloud SQL allows connections from 0.0.0.0/0. Restrict to specific IP ranges or use private IP."
    )
}

# Pass: Firewall rule with restricted source
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_firewall"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    values.direction == "INGRESS"

    # No unrestricted source
    not has_unrestricted_source(values)

    msg := helpers.format_pass(
        "KSI-CNA-01",
        resource.address,
        "Firewall rule restricts ingress to specific source ranges."
    )
}

# Pass: Subnet with flow logs enabled
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_subnetwork"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    has_flow_logs(values)

    msg := helpers.format_pass(
        "KSI-CNA-01",
        resource.address,
        "Subnet has VPC flow logs enabled."
    )
}

# Helper: Check if all ports are in allowed list
all_ports_allowed(firewall) {
    allow_rule := firewall.allow[_]
    port := allow_rule.ports[_]
    port_num := to_number(port)
    port_num == allowed_public_ports[_]
}

# Helper: Check for management ports (SSH=22, RDP=3389)
is_management_port(ports) {
    port := ports[_]
    port == "22"
}

is_management_port(ports) {
    port := ports[_]
    port == "3389"
}

# Helper: Check if flow logs are enabled
has_flow_logs(subnet) {
    subnet.log_config[_]
}

# Helper: Check for unrestricted source ranges
has_unrestricted_source(firewall) {
    source_range := firewall.source_ranges[_]
    source_range == "0.0.0.0/0"
}

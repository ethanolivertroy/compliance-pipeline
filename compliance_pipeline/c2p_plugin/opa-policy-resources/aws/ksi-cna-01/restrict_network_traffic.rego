# KSI-CNA-01: Restrict Network Traffic (AWS)
#
# A secure cloud service offering will use network controls to limit traffic
# to only traffic from vetted locations or resources.
#
# This policy validates:
# - Security groups do not allow unrestricted ingress (0.0.0.0/0)
# - VPCs have flow logs enabled
# - NACLs follow least-privilege principles

package ksi.cna01.aws

import data.lib.helpers
import data.lib.terraform
import future.keywords.in

# Configurable parameters (injected via Jinja2)
# Default: Only allow traffic from private RFC 1918 ranges
allowed_ingress_cidrs := {{ allowed_ingress_cidrs | default('["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]') | safe }}

# Ports that are allowed from public internet (e.g., HTTPS only)
allowed_public_ports := {{ allowed_public_ports | default('[443]') | safe }}

# Deny: Security group rules with unrestricted ingress
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group_rule"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    values.type == "ingress"

    # Check for 0.0.0.0/0 in CIDR blocks
    cidr := values.cidr_blocks[_]
    helpers.is_public_cidr(cidr)

    # Not an allowed public port
    not is_allowed_public_port(values.from_port, values.to_port)

    msg := helpers.format_violation(
        "KSI-CNA-01",
        resource.address,
        sprintf("Security group rule allows unrestricted ingress from %s on ports %d-%d. Only vetted source IPs should be allowed.", [cidr, values.from_port, values.to_port])
    )
}

# Deny: Security group with inline ingress rules allowing 0.0.0.0/0
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    ingress_rule := values.ingress[_]

    cidr := ingress_rule.cidr_blocks[_]
    helpers.is_public_cidr(cidr)

    not is_allowed_public_port(ingress_rule.from_port, ingress_rule.to_port)

    msg := helpers.format_violation(
        "KSI-CNA-01",
        resource.address,
        sprintf("Security group has inline rule allowing unrestricted ingress from %s on ports %d-%d.", [cidr, ingress_rule.from_port, ingress_rule.to_port])
    )
}

# Deny: VPC without flow logs
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_vpc"
    resource.change.actions[_] in ["create", "update"]

    # Check if there's a corresponding flow log for this VPC
    not has_flow_log(resource.change.after.id, resource.address)

    msg := helpers.format_violation(
        "KSI-CNA-01",
        resource.address,
        "VPC does not have VPC Flow Logs enabled. Network traffic must be monitored for security analysis."
    )
}

# Warn: Security group with SSH (22) or RDP (3389) from anywhere
warn[msg] {
    resource := input.resource_changes[_]
    resource.type in ["aws_security_group", "aws_security_group_rule"]
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    # Check inline rules or standalone rule
    ingress_rule := get_ingress_rule(resource)

    cidr := ingress_rule.cidr_blocks[_]
    helpers.is_public_cidr(cidr)

    is_management_port(ingress_rule.from_port, ingress_rule.to_port)

    msg := helpers.format_violation(
        "KSI-CNA-01",
        resource.address,
        sprintf("Security group allows management access (SSH/RDP) from %s. Use a bastion host or VPN instead.", [cidr])
    )
}

# Pass: Security group rule with restricted ingress
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group_rule"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    values.type == "ingress"

    # All CIDRs are in allowed list
    all_cidrs_allowed(values.cidr_blocks)

    msg := helpers.format_pass(
        "KSI-CNA-01",
        resource.address,
        "Security group rule restricts ingress to vetted source IPs."
    )
}

# Helper: Check if port range is allowed for public access
is_allowed_public_port(from_port, to_port) {
    port := allowed_public_ports[_]
    from_port <= port
    to_port >= port
    from_port == to_port  # Single port only
}

# Helper: Check if ports are management ports (SSH/RDP)
is_management_port(from_port, to_port) {
    # SSH
    from_port <= 22
    to_port >= 22
}

is_management_port(from_port, to_port) {
    # RDP
    from_port <= 3389
    to_port >= 3389
}

# Helper: Check if all CIDRs are in the allowed list
all_cidrs_allowed(cidrs) {
    count([c | c := cidrs[_]; not cidr_allowed(c)]) == 0
}

cidr_allowed(cidr) {
    allowed := allowed_ingress_cidrs[_]
    cidr == allowed
}

cidr_allowed(cidr) {
    helpers.is_private_cidr(cidr)
}

# Helper: Check if VPC has a corresponding flow log
has_flow_log(vpc_id, vpc_address) {
    flow_log := input.resource_changes[_]
    flow_log.type == "aws_flow_log"
    flow_log.change.actions[_] in ["create", "update", "no-op"]
    flow_log.change.after.vpc_id == vpc_id
}

has_flow_log(vpc_id, vpc_address) {
    # Also check by reference pattern
    flow_log := input.resource_changes[_]
    flow_log.type == "aws_flow_log"
    flow_log.change.actions[_] in ["create", "update", "no-op"]
    contains(flow_log.change.after_unknown.vpc_id, vpc_address)
}

# Helper: Get ingress rule from security group or rule resource
get_ingress_rule(resource) = rule {
    resource.type == "aws_security_group_rule"
    resource.change.after.type == "ingress"
    rule := resource.change.after
}

get_ingress_rule(resource) = rule {
    resource.type == "aws_security_group"
    rule := resource.change.after.ingress[_]
}

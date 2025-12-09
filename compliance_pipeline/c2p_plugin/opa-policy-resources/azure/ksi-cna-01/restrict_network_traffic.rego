# KSI-CNA-01: Restrict Network Traffic (Azure)
#
# A secure cloud service offering will use network controls to limit traffic
# to only traffic from vetted locations or resources.
#
# This policy validates:
# - Network Security Groups do not allow unrestricted ingress (0.0.0.0/0)
# - NSG flow logs are enabled
# - Subnets have NSGs attached

package ksi.cna01.azure

import data.lib.helpers
import data.lib.terraform
import future.keywords.in

# Configurable parameters (injected via Jinja2)
allowed_ingress_cidrs := ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
allowed_public_ports := [443]

# Deny: NSG rule with unrestricted inbound access
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_network_security_rule"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    values.direction == "Inbound"
    values.access == "Allow"

    # Check for unrestricted source
    values.source_address_prefix == "*"

    # Not an allowed public port
    not is_allowed_public_port(values.destination_port_range)

    msg := helpers.format_violation(
        "KSI-CNA-01",
        resource.address,
        sprintf("NSG rule allows unrestricted inbound access from '*' on port %s. Only vetted source IPs should be allowed.", [values.destination_port_range])
    )
}

# Deny: NSG rule allowing SSH/RDP from anywhere
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_network_security_rule"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    values.direction == "Inbound"
    values.access == "Allow"
    values.source_address_prefix == "*"

    is_management_port(values.destination_port_range)

    msg := helpers.format_violation(
        "KSI-CNA-01",
        resource.address,
        sprintf("NSG rule allows management access (SSH/RDP) from '*' on port %s. Use Azure Bastion or VPN instead.", [values.destination_port_range])
    )
}

# Deny: NSG with inline rules allowing unrestricted access
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_network_security_group"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    rule := values.security_rule[_]

    rule.direction == "Inbound"
    rule.access == "Allow"
    rule.source_address_prefix == "*"

    not is_allowed_public_port(rule.destination_port_range)

    msg := helpers.format_violation(
        "KSI-CNA-01",
        resource.address,
        sprintf("NSG has inline rule allowing unrestricted inbound from '*' on port %s.", [rule.destination_port_range])
    )
}

# Deny: VNet without Network Watcher flow logs
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_virtual_network"
    resource.change.actions[_] in ["create", "update"]

    # Check if there's a corresponding flow log
    not has_flow_log(resource.address)

    msg := helpers.format_violation(
        "KSI-CNA-01",
        resource.address,
        "Virtual Network does not have NSG flow logs configured. Network traffic should be monitored."
    )
}

# Deny: Subnet without NSG association
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_subnet"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after

    # Skip special subnets that can't have NSGs
    not is_special_subnet(values.name)

    # Check for NSG association
    not has_nsg_association(resource.address)

    msg := helpers.format_violation(
        "KSI-CNA-01",
        resource.address,
        "Subnet does not have a Network Security Group associated. All subnets should have NSG protection."
    )
}

# Pass: NSG rule with restricted source
pass[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_network_security_rule"
    resource.change.actions[_] in ["create", "update"]

    values := resource.change.after
    values.direction == "Inbound"
    values.access == "Allow"

    values.source_address_prefix != "*"
    not helpers.is_public_cidr(values.source_address_prefix)

    msg := helpers.format_pass(
        "KSI-CNA-01",
        resource.address,
        "NSG rule restricts inbound to specific source addresses."
    )
}

# Helper: Check if port is allowed for public access
is_allowed_public_port(port_range) {
    port := allowed_public_ports[_]
    port_range == sprintf("%d", [port])
}

is_allowed_public_port(port_range) {
    port_range == "443"
}

# Helper: Check if port is a management port
is_management_port(port_range) {
    port_range == "22"
}

is_management_port(port_range) {
    port_range == "3389"
}

is_management_port(port_range) {
    port_range == "22-22"
}

is_management_port(port_range) {
    port_range == "3389-3389"
}

# Helper: Check if VNet has flow logs
has_flow_log(vnet_address) {
    flow_log := input.resource_changes[_]
    flow_log.type == "azurerm_network_watcher_flow_log"
    flow_log.change.actions[_] in ["create", "update", "no-op"]
}

# Helper: Check if subnet has NSG association
has_nsg_association(subnet_address) {
    assoc := input.resource_changes[_]
    assoc.type == "azurerm_subnet_network_security_group_association"
    assoc.change.actions[_] in ["create", "update", "no-op"]
    contains(assoc.change.after.subnet_id, subnet_address)
}

# Helper: Check if subnet is a special Azure subnet
is_special_subnet(name) {
    special_subnets := [
        "GatewaySubnet",
        "AzureFirewallSubnet",
        "AzureBastionSubnet",
        "RouteServerSubnet",
    ]
    name == special_subnets[_]
}

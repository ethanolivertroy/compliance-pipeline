# helpers.rego - Common helper functions for FedRAMP 20x KSI policies
package lib.helpers

import future.keywords.in

# Check if a value exists and is not null/empty
is_set(value) {
    value != null
    value != ""
}

# Get a nested value safely with a default
get_default(obj, key, default_value) = result {
    result := obj[key]
} else = result {
    result := default_value
}

# Check if a string is in a list (case-insensitive)
string_in_list(str, list) {
    lower(str) == lower(list[_])
}

# Check if a CIDR is private (RFC 1918)
is_private_cidr(cidr) {
    startswith(cidr, "10.")
}

is_private_cidr(cidr) {
    startswith(cidr, "172.16.")
}

is_private_cidr(cidr) {
    startswith(cidr, "172.17.")
}

is_private_cidr(cidr) {
    startswith(cidr, "172.18.")
}

is_private_cidr(cidr) {
    startswith(cidr, "172.19.")
}

is_private_cidr(cidr) {
    startswith(cidr, "172.2")
}

is_private_cidr(cidr) {
    startswith(cidr, "172.30.")
}

is_private_cidr(cidr) {
    startswith(cidr, "172.31.")
}

is_private_cidr(cidr) {
    startswith(cidr, "192.168.")
}

# Check if CIDR allows all traffic (0.0.0.0/0 or ::/0)
is_public_cidr(cidr) {
    cidr == "0.0.0.0/0"
}

is_public_cidr(cidr) {
    cidr == "::/0"
}

# Extract resource type from Terraform address
resource_type(address) = type {
    parts := split(address, ".")
    type := parts[0]
}

# Extract resource name from Terraform address
resource_name(address) = name {
    parts := split(address, ".")
    name := parts[1]
}

# Format a violation message consistently
format_violation(ksi, resource_address, message) = formatted {
    formatted := sprintf("%s Violation: Resource '%s' - %s", [ksi, resource_address, message])
}

# Format a pass message consistently
format_pass(ksi, resource_address, message) = formatted {
    formatted := sprintf("%s Pass: Resource '%s' - %s", [ksi, resource_address, message])
}

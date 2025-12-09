# terraform.rego - Terraform plan parsing helpers
package lib.terraform

import future.keywords.in

# Get all resources from a Terraform plan that match the given type
resources_by_type(plan, resource_type) = resources {
    resources := [r |
        r := plan.resource_changes[_]
        r.type == resource_type
        r.change.actions[_] in ["create", "update", "no-op"]
    ]
}

# Get all resources being created or updated
changing_resources(plan) = resources {
    resources := [r |
        r := plan.resource_changes[_]
        r.change.actions[_] in ["create", "update"]
    ]
}

# Get all resources being created
created_resources(plan) = resources {
    resources := [r |
        r := plan.resource_changes[_]
        "create" in r.change.actions
    ]
}

# Get the "after" values for a resource (the planned state)
planned_values(resource) = values {
    values := resource.change.after
}

# Get the "before" values for a resource (the current state)
current_values(resource) = values {
    values := resource.change.before
}

# Check if a resource is being created
is_create(resource) {
    "create" in resource.change.actions
}

# Check if a resource is being updated
is_update(resource) {
    "update" in resource.change.actions
}

# Check if a resource is being deleted
is_delete(resource) {
    "delete" in resource.change.actions
}

# Check if a resource has no changes
is_noop(resource) {
    resource.change.actions == ["no-op"]
}

# Get resource address (e.g., "aws_security_group.main")
resource_address(resource) = resource.address

# Get resource type from a resource
resource_type(resource) = resource.type

# Get resource name from address
resource_name(resource) = name {
    parts := split(resource.address, ".")
    count(parts) >= 2
    name := parts[1]
}

# Check if a tag exists on a resource
has_tag(resource, tag_key) {
    planned_values(resource).tags[tag_key]
}

# Get tag value from a resource
get_tag(resource, tag_key) = value {
    value := planned_values(resource).tags[tag_key]
}

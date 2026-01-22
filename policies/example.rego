# Example Rego policies for Sentinel authorization
# See: https://www.openpolicyagent.org/docs/latest/policy-language/

package sentinel.authz

import rego.v1

# Default to deny
default allow := false

# Allow authenticated users to read public resources
allow if {
    input.action == "read"
    input.resource.visibility == "public"
}

# Allow resource owners full access
allow if {
    input.principal.id == input.resource.owner_id
}

# Allow users with viewer role to read any resource
allow if {
    input.action == "read"
    input.principal.role == "viewer"
}

# Allow users with editor role to read and update
allow if {
    input.principal.role == "editor"
    input.action in ["read", "update"]
}

# Allow admins full access
allow if {
    input.principal.role == "admin"
}

# Deny rules take precedence

default deny := false

# Deny access to admin endpoints for non-admin users
deny if {
    startswith(input.resource.path, "/admin")
    input.principal.role != "admin"
}

# Deny access outside business hours
deny if {
    hour := time.clock(time.now_ns())[0]
    hour < 9
    input.principal.role != "admin"
    not input.principal.allow_after_hours
}

deny if {
    hour := time.clock(time.now_ns())[0]
    hour > 17
    input.principal.role != "admin"
    not input.principal.allow_after_hours
}

# Rate limit protection
deny if {
    input.context.request_count > 1000
    input.principal.tier != "premium"
}

# Final decision computation
decision := "allow" if {
    allow
    not deny
}

decision := "deny" if {
    not allow
}

decision := "deny" if {
    deny
}

# Provide reasons for decisions
reasons contains reason if {
    allow
    not deny
    reason := "Request allowed by policy"
}

reasons contains reason if {
    not allow
    reason := "No matching allow rule"
}

reasons contains reason if {
    deny
    startswith(input.resource.path, "/admin")
    reason := "Admin endpoint access denied for non-admin user"
}

reasons contains reason if {
    deny
    input.context.request_count > 1000
    reason := "Rate limit exceeded"
}

// Example Cedar policies for Sentinel authorization
// See: https://www.cedarpolicy.com/

// Allow authenticated users to read public resources
permit(
  principal,
  action == Action::"read",
  resource
) when {
  resource.visibility == "public"
};

// Allow resource owners full access to their resources
permit(
  principal,
  action,
  resource
) when {
  principal == resource.owner
};

// Allow users with viewer role to read any resource
permit(
  principal,
  action == Action::"read",
  resource
) when {
  principal.role == "viewer"
};

// Allow users with editor role to read and update resources
permit(
  principal,
  action,
  resource
) when {
  principal.role == "editor" &&
  (action == Action::"read" || action == Action::"update")
};

// Allow admins full access
permit(
  principal,
  action,
  resource
) when {
  principal.role == "admin"
};

// Deny access to admin endpoints for non-admin users
forbid(
  principal,
  action,
  resource
) when {
  resource.path.hasPrefix("/admin") &&
  principal.role != "admin"
};

// Deny access outside business hours (example with context)
forbid(
  principal,
  action,
  resource
) when {
  context.hour < 9 || context.hour > 17
} unless {
  principal.role == "admin" ||
  principal.allowAfterHours == true
};

// Rate limit protection - deny if too many requests
forbid(
  principal,
  action,
  resource
) when {
  context.requestCount > 1000
} unless {
  principal.tier == "premium"
};

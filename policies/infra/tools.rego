# Title: Infrastructure tool names and protected environments
package elodea.authz

import rego.v1

# ============================================================
# Shared definitions for the infrastructure pack (kubernetes.rego,
# terraform.rego, database.rego).
#
# The pack matches Elodea's canonical tool names (kubernetes.resource.delete,
# terraform.apply, database.query, ...). MCP servers name their tools
# differently, so map yours here. Check the names and argument shapes against
# your server's tools/list before relying on a mapping: a tool the pack does
# not recognize falls through to default_deny, never to allow.
#
#   infra_tool_aliases := {
#       "resources_delete": "kubernetes.resource.delete",
#       "execute_sql": "database.query",
#   }
# ============================================================

infra_tool_aliases := {}

# The tool name the infrastructure rules match on.
infra_tool := object.get(infra_tool_aliases, input.tool, input.tool)

# Namespaces and Terraform workspaces that count as production. Changes there
# wait for a person; everywhere else they run autonomously.
infra_protected_names := {"production", "prod", "live"}

infra_protected(name) if {
    is_string(name)
    lower(name) in infra_protected_names
}

infra_protected(name) if {
    is_string(name)
    regex.match(`^(prod|production)-|-(prod|production)$`, lower(name))
}

# A required name argument: a non-empty string.
infra_name_valid(name) if {
    is_string(name)
    trim_space(name) != ""
}

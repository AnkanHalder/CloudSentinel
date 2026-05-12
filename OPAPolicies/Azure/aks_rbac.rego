package cloud_security

deny contains vuln if {
    some i
    res := input.resource[i]

    some aks_name
    aks := res.azurerm_kubernetes_cluster[aks_name]

    aks.role_based_access_control_enabled == false

    vuln := {
        "severity_score": 8,
        "resource_name": sprintf("azurerm_kubernetes_cluster.%v", [aks_name]),
        "message": "AKS cluster has Role-Based Access Control (RBAC) disabled.",
        "remediation": "Enable 'role_based_access_control_enabled = true' to enforce RBAC."
    }
}

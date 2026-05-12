package cloud_security

deny contains vuln if {
    some i
    res := input.resource[i]

    some sa_name
    sa := res.azurerm_storage_account[sa_name]

    sa.allow_blob_public_access == true

    vuln := {
        "severity_score": 8,
        "resource_name": sprintf("azurerm_storage_account.%v", [sa_name]),
        "message": "Azure Storage Account allows public blob access.",
        "remediation": "Set 'allow_blob_public_access = false' to restrict anonymous access."
    }
}

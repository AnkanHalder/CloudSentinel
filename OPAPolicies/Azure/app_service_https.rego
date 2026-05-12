package cloud_security

deny contains vuln if {
    some i
    res := input.resource[i]

    some app_name
    app := res.azurerm_app_service[app_name]

    app.https_only == false

    vuln := {
        "severity_score": 6,
        "resource_name": sprintf("azurerm_app_service.%v", [app_name]),
        "message": "Azure App Service does not enforce HTTPS only.",
        "remediation": "Set 'https_only = true' to prevent unencrypted HTTP traffic."
    }
}

package cloud_security

deny contains vuln if {
    some i
    res := input.resource[i]

    some rule_name
    rule := res.azurerm_sql_firewall_rule[rule_name]

    rule.start_ip_address == "0.0.0.0"
    rule.end_ip_address == "0.0.0.0"

    vuln := {
        "severity_score": 7,
        "resource_name": sprintf("azurerm_sql_firewall_rule.%v", [rule_name]),
        "message": "Azure SQL Firewall allows access to Azure services (0.0.0.0/0.0.0.0) which can include external tenants.",
        "remediation": "Disable 'Allow access to Azure services' and use specific VNet rules or IP ranges."
    }
}

package cloud_security

deny contains vuln if {
    some i
    res := input.resource[i]

    some nsg_name
    nsg := res.azurerm_network_security_group[nsg_name]

    some j
    rule := nsg.security_rule[j]

    rule.access == "Allow"
    rule.direction == "Inbound"
    rule.destination_port_range == "3389"
    rule.source_address_prefix == "*"

    vuln := {
        "severity_score": 9,
        "resource_name": sprintf("azurerm_network_security_group.%v", [nsg_name]),
        "message": "Network Security Group allows inbound RDP (port 3389) from the internet.",
        "remediation": "Restrict RDP access to specific corporate IP ranges."
    }
}

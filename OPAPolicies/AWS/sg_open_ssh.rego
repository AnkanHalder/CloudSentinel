package cloud_security

deny contains vuln if {
    some i
    res := input.resource[i]

    some sg_name
    sg := res.aws_security_group[sg_name]

    some j
    ingress := sg.ingress[j]

    # hcl2 parses lists/arrays, so we check if "0.0.0.0/0" is in cidr_blocks
    some k
    ingress.cidr_blocks[k] == "0.0.0.0/0"
    ingress.to_port == 22

    vuln := {
        "severity_score": 9,
        "resource_name": sprintf("aws_security_group.%v", [sg_name]),
        "message": "Security Group allows inbound SSH (port 22) from the internet.",
        "remediation": "Restrict SSH access to specific IP ranges (e.g. corporate VPN or bastion host IPs)."
    }
}

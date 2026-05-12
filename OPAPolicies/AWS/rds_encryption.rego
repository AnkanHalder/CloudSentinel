package cloud_security

deny contains vuln if {
    some i
    res := input.resource[i]

    some rds_name
    rds := res.aws_db_instance[rds_name]

    # Default is false, so if it's missing or explicitly false, it's a vulnerability
    not rds.storage_encrypted == true

    vuln := {
        "severity_score": 7,
        "resource_name": sprintf("aws_db_instance.%v", [rds_name]),
        "message": "RDS database instance is not encrypted at rest.",
        "remediation": "Enable 'storage_encrypted = true' and specify a KMS key ID."
    }
}

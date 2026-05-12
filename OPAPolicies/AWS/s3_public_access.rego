package cloud_security

deny contains vuln if {
    some i
    res := input.resource[i]

    some bucket_name
    bucket := res.aws_s3_bucket[bucket_name]

    bucket.acl == "public-read"

    vuln := {
        "severity_score": 8,
        "resource_name": sprintf("aws_s3_bucket.%v", [bucket_name]),
        "message": "S3 bucket allows public read access.",
        "remediation": "Change the ACL to 'private' and use IAM policies or bucket policies for access control."
    }
}

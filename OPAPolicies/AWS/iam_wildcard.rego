package cloud_security

deny contains vuln if {
    some i
    res := input.resource[i]

    some policy_name
    policy := res.aws_iam_policy[policy_name]

    # A simple check for wildcard action in JSON policy (HCL converts jsonencode to string but let's assume it's pure HCL for now or simple string matching)
    # If the policy string contains "*", it's a weak regex-like check for MVP purposes
    contains(policy.policy, "\"Action\": \"*\"")
    contains(policy.policy, "\"Resource\": \"*\"")

    vuln := {
        "severity_score": 10,
        "resource_name": sprintf("aws_iam_policy.%v", [policy_name]),
        "message": "IAM policy grants full administrative privileges (* on *).",
        "remediation": "Apply the principle of least privilege by specifying exact actions and resources."
    }
}

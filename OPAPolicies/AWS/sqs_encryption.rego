package cloud_security

deny contains vuln if {
    some i
    res := input.resource[i]

    some sqs_name
    sqs := res.aws_sqs_queue[sqs_name]

    not sqs.kms_master_key_id
    not sqs.sqs_managed_sse_enabled == true

    vuln := {
        "severity_score": 6,
        "resource_name": sprintf("aws_sqs_queue.%v", [sqs_name]),
        "message": "SQS queue does not have server-side encryption enabled.",
        "remediation": "Enable SQS managed SSE or provide a 'kms_master_key_id'."
    }
}

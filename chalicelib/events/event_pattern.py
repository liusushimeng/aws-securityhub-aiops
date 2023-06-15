findings_imported = {
    "detail-type": [
        "Security Hub Findings - Imported"
    ],
    "source": [
        "aws.securityhub"
    ],
    "detail": {
        "findings": {
            "Workflow": {
                "Status": [
                    "NEW",
                    "SUPPRESSED"
                ]
            }
        }
    }
}

findings_custom_action = {
    "detail-type": [
        "Security Hub Findings - Custom Action"
    ],
    "resources": [
        {"prefix": "arn:aws-cn:securityhub:cn-north-1:843403612003:action/custom/"},
    ],
    "source": [
        "aws.securityhub"
    ]
}

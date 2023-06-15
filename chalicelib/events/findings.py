import json

import boto3
from chalice import Blueprint
from chalicelib.utils import get_wechat_group, send_wechat_message
from .event_pattern import findings_custom_action, findings_imported


sechub_findings = Blueprint(__name__)


def findings_forwarder(event):
    lambda_client = boto3.client('lambda')
    detail_type = event['detail-type']
    findings = event['detail']['findings']

    if detail_type == 'Security Hub Findings - Custom Action':
        actionName = event['detail']['actionName']
        trigger = 'Manually'
    if detail_type == 'Security Hub Findings - Imported':
        actionName = ''
        trigger = 'Automatically'

    for finding in findings:
        response = {}
        response['FindingId'] = finding['Id']
        response['Title'] = finding['Title']
        response['Resource'] = finding['Resources'][0]['Id']

        product_name = finding['ProductFields']['aws/securityhub/ProductName']
        if product_name == 'Security Hub':
            if actionName == 'Suppressed' or actionName == 'UnSuppressed':
                handler = actionName
            else:
                if 'ControlId' in finding['ProductFields']:
                    handler = finding['ProductFields']['ControlId'].replace('.', '')
                if 'RuleId' in finding['ProductFields']:
                    handler = "CIS" + finding['ProductFields']['RuleId'].replace(
                        '.', '')
        if product_name == 'GuardDuty':
            handler = 'GuardDuty'
        if product_name == 'IAM Access Analyzer':
            handler = 'IAMAccessAnalyzer'

        response['Trigger'] = trigger
        response['Handler'] = handler
        response['ProductName'] = product_name

        if handler in actionName.replace('.', '') or actionName == '':
            if 'Compliance' in finding and finding['Compliance']['Status'] == 'FAILED' and finding['Workflow']['Status'] == 'NEW' or handler in 'GuardDuty|IAMAccessAnalyzer|UnSuppressed|IAM3':
                role_arn = ':'.join(['arn:aws-cn:iam:', finding['AwsAccountId'],
                                    'role/oap2-ims/ims-service-role'])
                payload = {"role_arn": role_arn, "finding": finding,
                           "handler": handler, "trigger": trigger}

                lambda_client.invoke(
                    FunctionName='securityhub-dev-findings-handler',
                    InvocationType='Event',
                    Payload=json.dumps(payload)
                )
                response['Fixed'] = 'Fixing'
            elif finding['Workflow']['Status'] == 'SUPPRESSED':
                response['Fixed'] = 'Suppressed'
            else:
                response['Fixed'] = 'Passed'
        else:
            response['Fixed'] = 'Using wrong handler'

        if response['Fixed'] not in 'Passed|Suppressed':
            groupId = get_wechat_group(groupName='AWS SecurityHub Support')['data'][0][
                'groupId']
            title = f"{response['ProductName']} Finding"
            description = (f"<div class=\"highlight\">{response['Title']}</div>"
                           f"<div class=\"normal\">Resource: {response['Resource']}</div>"
                           f"<div class=\"gray\">Handler: {response['Handler']}</div>"
                           f"<div class=\"highlight\">Trigger: {response['Trigger']}</div>"
                           f"<div class=\"gray\">Fixed: {response['Fixed']}</div>")
            send_wechat_message(
                groupId=groupId,
                title=title,
                description=description
            )
        print(response)


@sechub_findings.on_cw_event(event_pattern=findings_imported, name='findings-imported')
def lambda_handler_finding_imported(event):
    findings_forwarder(event.to_dict())


@sechub_findings.on_cw_event(event_pattern=findings_custom_action, name='findings-custom-action')
def lambda_handler_findings_custom_action(event):
    findings_forwarder(event.to_dict())

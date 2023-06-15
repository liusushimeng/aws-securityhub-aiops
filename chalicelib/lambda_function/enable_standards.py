import time
from chalice import Blueprint

from chalicelib.utils import switch_role, get_wechat_group, send_wechat_message


enable_standards = Blueprint(__name__)


def batch_enable_standards(**kwargs):
    securityhub_client = kwargs["securityhub_client"]
    response = securityhub_client.batch_enable_standards(
        StandardsSubscriptionRequests=[
            {
                'StandardsArn': 'arn:aws-cn:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0',
            },
            {
                'StandardsArn': 'arn:aws-cn:securityhub:cn-north-1::standards/aws-foundational-security-best-practices/v/1.0.0',
            },
        ]
    )
    response = securityhub_client.get_enabled_standards()[
        'StandardsSubscriptions']
    while response[0]['StandardsStatus'] not in 'READY|INCOMPLETE' or \
            response[1]['StandardsStatus'] not in 'READY|INCOMPLETE':
        response = securityhub_client.get_enabled_standards()[
            'StandardsSubscriptions']
    return 'Enabled'


def get_enabled_standards_controls(**kwargs):
    controls = []
    securityhub_client = kwargs["securityhub_client"]
    standards_subscription_arns = kwargs["StandardsSubscriptionArns"]
    for standards_subscription_arn in standards_subscription_arns:
        response = securityhub_client.describe_standards_controls(
            StandardsSubscriptionArn=standards_subscription_arn
        )
        controls.extend(response['Controls'])
        while "NextToken" in response:
            NT = response["NextToken"]
            response = securityhub_client.describe_standards_controls(
                NextToken=NT,
                StandardsSubscriptionArn=standards_subscription_arn
            )
            controls.extend(response['Controls'])
    return controls


def disable_standards_controls(**kwargs):
    securityhub_client = kwargs["securityhub_client"]
    exception_controls_ids = kwargs["exception_controls_ids"]
    enabled_standards_controls = kwargs["enabled_standards_controls"]
    for exception_controls_id in exception_controls_ids:
        for esc in enabled_standards_controls:
            if esc['ControlId'] == exception_controls_id:
                StandardsControlArn = esc['StandardsControlArn']
        response = securityhub_client.update_standards_control(
            StandardsControlArn=StandardsControlArn,
            ControlStatus='DISABLED',
            DisabledReason='Not applicable for our service'
        )
        time.sleep(0.2)


@enable_standards.lambda_function(name='enable-standards')
def lambda_handler(event, context):
    response = {}

    AccountId = event['AwsAccountId']
    Email = event['Email']
    Action = event['Action']

    response['Action'] = Action
    response['AccountId'] = AccountId
    response['Email'] = Email

    RoleArn = event['RoleArn']
    exception_controls_ids = event['ExceptionControlsIDs']
    sts_session = switch_role(RoleArn=RoleArn)
    securityhub_client = sts_session.client('securityhub')

    response['StandardsSubscriptions'] = batch_enable_standards(
        securityhub_client=securityhub_client
    )
    enabled_standards = securityhub_client.get_enabled_standards()[
        'StandardsSubscriptions']
    standards_subscription_arns = [i['StandardsSubscriptionArn'] for i in
                                   enabled_standards]
    enabled_standards_controls = get_enabled_standards_controls(
        securityhub_client=securityhub_client,
        StandardsSubscriptionArns=standards_subscription_arns
    )
    disable_standards_controls(
        securityhub_client=securityhub_client,
        exception_controls_ids=exception_controls_ids,
        enabled_standards_controls=enabled_standards_controls
    )
    response['ExceptionControls'] = 'Disabled'
    groupId = get_wechat_group(groupName='AWS SecurityHub Support')['data'][0]['groupId']
    title = 'SecurityHub Standards'
    description = (f"<div class=\"highlight\">{response['Action']}</div>"
                   f"<div class=\"normal\">{response['AccountId']}</div>"
                   f"<div class=\"gray\">{response['Email']}</div>"
                   f"<div class=\"highlight\">{response['StandardsSubscriptions']}</div>"
                   f"<div class=\"gray\">Exception Controls {response['ExceptionControls']}</div>")
    send_wechat_message(
        groupId=groupId,
        title=title,
        description=description
    )
    print(response)
    return response

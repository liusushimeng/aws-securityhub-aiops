from chalice import Blueprint
from chalicelib.utils import switch_role, get_wechat_group, send_wechat_message


disable_standards = Blueprint(__name__)


@disable_standards.lambda_function(name='disable-standards')
def lambda_handler(event, context):
    response = {}

    AccountId = event['AwsAccountId']
    Email = event['Email']
    Action = event['Action']

    response['Action'] = Action
    response['AccountId'] = AccountId
    response['Email'] = Email

    RoleArn = event['RoleArn']
    sts_session = switch_role(RoleArn=RoleArn)
    securityhub_client = sts_session.client('securityhub')

    standardsSubscriptionArns = []
    standardsSubscriptions = securityhub_client.get_enabled_standards()['StandardsSubscriptions']
    if len(standardsSubscriptions) > 0:
        for enabled_standard in standardsSubscriptions:
            if enabled_standard['StandardsStatus'] in 'READY|INCOMPLETE':
                standardsSubscriptionArns.append(enabled_standard['StandardsSubscriptionArn'])
        securityhub_client.batch_disable_standards(StandardsSubscriptionArns=standardsSubscriptionArns)
        res = securityhub_client.get_enabled_standards()['StandardsSubscriptions']
        while len(res) != 0:
            res = securityhub_client.get_enabled_standards()['StandardsSubscriptions']
        response['StandardsSubscriptions'] = 'Disabled Done'
    else:
        response['StandardsSubscriptions'] = 'Already Disabled Before'
    groupId = get_wechat_group(groupName='AWS SecurityHub Support')['data'][0]['groupId']
    title = 'SecurityHub Standards'
    description = (f"<div class=\"highlight\">{response['Action']}</div>"
                   f"<div class=\"normal\">{response['AccountId']}</div>"
                   f"<div class=\"gray\">{response['Email']}</div>"
                   f"<div class=\"highlight\">{response['StandardsSubscriptions']}</div>")
    send_wechat_message(
        groupId=groupId,
        title=title,
        description=description
    )
    print(response)
    return response

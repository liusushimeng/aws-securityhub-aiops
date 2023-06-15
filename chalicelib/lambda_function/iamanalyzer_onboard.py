import uuid

from chalice import Blueprint
from chalicelib.utils import switch_role, get_wechat_group, send_wechat_message


iamanalyzer_onboard = Blueprint(__name__)


@iamanalyzer_onboard.lambda_function(name='iamanalyzer-onboard')
def lambda_handler(event, context):
    AccountId = event['AwsAccountId']
    Email = event['Email']
    RoleArn = event['RoleArn']
    Action = event['Action']

    response = {}
    response['Action'] = Action
    response['AccountId'] = AccountId
    response['Email'] = Email

    sts_session = switch_role(RoleArn=RoleArn)
    client = sts_session.client('accessanalyzer')
    res = client.list_analyzers()
    if len(res['analyzers']) == 0:
        a_name = '-'.join(['ConsoleAnalyzer', str(uuid.uuid1())])
        res = client.create_analyzer(
            analyzerName=a_name,
            type="ACCOUNT"
        )
        response['Analyzers'] = {'arn': res['arn'], 'status': 'ACTIVE'}
    else:
        response['Analyzers'] = {'arn': res['analyzers'][0]['arn'], 'status': 'Already ' + res['analyzers'][0]['status']}

    groupId = get_wechat_group(groupName='AWS SecurityHub Support')['data'][0]['groupId']
    title = 'SecurityHub Integrations'
    description = (f"<div class=\"highlight\">{response['Action']}</div>"
                   f"<div class=\"normal\">{response['AccountId']}</div>"
                   f"<div class=\"gray\">{response['Email']}</div>"
                   f"<div class=\"highlight\">{response['Analyzers']['status']}</div>")
    send_wechat_message(
        groupId=groupId,
        title=title,
        description=description
    )
    print(response)
    return response

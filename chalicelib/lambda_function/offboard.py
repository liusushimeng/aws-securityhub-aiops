from chalice import Blueprint
from chalicelib.utils import switch_role, get_wechat_group, send_wechat_message


offboard = Blueprint(__name__)


def list_members(**kwargs):
    members = []
    client = kwargs['securityhub_client']
    res = client.list_members(OnlyAssociated=False)
    members.extend(res['Members'])
    while 'NextToken' in res:
        NT = res['NextToken']
        res = client.list_members(
            NextToken=NT,
            OnlyAssociated=False
        )
        members.extend(res['Members'])
    return [i['AccountId'] for i in members]


def disassociate_members(**kwargs):
    res = None
    client = kwargs['securityhub_client']
    AccountId = kwargs['AccountId']
    res = client.disassociate_members(
        AccountIds=[
            AccountId,
        ]
    )
    return res


def delete_members(**kwargs):
    res = None
    client = kwargs['securityhub_client']
    AccountId = kwargs['AccountId']
    res = client.delete_members(
        AccountIds=[
            AccountId,
        ]
    )
    return res


def describe_hub(**kwargs):
    res = None
    client = kwargs['securityhub_client']
    try:
        res = client.describe_hub()
    except Exception as e:
        print("Exception:", e.args)
    return res


def disable_security_hub(**kwargs):
    client = kwargs['securityhub_client']
    res = client.disable_security_hub()
    return res


@offboard.lambda_function(name='offboard')
def lambda_handler(event, context):
    response = {}

    AccountId = event['AwsAccountId']
    Email = event['Email']
    MasterId = event['MasterId']
    Action = event['Action']

    response['Action'] = Action
    response['AccountId'] = AccountId
    response['Email'] = Email
    response['MasterId'] = MasterId

    RoleArn = event['RoleArn']
    sts_session = switch_role(RoleArn=RoleArn)
    securityhub_client = sts_session.client('securityhub')

    MasterRoleArn = event['MasterRoleArn']
    sts_session_admin = switch_role(RoleArn = MasterRoleArn)
    securityhub_client_admin = sts_session_admin.client('securityhub')

    res = list_members(securityhub_client=securityhub_client_admin)
    if AccountId in res:
        res = disassociate_members(
            securityhub_client=securityhub_client_admin,
            AccountId=AccountId
        )
        if res is not None:
            print(AccountId, ' member is disassociated')
            res = delete_members(
                securityhub_client=securityhub_client_admin,
                AccountId=AccountId
            )
    else:
        print(AccountId, ' is already disassociated')

    res = describe_hub(securityhub_client=securityhub_client)
    if res is not None:
        disable_security_hub(securityhub_client=securityhub_client)
        response['SecHub'] = 'Disabled'
    else:
        response['SecHub'] = 'Already Disabled'
    groupId = get_wechat_group(groupName='AWS SecurityHub Support')['data'][0]['groupId']
    title  = 'SecurityHub Service'
    description = (f"<div class=\"highlight\">{response['Action']}</div>"
                   f"<div class=\"normal\">{response['AccountId']}</div>"
                   f"<div class=\"gray\">{response['Email']}</div>"
                   f"<div class=\"highlight\">{response['SecHub']}</div>")
    send_wechat_message(
        groupId=groupId,
        title=title,
        description=description
    )
    print(response)
    return response

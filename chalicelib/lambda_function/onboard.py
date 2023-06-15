from chalice import Blueprint
from chalicelib.utils import switch_role, get_wechat_group, send_wechat_message


onboard = Blueprint(__name__)


def describe_hub(**kwargs):
    res = None
    client = kwargs['securityhub_client']
    try:
        res = client.describe_hub()
    except Exception as e:
        print("Exception:", e.args)
    return res


def enable_security_hub(**kwargs):
    client = kwargs['securityhub_client']
    res = client.enable_security_hub(
        EnableDefaultStandards=False
    )


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


def create_members(**kwargs):
    res = None
    client = kwargs['securityhub_client']
    AccountId = kwargs['AccountId']
    Email = kwargs['Email']
    try:
        res = client.create_members(
            AccountDetails=[
                {
                    'AccountId': AccountId,
                    'Email': Email
                },
            ]
        )
    except Exception as e:
        print("Exception:", e.args)
    return res


def invite_members(**kwargs):
    client = kwargs['securityhub_client']
    AccountId = kwargs['AccountId']
    res = client.invite_members(
        AccountIds=[
            AccountId,
        ]
    )
    return res


def list_invitations(**kwargs):
    client = kwargs['securityhub_client']
    res = client.list_invitations()
    return res


def accept_invitation(**kwargs):
    client = kwargs['securityhub_client']
    MasterId = kwargs['MasterId']
    InvitationId = kwargs['InvitationId']
    res = client.accept_invitation(
        MasterId=MasterId,
        InvitationId=InvitationId
    )


@onboard.lambda_function(name='onboard')
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

    res = describe_hub(securityhub_client=securityhub_client)
    if res is None:
        enable_security_hub(securityhub_client=securityhub_client)
        response['SecHub'] = 'Enabled'
    else:
        response['SecHub'] = 'Already Enabled'

    res = list_members(securityhub_client=securityhub_client_admin)
    if AccountId not in res:
        res = create_members(
            securityhub_client=securityhub_client_admin,
            AccountId=AccountId,
            Email=Email
        )
        if res is not None:
            print(AccountId, ' member is created')
            res = invite_members(
                securityhub_client=securityhub_client_admin,
                AccountId=AccountId
            )
    else:
        print(AccountId, ' is already invited')
    res = list_invitations(securityhub_client=securityhub_client)
    if 'Invitations' in res and len(res['Invitations']) > 0 :
        accept_invitation(
            securityhub_client=securityhub_client,
            MasterId=res['Invitations'][0]['AccountId'],
            InvitationId=res['Invitations'][0]['InvitationId']
        )
        response['Invite'] = 'Accepted'
    else:
        response['Invite'] = 'Already Accepted'
    groupId = get_wechat_group(groupName='AWS SecurityHub Support')['data'][0]['groupId']
    title = 'SecurityHub Service'
    description = (f"<div class=\"highlight\">{response['Action']}</div>"
                   f"<div class=\"normal\">{response['AccountId']}</div>"
                   f"<div class=\"gray\">{response['Email']}</div>"
                   f"<div class=\"highlight\">{response['SecHub']}</div>"
                   f"<div class=\"gray\">{response['Invite']}</div>")
    send_wechat_message(
        groupId=groupId,
        title=title,
        description=description
    )
    print(response)
    return response




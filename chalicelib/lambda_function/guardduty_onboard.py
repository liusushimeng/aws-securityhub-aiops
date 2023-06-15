from chalice import Blueprint
from chalicelib.utils import switch_role, get_wechat_group, send_wechat_message


guardduty_onboard = Blueprint(__name__)


def list_detectors(**kwargs):
    res = None
    client = kwargs['guardduty_client']
    try:
        res = client.list_detectors()
    except Exception as e:
        print("Exception:", e.args)
    return res


def create_detector(**kwargs):
    client = kwargs['guardduty_client']
    res = client.create_detector(
        Enable=True,
        FindingPublishingFrequency='SIX_HOURS',
        DataSources={
            'S3Logs': {
                'Enable': True
            },
        }
    )
    return res


def list_members(**kwargs):
    members = []
    client = kwargs['guardduty_client']
    DetectorId = kwargs['DetectorId']
    res = client.list_members(
        DetectorId=DetectorId
    )
    members.extend(res['Members'])
    while 'NextToken' in res:
        NT = res['NextToken']
        res = client.list_members(
            NextToken=NT,
            DetectorId=DetectorId
        )
        members.extend(res['Members'])
    return [i['AccountId'] for i in members]


def create_members(**kwargs):
    res = None
    client = kwargs['guardduty_client']
    DetectorId = kwargs['DetectorId']
    AccountId = kwargs['AccountId']
    Email = kwargs['Email']
    try:
        res = client.create_members(
            DetectorId=DetectorId,
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
    client = kwargs['guardduty_client']
    DetectorId = kwargs['DetectorId']
    AccountId = kwargs['AccountId']
    res = client.invite_members(
        DetectorId=DetectorId,
        AccountIds=[
            AccountId,
        ]
    )
    return res


def list_invitations(**kwargs):
    client = kwargs['guardduty_client']
    res = client.list_invitations()
    return res


def accept_invitation(**kwargs):
    client = kwargs['guardduty_client']
    DetectorId = kwargs['DetectorId']
    MasterId = kwargs['MasterId']
    InvitationId = kwargs['InvitationId']
    res = client.accept_invitation(
        DetectorId=DetectorId,
        MasterId=MasterId,
        InvitationId=InvitationId
    )


@guardduty_onboard.lambda_function(name='guardduty-onboard')
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
    guardduty_client = sts_session.client('guardduty')

    MasterRoleArn = event['MasterRoleArn']
    sts_session_admin = switch_role(RoleArn = MasterRoleArn)
    guardduty_client_admin = sts_session_admin.client('guardduty')

    res = list_detectors(guardduty_client=guardduty_client)
    if len(res['DetectorIds']) == 0:
        res = create_detector(guardduty_client=guardduty_client)
        detectorId_member = res['DetectorId']
        response['GuardDuty'] = 'Enabled'
    else:
        detectorId_member = res['DetectorIds'][0]
        response['GuardDuty'] = 'Already Enabled'

    res = list_detectors(guardduty_client=guardduty_client_admin)
    detectorId_master = res['DetectorIds'][0]
    res = list_members(
        guardduty_client=guardduty_client_admin,
        DetectorId=detectorId_master
    )

    if AccountId not in res:
        res = create_members(
            guardduty_client=guardduty_client_admin,
            DetectorId=detectorId_master,
            AccountId=AccountId,
            Email=Email
        )
        if res is not None:
            print(AccountId, ' member is created')
            res = invite_members(
                guardduty_client=guardduty_client_admin,
                DetectorId=detectorId_master,
                AccountId=AccountId
            )
    else:
        print(AccountId, ' is already invited')
    res = list_invitations(guardduty_client=guardduty_client)
    if 'Invitations' in res and len(res['Invitations']) > 0 :
        accept_invitation(
            guardduty_client=guardduty_client,
            DetectorId=detectorId_member,
            MasterId=res['Invitations'][0]['AccountId'],
            InvitationId=res['Invitations'][0]['InvitationId']
        )
        response['Invite'] = 'Accepted'
    else:
        response['Invite'] = 'Already Accepted'
    groupId = get_wechat_group(groupName='AWS SecurityHub Support')['data'][0]['groupId']
    title = 'SecurityHub Integrations'
    description = (f"<div class=\"highlight\">{response['Action']}</div>"
                   f"<div class=\"normal\">{response['AccountId']}</div>"
                   f"<div class=\"gray\">{response['Email']}</div>"
                   f"<div class=\"highlight\">{response['GuardDuty']}</div>"
                   f"<div class=\"gray\">{response['Invite']}</div>")
    send_wechat_message(
        groupId=groupId,
        title=title,
        description=description
    )
    print(response)
    return response


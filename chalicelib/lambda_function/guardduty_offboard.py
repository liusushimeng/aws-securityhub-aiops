from chalice import Blueprint
from chalicelib.utils import switch_role, get_wechat_group, send_wechat_message


guardduty_offboard = Blueprint(__name__)


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


def disassociate_members(**kwargs):
    res = None
    client = kwargs['guardduty_client']
    DetectorId = kwargs['DetectorId']
    AccountId = kwargs['AccountId']
    try:
        res = client.disassociate_members(
            DetectorId=DetectorId,
            AccountIds=[
                AccountId,
            ]
        )
    except Exception as e:
        print("Exception:", e.args)
    return res


def delete_members(**kwargs):
    res = None
    client = kwargs['guardduty_client']
    DetectorId = kwargs['DetectorId']
    AccountId = kwargs['AccountId']
    try:
        res = client.delete_members(
            DetectorId=DetectorId,
            AccountIds=[
                AccountId,
            ]
        )
    except Exception as e:
        print("Exception:", e.args)
    return res


def list_detectors(**kwargs):
    res = None
    client = kwargs['guardduty_client']
    try:
        res = client.list_detectors()
    except Exception as e:
        print("Exception:", e.args)
    return res


def delete_detector(**kwargs):
    res = None
    client = kwargs['guardduty_client']
    DetectorId = kwargs['DetectorId']
    try:
        res = client.delete_detector(DetectorId=DetectorId)
    except Exception as e:
        print("Exception:", e.args)
    return res


@guardduty_offboard.lambda_function(name='guardduty-offboard')
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

    res = list_detectors(guardduty_client=guardduty_client_admin)
    detectorId_master = res['DetectorIds'][0]
    res = list_members(
        guardduty_client=guardduty_client_admin,
        DetectorId=detectorId_master
    )
    if AccountId in res:
        res = disassociate_members(
            guardduty_client=guardduty_client_admin,
            DetectorId=detectorId_master,
            AccountId=AccountId
        )
        if res is not None:
            print(AccountId, ' member is disassociated')
            res = delete_members(
                guardduty_client=guardduty_client_admin,
                DetectorId=detectorId_master,
                AccountId=AccountId
            )
    else:
        print(AccountId, ' is already disassociated')

    res = list_detectors(guardduty_client=guardduty_client)
    if len(res['DetectorIds']) > 0:
        detectorId_member = res['DetectorIds'][0]
        res = delete_detector(
            guardduty_client=guardduty_client,
            DetectorId=detectorId_member
        )
        response['GuardDuty'] = 'Deleted'
    else:
        response['GuardDuty'] = 'Already Deleted'
    groupId = get_wechat_group(groupName='AWS SecurityHub Support')['data'][0]['groupId']
    title = 'SecurityHub Integrations'
    description = (f"<div class=\"highlight\">{response['Action']}</div>"
                   f"<div class=\"normal\">{response['AccountId']}</div>"
                   f"<div class=\"gray\">{response['Email']}</div>"
                   f"<div class=\"highlight\">{response['GuardDuty']}</div>")
    send_wechat_message(
        groupId=groupId,
        title=title,
        description=description
    )
    print(response)
    return response


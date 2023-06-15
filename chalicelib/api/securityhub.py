import json
import boto3
from chalice import Blueprint

from chalicelib.utils import respond, authorizer


securityhub = Blueprint(__name__)


@securityhub.route('/securityhub/{action}', methods=['POST'], authorizer=authorizer)
def lambda_handler(action):
    payload = securityhub.current_request.json_body
    if not payload:
        payload = dict()

    action_list = ['onboard',
                   'offboard',
                   'enable-standards',
                   'disable-standards',
                   'guardduty-onboard',
                   'guardduty-offboard',
                   'iamanalyzer-onboard'
                   ]

    if action in action_list:
        lambda_client = boto3.client('lambda')
        AwsAccountIds = payload['AwsAccountIds']
        MasterId = payload.get('MasterId', '843403612003')
        MasterRoleArn = ':'.join(['arn:aws-cn:iam:', MasterId, 'role/oap2-ims/ims-service-role'])
        ExceptionControlsIDs = payload.get('ExceptionControlsIDs', '')

        if len(AwsAccountIds) > 0:
            function_name = (
                f"{securityhub.lambda_context.function_name}-{action}"
            )

            for AwsAccount in AwsAccountIds:
                AwsAccountId = AwsAccount['AwsAccountId']
                Email = AwsAccount.get('Email', '')
                RoleArn = ':'.join(['arn:aws-cn:iam:', AwsAccountId, 'role/oap2-ims/ims-service-role'])
                payload = {
                    "AwsAccountId": AwsAccountId,
                    "Email": Email,
                    "RoleArn": RoleArn,
                    "MasterId": MasterId,
                    "MasterRoleArn": MasterRoleArn,
                    "ExceptionControlsIDs": ExceptionControlsIDs,
                    "Action": action
                }
                lambda_client.invoke(
                    FunctionName=function_name,
                    InvocationType='Event',
                    Payload=json.dumps(payload)
                )
            messages = {'Lambda Invoke': {'FunctionName': function_name, 'Action': action, 'AwsAccountIds': AwsAccountIds}}
            print(messages)
        else:
            messages = 'No AWS Account Input'
            print(messages)
    else:
        messages = 'No this action. The right action in list ' + str(action_list)
        print(messages)

    return respond(
        messages=messages,
        code=200
    )
